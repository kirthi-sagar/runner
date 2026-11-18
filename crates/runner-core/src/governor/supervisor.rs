//! Supervisor daemon loop (Phase 1b).
//!
//! Ties the async PSI poller to cgroup weight transitions, recalculates
//! slots under live pressure, and owns shared daemon state (reservations,
//! throttle overrides, drained nodes) for the MCP and IPC frontends.
//!
//! Throttling is weight-only: this module never freezes cgroups, so test
//! timers and TCP keepalives survive critical pressure on trickle CPU.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::{Notify, RwLock};

use super::afk::{poll_desktop_idle, AfkBoost, AfkMode, IdleState, PROBE_EVERY};
use super::cgroup::{weight_for_cpu_psi_with, CgroupSlice};
use super::psi::{PressureLevel, PsiPoller, PsiSnapshot};
use super::topology::detect_slots;
use crate::cache::server::CacheServerState;
use crate::cache::CacheStore;
use crate::config::{PeerRecord, RunnerConfig};
use crate::mesh::cloud::{CloudNode, CloudPool};
use crate::mesh::peer::apply_donor_caps;

/// Host headroom reservation for agent local work.
#[derive(Debug, Clone)]
pub struct Reservation {
    pub id: String,
    pub cores: f64,
    pub ram_mb: u64,
    pub reason: String,
    pub expires_at: Instant,
}

impl Reservation {
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// Agent-forced weight with an expiry.
#[derive(Debug, Clone)]
pub struct ThrottleOverride {
    pub weight: u32,
    pub expires_at: Instant,
}

impl ThrottleOverride {
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

/// One running job tracked for `runner top` and the IPC snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct InFlightJob {
    pub id: String,
    pub provider: String,
    pub name: String,
    pub started_unix_ms: u64,
}

/// Cap on tracked jobs; oldest entries roll off first.
pub const MAX_TRACKED_JOBS: usize = 64;

/// Last-known poll health of one CI forge, surfaced over IPC/MCP/CLI.
#[derive(Debug, Clone, Serialize)]
pub struct ForgeHealth {
    pub last_poll_unix_ms: u64,
    pub queue_depth: u32,
    pub last_error: Option<String>,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Mutable daemon state shared across governor, MCP, and IPC tasks.
#[derive(Debug)]
pub struct SupervisorState {
    pub afk: AfkBoost,
    /// AFK probing policy seeded from `[governor] afk_mode`.
    pub afk_mode: AfkMode,
    /// Idle seconds before boost engages in Auto mode.
    pub afk_idle_secs: u64,
    /// Wall time of the last desktop-idle probe (5s throttle).
    pub afk_last_probe: Option<Instant>,
    reservations: HashMap<String, Reservation>,
    throttle: Option<ThrottleOverride>,
    drained: HashMap<String, String>,
    peers: HashMap<String, PeerRecord>,
    cloud_nodes: Vec<CloudNode>,
    cloud_pool: Option<CloudPool>,
    cloud_spend_cap: f64,
    cache: Option<CacheServerState>,
    donor_caps: Option<(u32, u64)>,
    next_reservation: u64,
    in_flight: u32,
    jobs: Vec<InFlightJob>,
    queue_depth: u32,
    forge_health: BTreeMap<String, ForgeHealth>,
    wakeup: Arc<Notify>,
    pub last_snapshot: PsiSnapshot,
    pub last_weight: Option<u32>,
    pub last_slots: u32,
    /// Operator CPU PSI thresholds (warn/crit) seeded from config.
    pub psi_warn: f64,
    pub psi_crit: f64,
    /// Last package temp reading (°C, None when unsensed).
    pub temp_c: Option<f64>,
    /// Latched thermal throttle (85°C engage, 78°C release).
    pub thermal_throttled: bool,
    /// On battery power: halt new job intake.
    pub discharging: bool,
}

impl SupervisorState {
    pub fn new() -> Self {
        Self {
            afk: AfkBoost::new(),
            afk_mode: AfkMode::default(),
            afk_idle_secs: 300,
            afk_last_probe: None,
            reservations: HashMap::new(),
            throttle: None,
            drained: HashMap::new(),
            peers: HashMap::new(),
            cloud_nodes: Vec::new(),
            cloud_pool: None,
            cloud_spend_cap: 0.0,
            cache: None,
            donor_caps: None,
            next_reservation: 1,
            in_flight: 0,
            jobs: Vec::new(),
            queue_depth: 0,
            forge_health: BTreeMap::new(),
            wakeup: Arc::new(Notify::new()),
            last_snapshot: PsiSnapshot::default(),
            last_weight: None,
            last_slots: 1,
            psi_warn: super::psi::CPU_WARN,
            psi_crit: super::psi::CPU_CRIT,
            temp_c: None,
            thermal_throttled: false,
            discharging: false,
        }
    }

    /// Refresh workstation guards from live sensors, applying the
    /// 85°C-engage / 78°C-release hysteresis band.
    pub fn poll_workstation_guards(&mut self) {
        let temp = super::thermal::package_temp_c();
        self.temp_c = temp;
        match (self.thermal_throttled, temp) {
            (false, Some(t)) if t >= super::thermal::THERMAL_THROTTLE_C => {
                eprintln!("runner: thermal throttle engaged at {t:.1}°C");
                self.thermal_throttled = true;
            }
            (true, Some(t)) if t < super::thermal::THERMAL_RELEASE_C => {
                eprintln!("runner: thermal throttle released at {t:.1}°C");
                self.thermal_throttled = false;
            }
            (true, None) => self.thermal_throttled = false,
            _ => {}
        }
        let discharging = super::thermal::power_state() == super::thermal::PowerState::Discharging;
        if discharging && !self.discharging {
            eprintln!("runner: on battery power; halting new job intake");
        } else if !discharging && self.discharging {
            eprintln!("runner: AC power restored; resuming job intake");
        }
        self.discharging = discharging;
    }

    /// Seed WAN peers, donor caps, and governor thresholds from config.
    pub fn seed_from_config(&mut self, config: &RunnerConfig) {
        for peer in &config.peers {
            self.peers.insert(peer.node_id.clone(), peer.clone());
        }
        if let Some(donor) = &config.donor {
            self.donor_caps = Some((donor.max_cores, donor.max_ram_mb));
        }
        if config.governor.warn_cpu_psi > 0.0
            && config.governor.crit_cpu_psi > config.governor.warn_cpu_psi
        {
            self.psi_warn = config.governor.warn_cpu_psi;
            self.psi_crit = config.governor.crit_cpu_psi;
        }
        self.afk_mode = AfkMode::parse(&config.governor.afk_mode);
        self.afk_idle_secs = config.governor.afk_idle_seconds;
    }

    /// Evaluate AFK boost for this tick. Always/Never modes bypass the
    /// probe; Auto probes `loginctl` at most once per [`PROBE_EVERY`].
    /// Idle engages the latch, presence restores it — the transition is
    /// free (latch flip only) and restores within one tick (~250ms).
    pub fn poll_afk(&mut self) {
        match self.afk_mode {
            AfkMode::Always => self.afk.on_idle_timeout(),
            AfkMode::Never => self.afk.on_user_input(),
            AfkMode::Auto => {
                let due = self
                    .afk_last_probe
                    .is_none_or(|t| t.elapsed() >= PROBE_EVERY);
                if !due {
                    return;
                }
                self.afk_last_probe = Some(Instant::now());
                match poll_desktop_idle(self.afk_idle_secs) {
                    IdleState::Idle => self.afk.on_idle_timeout(),
                    IdleState::Active => self.afk.on_user_input(),
                }
            }
        }
    }

    /// Drop expired reservations and throttle overrides.
    pub fn prune_expired(&mut self, now: Instant) {
        self.reservations.retain(|_, r| !r.expired(now));
        if self.throttle.as_ref().is_some_and(|t| t.expired(now)) {
            self.throttle = None;
        }
    }

    pub fn reserve(
        &mut self,
        cores: f64,
        ram_mb: u64,
        duration: Duration,
        reason: String,
        now: Instant,
    ) -> Reservation {
        let id = format!("res-{}", self.next_reservation);
        self.next_reservation += 1;
        let reservation = Reservation {
            id: id.clone(),
            cores,
            ram_mb,
            reason,
            expires_at: now + duration,
        };
        self.reservations.insert(id, reservation.clone());
        reservation
    }

    pub fn release(&mut self, id: &str) -> bool {
        self.reservations.remove(id).is_some()
    }

    pub fn reservations(&self) -> Vec<Reservation> {
        self.reservations.values().cloned().collect()
    }

    pub fn set_throttle(&mut self, weight: u32, duration: Duration, now: Instant) {
        self.throttle = Some(ThrottleOverride {
            weight,
            expires_at: now + duration,
        });
    }

    pub fn throttle_weight(&self, now: Instant) -> Option<u32> {
        self.throttle
            .as_ref()
            .filter(|t| !t.expired(now))
            .map(|t| t.weight)
    }

    pub fn drain_node(&mut self, node_id: String, reason: String) {
        self.drained.insert(node_id, reason);
    }

    pub fn drained_nodes(&self) -> HashMap<String, String> {
        self.drained.clone()
    }

    pub fn add_peer(&mut self, peer: PeerRecord) {
        self.peers.insert(peer.node_id.clone(), peer);
    }

    pub fn peers(&self) -> Vec<PeerRecord> {
        self.peers.values().cloned().collect()
    }

    pub fn add_cloud_node(&mut self, node: CloudNode) {
        self.cloud_nodes.push(node);
    }

    pub fn remove_cloud_node(&mut self, id: &str) -> bool {
        let before = self.cloud_nodes.len();
        self.cloud_nodes.retain(|n| n.id != id);
        self.cloud_nodes.len() != before
    }

    pub fn cloud_nodes(&self) -> Vec<CloudNode> {
        self.cloud_nodes.clone()
    }

    /// Attach the provider pool (once, at daemon startup) so IPC-driven
    /// termination can reach the cloud APIs. The pool holds API clients,
    /// never serialized into status output.
    pub fn set_cloud_pool(&mut self, pool: CloudPool, spend_cap: f64) {
        self.cloud_pool = Some(pool);
        self.cloud_spend_cap = spend_cap;
    }

    pub fn cloud_pool(&self) -> Option<CloudPool> {
        self.cloud_pool.clone()
    }

    /// Attach the LAN cache server state (once, at daemon startup
    /// after the proxy binds). Absent when binding failed.
    pub fn set_cache(&mut self, state: CacheServerState) {
        self.cache = Some(state);
    }

    pub fn cache_store(&self) -> Option<CacheStore> {
        self.cache.as_ref().map(|s| s.store.clone())
    }

    /// Base URL workers use for `ACTIONS_CACHE_URL` (None = disabled).
    pub fn cache_base_url(&self) -> Option<String> {
        self.cache.as_ref().map(|s| s.public_base.clone())
    }

    /// Per-boot bearer token injected as `ACTIONS_RUNTIME_TOKEN`.
    pub fn cache_token(&self) -> Option<String> {
        self.cache.as_ref().map(|s| s.token.clone())
    }

    pub fn cloud_spend_cap(&self) -> f64 {
        self.cloud_spend_cap
    }

    /// Clamp slots to donor caps when this host serves foreign jobs.
    pub fn clamp_slots(&self, slots: u32) -> u32 {
        self.donor_caps
            .map_or(slots, |(cores, ram)| apply_donor_caps(slots, cores, ram))
    }

    /// Local jobs currently executing.
    pub fn in_flight(&self) -> u32 {
        self.in_flight
    }

    pub fn in_flight_inc(&mut self) {
        self.in_flight += 1;
    }

    pub fn in_flight_dec(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Atomically reserve one execution slot when capacity allows.
    /// Check-and-increment under a single write lock so concurrent
    /// forge loops can never over-dispatch a constrained host.
    pub fn try_reserve_slot(&mut self) -> bool {
        if self.in_flight < self.last_slots {
            self.in_flight += 1;
            true
        } else {
            false
        }
    }

    /// Release a reservation made by [`try_reserve_slot`](Self::try_reserve_slot)
    /// when the poll yields no dispatchable job.
    pub fn release_slot_reservation(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Record a dispatch; oldest entries roll off past [`MAX_TRACKED_JOBS`].
    /// Keyed by `(provider, id)` so identical job IDs from different
    /// forges never evict each other.
    pub fn job_started(&mut self, provider: &str, id: &str, name: &str) {
        self.jobs.retain(|j| j.provider != provider || j.id != id);
        self.jobs.push(InFlightJob {
            id: id.to_string(),
            provider: provider.to_string(),
            name: name.to_string(),
            started_unix_ms: now_unix_ms(),
        });
        while self.jobs.len() > MAX_TRACKED_JOBS {
            self.jobs.remove(0);
        }
    }

    /// Drop a finished job from the registry (caller's forge only).
    pub fn job_finished(&mut self, provider: &str, id: &str) {
        self.jobs.retain(|j| j.provider != provider || j.id != id);
    }

    /// Record one forge poll outcome for IPC/MCP/CLI visibility.
    pub fn record_forge_poll(&mut self, provider: &str, queue_depth: u32, error: Option<String>) {
        self.forge_health.insert(
            provider.to_string(),
            ForgeHealth {
                last_poll_unix_ms: now_unix_ms(),
                queue_depth,
                last_error: error,
            },
        );
    }

    /// Last-known health per forge, in stable name order.
    pub fn forge_health(&self) -> BTreeMap<String, ForgeHealth> {
        self.forge_health.clone()
    }

    pub fn in_flight_jobs(&self) -> Vec<InFlightJob> {
        self.jobs.clone()
    }

    pub fn set_queue_depth(&mut self, depth: u32) {
        self.queue_depth = depth;
    }

    pub fn queue_depth(&self) -> u32 {
        self.queue_depth
    }

    /// Instant-dispatch trigger shared with the webhook listener.
    pub fn wakeup(&self) -> Arc<Notify> {
        self.wakeup.clone()
    }
}

impl Default for SupervisorState {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle to daemon state.
pub type SharedState = Arc<RwLock<SupervisorState>>;

pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(SupervisorState::new()))
}

/// Effective slots under live pressure (Phase 1b policy): any critical
/// pressure collapses to 1 slot; any warning halves the base; else base.
pub fn effective_slots(base: u32, snapshot: &PsiSnapshot) -> u32 {
    use PressureLevel::{Critical, Warning};
    let levels = (
        snapshot.cpu_pressure(),
        snapshot.mem_pressure(),
        snapshot.io_pressure(),
    );
    match levels {
        (Critical, _, _) | (_, Critical, _) | (_, _, Critical) => 1,
        (Warning, _, _) | (_, Warning, _) | (_, _, Warning) => base.max(1) / 2 + base.max(1) % 2,
        _ => base.max(1),
    }
}

/// Weight for one tick: the stricter of the agent override and the
/// pressure ladder. Never a freeze.
pub fn tick_weight(state: &SupervisorState, snapshot: &PsiSnapshot, now: Instant) -> u32 {
    let pressure =
        weight_for_cpu_psi_with(snapshot.cpu_some_avg10(), state.psi_warn, state.psi_crit);
    let weight = state
        .throttle_weight(now)
        .map_or(pressure, |o| o.min(pressure));
    if state.thermal_throttled {
        weight.min(super::cgroup::WEIGHT_TRICKLE)
    } else {
        weight
    }
}

/// Apply workstation guards to computed slots (pure policy): battery
/// halts all intake, thermal throttle halves to at least one.
pub fn apply_workstation_guards(slots: u32, throttled: bool, discharging: bool) -> u32 {
    if discharging {
        return 0;
    }
    if throttled {
        return slots.max(1) / 2 + slots.max(1) % 2;
    }
    slots
}

/// Wait for SIGINT or SIGTERM. Registration can fail in restricted
/// containers; that degrades to "no signal handling" (the loop keeps
/// its own cadence; SIGKILL still works) instead of aborting startup.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("runner: SIGINT handler unavailable ({e}); signals ignored");
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("runner: SIGTERM handler unavailable ({e}); signals ignored");
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
    };
    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
}

/// Run the governor loop until SIGINT/SIGTERM.
///
/// Best-effort under unprivileged execution: if the slice is not writable,
/// pressure is still polled, logged, and published to state.
pub async fn run_supervisor(state: SharedState) -> anyhow::Result<()> {
    let slice = CgroupSlice::system_default();
    let writable = match slice.ensure_baseline() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("runner: cgroup slice unavailable ({e}); running poll-only");
            false
        }
    };

    let poller = PsiPoller::spawn();
    let mut rx = poller.subscribe();
    eprintln!("runner: supervisor loop started (250ms PSI cadence)");

    loop {
        tokio::select! {
            _ = shutdown_signal() => {
                eprintln!("runner: shutdown signal received");
                // Persist cache counters/access times accrued since the
                // last mutation so a quiet period loses nothing.
                if let Some(store) = state.read().await.cache_store() {
                    if let Err(e) = store.flush() {
                        eprintln!("runner: cache index flush failed: {e}");
                    }
                }
                break;
            }
            changed = rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = *rx.borrow_and_update();
                let now = Instant::now();
                let mut guard = state.write().await;
                guard.prune_expired(now);
                guard.last_snapshot = snapshot;
                guard.poll_workstation_guards();
                guard.poll_afk();
                let weight = tick_weight(&guard, &snapshot, now);
                guard.last_weight = Some(weight);
                let base = detect_slots(guard.afk.boosted()).map(|r| r.slots).unwrap_or(1);
                let slots = guard.clamp_slots(effective_slots(base, &snapshot));
                guard.last_slots =
                    apply_workstation_guards(slots, guard.thermal_throttled, guard.discharging);
                drop(guard);
                if writable {
                    if let Err(e) = slice.set_weight(weight) {
                        eprintln!("runner: failed to apply cpu.weight={weight}: {e}");
                    }
                }
            }
        }
    }

    poller.stop();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::psi::{PsiFile, PsiLine};

    fn snapshot_with(cpu_some: f64, mem_some: f64, io_full: f64) -> PsiSnapshot {
        PsiSnapshot {
            cpu: PsiFile {
                some: PsiLine {
                    avg10: cpu_some,
                    ..Default::default()
                },
                ..Default::default()
            },
            memory: PsiFile {
                some: PsiLine {
                    avg10: mem_some,
                    ..Default::default()
                },
                ..Default::default()
            },
            io: PsiFile {
                full: PsiLine {
                    avg10: io_full,
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }

    #[test]
    fn tick_follows_pressure_ladder() {
        let state = SupervisorState::new();
        let now = Instant::now();
        assert_eq!(
            tick_weight(&state, &snapshot_with(10.0, 1.0, 1.0), now),
            100
        );
        assert_eq!(tick_weight(&state, &snapshot_with(30.0, 1.0, 1.0), now), 25);
        assert_eq!(tick_weight(&state, &snapshot_with(50.0, 1.0, 1.0), now), 1);
    }

    #[test]
    fn job_registry_tracks_finishes_and_caps() {
        let mut state = SupervisorState::new();
        state.job_started("github", "1", "ci / a");
        state.job_started("github", "2", "ci / b");
        assert_eq!(state.in_flight_jobs().len(), 2);
        // Re-recording the same id replaces instead of duplicating.
        state.job_started("github", "1", "ci / a-retry");
        assert_eq!(state.in_flight_jobs().len(), 2);
        state.job_finished("github", "1");
        let jobs = state.in_flight_jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "2");
        // Overflow rolls the oldest off.
        for i in 0..MAX_TRACKED_JOBS + 10 {
            state.job_started("github", &format!("x{i}"), "flood");
        }
        assert_eq!(state.in_flight_jobs().len(), MAX_TRACKED_JOBS);
        state.set_queue_depth(9);
        assert_eq!(state.queue_depth(), 9);
    }

    #[test]
    fn job_lifecycle_is_namespaced_by_provider() {
        let mut state = SupervisorState::new();
        state.job_started("github", "42", "ci");
        state.job_started("gitlab", "42", "test");
        assert_eq!(state.in_flight_jobs().len(), 2);
        // Finishing one forge's job keeps the other's record.
        state.job_finished("gitlab", "42");
        let jobs = state.in_flight_jobs();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].provider, "github");
        // Wrong-forge finish is a no-op.
        state.job_finished("bitbucket", "42");
        assert_eq!(state.in_flight_jobs().len(), 1);
        state.job_finished("github", "42");
        assert!(state.in_flight_jobs().is_empty());
    }

    #[test]
    fn slot_reservation_is_bounded_and_releasable() {
        let mut state = SupervisorState::new();
        state.last_slots = 2;
        assert!(state.try_reserve_slot());
        assert!(state.try_reserve_slot());
        assert!(!state.try_reserve_slot());
        assert_eq!(state.in_flight(), 2);
        state.release_slot_reservation();
        assert!(state.try_reserve_slot());
        // Release saturates at zero instead of underflowing.
        state.in_flight_dec();
        state.in_flight_dec();
        state.in_flight_dec();
        state.release_slot_reservation();
        assert_eq!(state.in_flight(), 0);
    }

    #[tokio::test]
    async fn concurrent_reservation_yields_exactly_last_slots_winners() {
        let state = new_shared_state();
        state.write().await.last_slots = 3;
        let mut handles = Vec::new();
        for _ in 0..12 {
            let state = state.clone();
            handles.push(tokio::spawn(async move {
                state.write().await.try_reserve_slot()
            }));
        }
        let mut wins = 0;
        for handle in handles {
            if handle.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 3);
        assert_eq!(state.read().await.in_flight(), 3);
    }

    #[test]
    fn forge_health_records_polls_and_errors() {
        let mut state = SupervisorState::new();
        assert!(state.forge_health().is_empty());
        state.record_forge_poll("gitlab", 2, None);
        state.record_forge_poll("github", 0, Some("HTTP 403".to_string()));
        let health = state.forge_health();
        assert_eq!(health["gitlab"].queue_depth, 2);
        assert!(health["gitlab"].last_error.is_none());
        assert!(health["gitlab"].last_poll_unix_ms > 0);
        assert_eq!(health["github"].last_error.as_deref(), Some("HTTP 403"));
        // Success clears the previous error.
        state.record_forge_poll("github", 1, None);
        assert!(state.forge_health()["github"].last_error.is_none());
    }

    #[test]
    fn tick_honors_configured_thresholds() {
        let mut config = RunnerConfig::default();
        config.governor.warn_cpu_psi = 70.0;
        config.governor.crit_cpu_psi = 90.0;
        let mut state = SupervisorState::new();
        state.seed_from_config(&config);
        let now = Instant::now();
        // 50% pressure is critical by default but normal under custom bands.
        assert_eq!(
            tick_weight(&state, &snapshot_with(50.0, 1.0, 1.0), now),
            100
        );
        assert_eq!(tick_weight(&state, &snapshot_with(80.0, 1.0, 1.0), now), 25);
        assert_eq!(tick_weight(&state, &snapshot_with(95.0, 1.0, 1.0), now), 1);
        // Thermal latch overrides even idle pressure with a trickle.
        state.thermal_throttled = true;
        assert_eq!(tick_weight(&state, &snapshot_with(1.0, 1.0, 1.0), now), 1);
    }

    #[test]
    fn workstation_guards_gate_slots() {
        // Battery halts all intake regardless of throttling.
        assert_eq!(apply_workstation_guards(4, false, true), 0);
        assert_eq!(apply_workstation_guards(4, true, true), 0);
        // Thermal throttle halves, rounding up, minimum one.
        assert_eq!(apply_workstation_guards(4, true, false), 2);
        assert_eq!(apply_workstation_guards(3, true, false), 2);
        assert_eq!(apply_workstation_guards(1, true, false), 1);
        // No guards: passthrough.
        assert_eq!(apply_workstation_guards(4, false, false), 4);
    }

    #[test]
    fn degenerate_config_keeps_safe_defaults() {
        // Degenerate config keeps safe defaults.
        let mut bad = RunnerConfig::default();
        bad.governor.warn_cpu_psi = 90.0;
        bad.governor.crit_cpu_psi = 10.0;
        let mut state = SupervisorState::new();
        state.seed_from_config(&bad);
        assert_eq!(state.psi_warn, crate::governor::psi::CPU_WARN);
        assert_eq!(state.psi_crit, crate::governor::psi::CPU_CRIT);
    }

    #[test]
    fn override_takes_stricter_weight() {
        let mut state = SupervisorState::new();
        let now = Instant::now();
        state.set_throttle(25, Duration::from_secs(60), now);
        // Override forces 25 even when pressure is normal ...
        assert_eq!(tick_weight(&state, &snapshot_with(5.0, 1.0, 1.0), now), 25);
        // ... but critical pressure still wins over a warning override.
        assert_eq!(tick_weight(&state, &snapshot_with(90.0, 1.0, 1.0), now), 1);
    }

    #[test]
    fn pressure_shrinks_effective_slots() {
        assert_eq!(effective_slots(4, &snapshot_with(5.0, 1.0, 1.0)), 4);
        assert_eq!(effective_slots(4, &snapshot_with(30.0, 1.0, 1.0)), 2);
        assert_eq!(effective_slots(4, &snapshot_with(50.0, 1.0, 1.0)), 1);
        assert_eq!(effective_slots(4, &snapshot_with(5.0, 20.0, 1.0)), 1);
    }

    #[test]
    fn reservations_expire_and_release() {
        let mut state = SupervisorState::new();
        let now = Instant::now();
        let res = state.reserve(2.0, 4096, Duration::from_secs(1), "t".into(), now);
        assert!(state.release(&res.id));
        assert!(!state.release(&res.id));
        state.reserve(1.0, 1024, Duration::from_secs(1), "t".into(), now);
        state.prune_expired(now + Duration::from_secs(2));
        assert!(state.reservations().is_empty());
    }

    #[test]
    fn afk_seed_defaults_to_auto() {
        let mut state = SupervisorState::new();
        state.seed_from_config(&RunnerConfig::default());
        assert_eq!(state.afk_mode, AfkMode::Auto);
        assert_eq!(state.afk_idle_secs, 300);
    }

    #[test]
    fn afk_always_never_bypass_probe() {
        let mut state = SupervisorState::new();
        state.afk_mode = AfkMode::Always;
        state.poll_afk();
        assert!(state.afk.boosted());
        assert!(state.afk_last_probe.is_none());
        state.afk_mode = AfkMode::Never;
        state.poll_afk();
        assert!(!state.afk.boosted());
        assert!(state.afk_last_probe.is_none());
    }

    #[test]
    fn afk_auto_throttles_within_window() {
        let mut state = SupervisorState::new();
        state.afk_mode = AfkMode::Auto;
        state.afk_last_probe = Some(Instant::now());
        // Recent probe: no subprocess spawned, latch untouched.
        state.poll_afk();
        assert!(!state.afk.boosted());
    }
}
