//! Supervisor daemon loop (Phase 1b).
//!
//! Ties the async PSI poller to cgroup weight transitions, recalculates
//! slots under live pressure, and owns shared daemon state (reservations,
//! throttle overrides, drained nodes) for the MCP and IPC frontends.
//!
//! Throttling is weight-only: this module never freezes cgroups, so test
//! timers and TCP keepalives survive critical pressure on trickle CPU.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::afk::AfkBoost;
use super::cgroup::{CgroupSlice, weight_for_cpu_psi};
use super::psi::{PressureLevel, PsiPoller, PsiSnapshot};
use super::topology::detect_slots;
use crate::config::{PeerRecord, RunnerConfig};
use crate::mesh::cloud::CloudNode;
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

/// Mutable daemon state shared across governor, MCP, and IPC tasks.
#[derive(Debug)]
pub struct SupervisorState {
    pub afk: AfkBoost,
    reservations: HashMap<String, Reservation>,
    throttle: Option<ThrottleOverride>,
    drained: HashMap<String, String>,
    peers: HashMap<String, PeerRecord>,
    cloud_nodes: Vec<CloudNode>,
    donor_caps: Option<(u32, u64)>,
    next_reservation: u64,
    in_flight: u32,
    pub last_snapshot: PsiSnapshot,
    pub last_weight: Option<u32>,
    pub last_slots: u32,
}

impl SupervisorState {
    pub fn new() -> Self {
        Self {
            afk: AfkBoost::new(),
            reservations: HashMap::new(),
            throttle: None,
            drained: HashMap::new(),
            peers: HashMap::new(),
            cloud_nodes: Vec::new(),
            donor_caps: None,
            next_reservation: 1,
            in_flight: 0,
            last_snapshot: PsiSnapshot::default(),
            last_weight: None,
            last_slots: 1,
        }
    }

    /// Seed WAN peers and donor caps from persisted config at startup.
    pub fn seed_from_config(&mut self, config: &RunnerConfig) {
        for peer in &config.peers {
            self.peers.insert(peer.node_id.clone(), peer.clone());
        }
        if let Some(donor) = &config.donor {
            self.donor_caps = Some((donor.max_cores, donor.max_ram_mb));
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

    /// Clamp slots to donor caps when this host serves foreign jobs.
    pub fn clamp_slots(&self, slots: u32) -> u32 {
        self.donor_caps.map_or(slots, |(cores, ram)| apply_donor_caps(slots, cores, ram))
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
    let pressure = weight_for_cpu_psi(snapshot.cpu_some_avg10());
    state.throttle_weight(now).map_or(pressure, |o| o.min(pressure))
}

/// Wait for SIGINT or SIGTERM.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
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
                let weight = tick_weight(&guard, &snapshot, now);
                guard.last_weight = Some(weight);
                let base = detect_slots(guard.afk.boosted()).map(|r| r.slots).unwrap_or(1);
                guard.last_slots = guard.clamp_slots(effective_slots(base, &snapshot));
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
                some: PsiLine { avg10: cpu_some, ..Default::default() },
                ..Default::default()
            },
            memory: PsiFile {
                some: PsiLine { avg10: mem_some, ..Default::default() },
                ..Default::default()
            },
            io: PsiFile {
                full: PsiLine { avg10: io_full, ..Default::default() },
                ..Default::default()
            },
        }
    }

    #[test]
    fn tick_follows_pressure_ladder() {
        let state = SupervisorState::new();
        let now = Instant::now();
        assert_eq!(tick_weight(&state, &snapshot_with(10.0, 1.0, 1.0), now), 100);
        assert_eq!(tick_weight(&state, &snapshot_with(30.0, 1.0, 1.0), now), 25);
        assert_eq!(tick_weight(&state, &snapshot_with(50.0, 1.0, 1.0), now), 1);
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
}
