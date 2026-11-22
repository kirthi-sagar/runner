//! Reservation spend accounting: billable core-hours and estimated
//! cost per host-reservation grant, plus the enterprise
//! [`ReservationHooks`] implementation the daemon installs at boot.
//!
//! Conventions mirror the cloud spend ledger: path-handle ledgers with
//! load-mutate-store ops, epoch-second timestamps, month attribution
//! by grant month. Two deliberate divergences: core-hours accrue with
//! second granularity (no whole-hour round-up — internal transfer
//! pricing, matching the envelope math exactly), and a zero monthly
//! cap means UNENFORCED (budgeting is opt-in restriction on a
//! previously free feature; cf. cloud, where zero denies).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::audit::{AuditLog, LogLevel};
use runner_core::mcp::reservation::{ReservationHooks, ReservationRequest};
use runner_core::mesh::cloud::ledger::year_month;

/// Nominal internal transfer rate, USD per core-hour. This prices
/// agent headroom against the monthly cap; it is not cloud money.
/// Configurable rate is a follow-up.
pub const RATE_HOST_CORE_HOUR_USD: f64 = 0.05;

/// One reservation's billable lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReservationSpendEntry {
    pub reservation_id: String,
    pub cores: f64,
    pub memory_mb: u64,
    /// Preemption rank label at grant (`"low"`…`"critical"`).
    pub priority: String,
    pub granted_at: u64,
    pub duration_secs: u64,
    /// Unix epoch seconds, or `None` while the lease runs.
    #[serde(default)]
    pub released_at: Option<u64>,
}

impl ReservationSpendEntry {
    /// Elapsed billable seconds through `now_secs` (frozen at release).
    pub fn elapsed_secs(&self, now_secs: u64) -> u64 {
        self.released_at
            .unwrap_or(now_secs)
            .saturating_sub(self.granted_at)
    }

    /// Accrued core-hours through `now_secs`.
    pub fn accrued_core_hours(&self, now_secs: u64) -> f64 {
        self.cores * (self.elapsed_secs(now_secs) as f64 / 3600.0)
    }

    /// Accrued USD through `now_secs`.
    pub fn accrued_cost_usd(&self, now_secs: u64) -> f64 {
        self.accrued_core_hours(now_secs) * RATE_HOST_CORE_HOUR_USD
    }

    /// Estimated total cost if held for the full duration.
    pub fn estimated_total_cost_usd(&self) -> f64 {
        self.cores * (self.duration_secs as f64 / 3600.0) * RATE_HOST_CORE_HOUR_USD
    }
}

/// Default ledger location (`~/.runner/reservation_spend.json`).
pub fn default_ledger_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".runner")
            .join("reservation_spend.json")
    })
}

/// Path-only reservation spend ledger handle (see module docs).
#[derive(Debug, Clone)]
pub struct ReservationSpendLedger {
    path: PathBuf,
}

impl ReservationSpendLedger {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Vec<ReservationSpendEntry>, String> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let text =
            std::fs::read_to_string(&self.path).map_err(|e| format!("spend ledger read: {e}"))?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&text).map_err(|e| format!("spend ledger parse: {e}"))
    }

    pub fn store(&self, entries: &[ReservationSpendEntry]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("spend ledger dir: {e}"))?;
        }
        let text = serde_json::to_string_pretty(entries)
            .map_err(|e| format!("spend ledger encode: {e}"))?;
        std::fs::write(&self.path, text).map_err(|e| format!("spend ledger write: {e}"))
    }

    /// Record a grant (no-op for duplicate ids).
    pub fn record_grant(&self, entry: ReservationSpendEntry) -> Result<(), String> {
        let mut entries = self.load()?;
        if !entries
            .iter()
            .any(|e| e.reservation_id == entry.reservation_id)
        {
            entries.push(entry);
            self.store(&entries)?;
        }
        Ok(())
    }

    /// Stamp a release (no-op for unknown ids).
    pub fn record_release(&self, reservation_id: &str, at: u64) -> Result<(), String> {
        let mut entries = self.load()?;
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.reservation_id == reservation_id)
        {
            entry.released_at = Some(at);
            self.store(&entries)?;
        }
        Ok(())
    }

    /// Total USD accrued by entries granted in (year, month).
    pub fn month_spend(&self, year: i32, month: u32, now_secs: u64) -> Result<f64, String> {
        Ok(self
            .load()?
            .iter()
            .filter(|e| year_month(e.granted_at) == (year, month))
            .map(|e| e.accrued_cost_usd(now_secs))
            .sum())
    }

    /// Spend for the calendar month containing `now_secs`.
    pub fn current_month_spend(&self, now_secs: u64) -> Result<f64, String> {
        let (year, month) = year_month(now_secs);
        self.month_spend(year, month, now_secs)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Enterprise accounting: budget gate + ledger + audit trail.
/// Paths are explicit (tests use temp dirs); missing paths degrade
/// gracefully — except the budget gate, which denies when a
/// configured cap cannot be verified.
#[derive(Debug)]
pub struct EnterpriseReservationHooks {
    ledger: Option<ReservationSpendLedger>,
    audit_path: Option<PathBuf>,
    monthly_cap_usd: f64,
}

impl EnterpriseReservationHooks {
    pub fn new(
        ledger_path: Option<PathBuf>,
        audit_path: Option<PathBuf>,
        monthly_cap_usd: f64,
    ) -> Self {
        Self {
            ledger: ledger_path.map(ReservationSpendLedger::new),
            audit_path,
            monthly_cap_usd,
        }
    }

    pub fn from_default_paths(monthly_cap_usd: f64) -> Self {
        Self::new(
            default_ledger_path(),
            super::audit::default_audit_path(),
            monthly_cap_usd,
        )
    }

    /// Best-effort audit append (mirrors every other audit call site:
    /// open failures skip silently, appends never fail).
    fn audit(&self, level: LogLevel, message: String) {
        let Some(path) = &self.audit_path else {
            return;
        };
        if let Ok(mut log) = AuditLog::open(path) {
            log.append(level, "reservation", &message);
        }
    }
}

impl ReservationHooks for EnterpriseReservationHooks {
    fn check_budget(&self, request: &ReservationRequest) -> Result<(), String> {
        if self.monthly_cap_usd <= 0.0 {
            return Ok(());
        }
        let Some(ledger) = &self.ledger else {
            return Err("cannot verify reservation spend: ledger unavailable; \
                 refusing to provision blind"
                .to_string());
        };
        let now = now_secs();
        let spent = ledger.current_month_spend(now).map_err(|e| {
            format!("cannot verify reservation spend against the ledger ({e}); refusing to provision blind")
        })?;
        let estimate = request.estimated_cost_usd(RATE_HOST_CORE_HOUR_USD);
        if spent + estimate > self.monthly_cap_usd {
            return Err(format!(
                "reservation estimated ${estimate:.2} exceeds remaining monthly budget \
                 ${:.2} of ${:.2} cap",
                (self.monthly_cap_usd - spent).max(0.0),
                self.monthly_cap_usd
            ));
        }
        Ok(())
    }

    fn on_grant(
        &self,
        reservation: &runner_core::governor::supervisor::Reservation,
        request: &ReservationRequest,
    ) -> Result<(), String> {
        let priority = serde_json::to_value(reservation.priority)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "normal".to_string());
        if let Some(ledger) = &self.ledger {
            ledger.record_grant(ReservationSpendEntry {
                reservation_id: reservation.id.clone(),
                cores: reservation.cores,
                memory_mb: reservation.ram_mb,
                priority: priority.clone(),
                granted_at: now_secs(),
                duration_secs: request.duration_secs,
                released_at: None,
            })?;
        }
        self.audit(
            LogLevel::Info,
            format!(
                "granted {}: {} cores, {} MiB, {priority} priority, est ${:.2}",
                reservation.id,
                reservation.cores,
                reservation.ram_mb,
                request.estimated_cost_usd(RATE_HOST_CORE_HOUR_USD),
            ),
        );
        Ok(())
    }

    fn on_release(
        &self,
        reservation: &runner_core::governor::supervisor::Reservation,
    ) -> Result<(), String> {
        if let Some(ledger) = &self.ledger {
            ledger.record_release(&reservation.id, now_secs())?;
        }
        self.audit(LogLevel::Info, format!("released {}", reservation.id));
        Ok(())
    }

    fn on_released(&self, reservation_id: &str) -> Result<(), String> {
        if let Some(ledger) = &self.ledger {
            ledger.record_release(reservation_id, now_secs())?;
        }
        self.audit(
            LogLevel::Info,
            format!("reservation {reservation_id} expired naturally; headroom reclaimed"),
        );
        Ok(())
    }

    fn on_preempt(
        &self,
        victim_ids: &[String],
        incoming: &ReservationRequest,
    ) -> Result<(), String> {
        self.audit(
            LogLevel::Warn,
            format!(
                "preempted [{}] for {} cores, {} MiB at {:?} priority",
                victim_ids.join(", "),
                incoming.cores,
                incoming.memory_mb,
                incoming.priority,
            ),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_core::governor::supervisor::ReservationPriority;

    /// 2026-11-16T00:00:00Z.
    const NOV_16: u64 = 1_794_787_200;
    /// 2026-12-16T00:00:00Z.
    const DEC_16: u64 = NOV_16 + 30 * 86_400;

    fn temp_dir(tag: &str) -> runner_core::test_support::TempDir {
        runner_core::test_support::TempDir::new(tag).unwrap()
    }

    fn entry(id: &str, cores: f64, granted_at: u64, duration_secs: u64) -> ReservationSpendEntry {
        ReservationSpendEntry {
            reservation_id: id.to_string(),
            cores,
            memory_mb: 1024,
            priority: "normal".to_string(),
            granted_at,
            duration_secs,
            released_at: None,
        }
    }

    #[test]
    fn entry_math_accrues_and_freezes_at_release() {
        let mut e = entry("r1", 2.0, NOV_16, 7200);
        // One hour in: 2 core-hours at the nominal rate.
        assert_eq!(e.accrued_core_hours(NOV_16 + 3600), 2.0);
        assert_eq!(
            e.accrued_cost_usd(NOV_16 + 3600),
            2.0 * RATE_HOST_CORE_HOUR_USD
        );
        assert_eq!(e.estimated_total_cost_usd(), 4.0 * RATE_HOST_CORE_HOUR_USD);
        // Release freezes accrual: far-future cost equals release cost.
        e.released_at = Some(NOV_16 + 3600);
        assert_eq!(
            e.accrued_cost_usd(NOV_16 + 100_000),
            e.accrued_cost_usd(NOV_16 + 3600)
        );
    }

    #[test]
    fn ledger_roundtrip_attributes_by_grant_month() {
        let dir = temp_dir("spend-ledger");
        let ledger = ReservationSpendLedger::new(dir.path().join("spend.json"));
        assert_eq!(ledger.current_month_spend(NOV_16 + 3600).unwrap(), 0.0);
        ledger
            .record_grant(entry("nov", 2.0, NOV_16, 7200))
            .unwrap();
        ledger
            .record_grant(entry("dec", 2.0, DEC_16, 7200))
            .unwrap();
        // Duplicate grant is a no-op (idempotent agents).
        ledger
            .record_grant(entry("nov", 2.0, NOV_16, 7200))
            .unwrap();
        assert_eq!(ledger.load().unwrap().len(), 2);
        // Only the November grant counts toward November spend.
        let spend = ledger.current_month_spend(NOV_16 + 3600).unwrap();
        assert_eq!(spend, 2.0 * RATE_HOST_CORE_HOUR_USD);
        // Unknown release is a no-op.
        ledger.record_release("ghost", NOV_16 + 10).unwrap();
        ledger.record_release("nov", NOV_16 + 3600).unwrap();
        let loaded = ledger.load().unwrap();
        assert_eq!(
            loaded
                .iter()
                .find(|e| e.reservation_id == "nov")
                .unwrap()
                .released_at,
            Some(NOV_16 + 3600)
        );
    }

    fn hooks_with_cap(
        dir: &runner_core::test_support::TempDir,
        cap: f64,
    ) -> EnterpriseReservationHooks {
        EnterpriseReservationHooks::new(
            Some(dir.path().join("spend.json")),
            Some(dir.path().join("audit.jsonl")),
            cap,
        )
    }

    fn request(cores: f64, secs: u64) -> ReservationRequest {
        ReservationRequest {
            cores,
            memory_mb: 1024,
            priority: ReservationPriority::Normal,
            duration_secs: secs,
            reason: "t".to_string(),
        }
    }

    #[test]
    fn budget_gate_enforces_remaining_cap() {
        let dir = temp_dir("spend-budget");
        // 2 cores x 1h x $0.05 = $0.10 estimate.
        let hooks = hooks_with_cap(&dir, 0.05);
        let err = hooks.check_budget(&request(2.0, 3600)).unwrap_err();
        assert!(err.contains("exceeds remaining monthly budget"), "{err}");
        let hooks = hooks_with_cap(&dir, 10.0);
        assert!(hooks.check_budget(&request(2.0, 3600)).is_ok());
        // Zero cap means unenforced (deliberate cloud divergence).
        let hooks = hooks_with_cap(&dir, 0.0);
        assert!(hooks.check_budget(&request(1024.0, 604_800)).is_ok());
    }

    #[test]
    fn budget_gate_denies_unreadable_ledger() {
        let dir = temp_dir("spend-corrupt");
        std::fs::write(dir.path().join("spend.json"), "{not json").unwrap();
        let hooks = hooks_with_cap(&dir, 10.0);
        let err = hooks.check_budget(&request(1.0, 60)).unwrap_err();
        assert!(err.contains("refusing to provision blind"), "{err}");
    }

    #[test]
    fn natural_expiry_stamps_ledger_and_audits_reclaim() {
        use runner_core::governor::supervisor::{ReservationPriority, SupervisorState};
        use runner_core::mcp::reservation::ReservationHooks;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let dir = temp_dir("spend-expiry");
        let mut state = SupervisorState::new();
        state.set_reservation_hooks(Arc::new(hooks_with_cap(&dir, 0.0)));
        let now = Instant::now();
        // Seed the ledger the way on_grant would, then expire.
        let reservation = state.reserve(
            2.0,
            2048,
            Duration::from_secs(1),
            "t".into(),
            ReservationPriority::Normal,
            now,
        );
        let hooks = hooks_with_cap(&dir, 0.0);
        hooks.on_grant(&reservation, &request(2.0, 3600)).unwrap();
        state.prune_expired(now + Duration::from_secs(2));
        // Ledger stamped released; audit carries the exact reclaim line.
        let ledger = ReservationSpendLedger::new(dir.path().join("spend.json"));
        let entries = ledger.load().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].released_at.is_some());
        let trail = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(
            trail.contains(&format!(
                "reservation {} expired naturally; headroom reclaimed",
                reservation.id
            )),
            "{trail}"
        );
        let log = super::super::audit::AuditLog::open(&dir.path().join("audit.jsonl")).unwrap();
        assert!(log.verify());
    }

    #[test]
    fn grant_release_preempt_record_ledger_and_audit() {
        use runner_core::governor::supervisor::Reservation;
        let dir = temp_dir("spend-hooks");
        let hooks = hooks_with_cap(&dir, 0.0);
        let reservation = Reservation {
            id: "res-7".to_string(),
            cores: 2.0,
            ram_mb: 2048,
            reason: "t".to_string(),
            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(60),
            priority: ReservationPriority::High,
        };
        hooks.on_grant(&reservation, &request(2.0, 3600)).unwrap();
        hooks
            .on_preempt(&["res-1".to_string()], &request(4.0, 60))
            .unwrap();
        hooks.on_release(&reservation).unwrap();
        // Ledger: stamped release + intact entry.
        let ledger = ReservationSpendLedger::new(dir.path().join("spend.json"));
        let entries = ledger.load().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].released_at.is_some());
        // Audit: chained trail with all three events.
        let log = super::super::audit::AuditLog::open(&dir.path().join("audit.jsonl")).unwrap();
        assert!(log.verify());
        let trail = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(trail.contains("granted res-7"), "{trail}");
        assert!(trail.contains("preempted [res-1]"), "{trail}");
        assert!(trail.contains("released res-7"), "{trail}");
    }
}
