//! Dynamic resource reservation protocol (v2.7.0 Phase 1).
//!
//! Canonical request envelope for `reserve_host_resources` /
//! `release_host_resources`, shared by the MCP dispatcher, the daemon
//! IPC arm, and the local fallback so all three normalize, validate,
//! and store identically.
//!
//! Wire compatibility: v1 clients send `ram_gb` + `duration_minutes`;
//! v2 clients send `memory_mb` + `duration_secs` + `priority`. When
//! both generations are present the v2 fields win (documented
//! precedence — migration clients routinely send both, so conflicts
//! must not error). Missing v1 fields no longer fail parsing; the
//! envelope requires some positive memory and duration from either
//! generation instead.
//!
//! Groundwork laid here, wired later:
//!
//! * Governor preemption: [`ReservationPriority`] ordering is the
//!   eviction rank, per-victim
//!   [`Reservation::preemptible_by`](crate::governor::supervisor::Reservation::preemptible_by)
//!   predicate, and [`select_preemption_victims`] greedy victim policy,
//!   wired into the reservation workflow with slot clamping in Phase 2.
//! * Spend ledger: [`ReservationRequest::billable_core_hours`] and
//!   [`estimated_cost_usd`](ReservationRequest::estimated_cost_usd)
//!   are the pure charging inputs a future `SpendLedger::record_*`
//!   entry will consume. No ledger writes in Phase 1.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::tools::ReserveHostResourcesArgs;
use crate::governor::supervisor::{Reservation, ReservationPriority};

/// Re-exported sanity ceilings (defined beside the config that
/// overrides them).
pub use crate::config::ReservationLimits;
/// Re-exported victim policy (defined beside the governor state it
/// acts on); the preemption groundwork tests below resolve through it.
pub use crate::governor::supervisor::select_preemption_victims;

/// Enterprise accounting hooks for the reservation lifecycle.
///
/// Core defines the trait and calls it; `runner-enterprise`
/// implements it (core→enterprise calls would cycle the crates).
/// Servers without installed hooks enforce limits only — budgeting
/// and accounting are enterprise value-add, so unwired operation
/// (unit tests, offline MCP fallback) stays functional.
///
/// Method contract: `check_budget` runs pre-grant (fail-closed deny
/// on unreadable ledgers, mirroring the cloud spend gate);
/// `on_grant` failures roll the grant back; `on_release` failures
/// are logged by the caller while the release stands (cleanup must
/// not strand capacity); `on_preempt` failures propagate (fail-closed
/// and self-healing: victims are already gone, so a retry admits);
/// `on_released` failures are logged per lease while pruning proceeds
/// (expiry is a fact of time — capacity restoration must never wait
/// on accounting IO).
pub trait ReservationHooks: Send + Sync + std::fmt::Debug {
    /// Deny when the estimated cost exceeds remaining budget.
    fn check_budget(&self, request: &ReservationRequest) -> Result<(), String>;
    /// Record a completed grant (ledger + audit).
    fn on_grant(
        &self,
        reservation: &Reservation,
        request: &ReservationRequest,
    ) -> Result<(), String>;
    /// Record an explicit release (ledger + audit; best-effort at the
    /// call site).
    fn on_release(&self, reservation: &Reservation) -> Result<(), String>;
    /// Record a natural expiry (ledger stamp + distinct audit record;
    /// best-effort at the prune call site).
    fn on_released(&self, reservation_id: &str) -> Result<(), String>;
    /// Record preemption victims evicted for an incoming request.
    fn on_preempt(
        &self,
        victim_ids: &[String],
        incoming: &ReservationRequest,
    ) -> Result<(), String>;
}

/// Scripted hooks double: records calls, replays a scripted budget
/// verdict. Shared by the MCP and IPC dispatch tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct ScriptHooks {
    /// Recorded calls: "budget", "grant:{id}", "release:{id}",
    /// "expired:{id}", "preempt:{n}".
    pub calls: std::sync::Mutex<Vec<String>>,
    /// When set, `check_budget` denies with this message (once).
    pub deny_budget_with: std::sync::Mutex<Option<String>>,
}

#[cfg(test)]
impl ReservationHooks for ScriptHooks {
    fn check_budget(&self, _request: &ReservationRequest) -> Result<(), String> {
        self.calls.lock().unwrap().push("budget".to_string());
        match self.deny_budget_with.lock().unwrap().take() {
            Some(message) => Err(message),
            None => Ok(()),
        }
    }

    fn on_grant(
        &self,
        reservation: &Reservation,
        _request: &ReservationRequest,
    ) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("grant:{}", reservation.id));
        Ok(())
    }

    fn on_release(&self, reservation: &Reservation) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("release:{}", reservation.id));
        Ok(())
    }

    fn on_released(&self, reservation_id: &str) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("expired:{reservation_id}"));
        Ok(())
    }

    fn on_preempt(
        &self,
        victim_ids: &[String],
        _incoming: &ReservationRequest,
    ) -> Result<(), String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("preempt:{}", victim_ids.len()));
        Ok(())
    }
}

/// Canonical reservation request envelope (v2 dynamic protocol).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReservationRequest {
    /// Fractional cores of CPU headroom.
    pub cores: f64,
    /// Memory headroom, MiB.
    pub memory_mb: u64,
    /// Preemption rank (default Normal).
    pub priority: ReservationPriority,
    /// Hold duration, seconds.
    pub duration_secs: u64,
    /// Human-readable purpose.
    pub reason: String,
}

impl ReservationRequest {
    /// Hold duration as a [`Duration`].
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.duration_secs)
    }

    /// Validate against limits plus the live table size. Re-checks
    /// positivity so direct constructors cannot bypass normalization.
    pub fn validate(&self, limits: &ReservationLimits, active: usize) -> Result<(), ReserveError> {
        if !self.cores.is_finite() || self.cores <= 0.0 {
            return Err(ReserveError::invalid("cores must be a finite value > 0"));
        }
        if self.memory_mb == 0 {
            return Err(ReserveError::invalid("memory_mb must be > 0"));
        }
        if self.duration_secs == 0 {
            return Err(ReserveError::invalid("duration_secs must be > 0"));
        }
        if self.cores > limits.max_cores {
            return Err(ReserveError::invalid(format!(
                "cores {} exceeds max {}",
                self.cores, limits.max_cores
            )));
        }
        if self.memory_mb > limits.max_memory_mb {
            return Err(ReserveError::invalid(format!(
                "memory_mb {} exceeds max {}",
                self.memory_mb, limits.max_memory_mb
            )));
        }
        if self.duration_secs > limits.max_duration_secs {
            return Err(ReserveError::invalid(format!(
                "duration_secs {} exceeds max {}",
                self.duration_secs, limits.max_duration_secs
            )));
        }
        if active >= limits.max_active {
            return Err(ReserveError::Full {
                active,
                max: limits.max_active,
            });
        }
        Ok(())
    }

    /// Billable core-hours (ledger charging input, Phase N).
    pub fn billable_core_hours(&self) -> f64 {
        self.cores * (self.duration_secs as f64 / 3600.0)
    }

    /// Estimated cost at a per-core-hour rate (ledger input, Phase N).
    pub fn estimated_cost_usd(&self, rate_per_core_hour: f64) -> f64 {
        self.billable_core_hours() * rate_per_core_hour
    }
}

/// Reservation failure: invalid requests (`-32602`) versus
/// retryable `-32603` denials (full table, exhausted budget —
/// preemption converts capacity denials into evictions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveError {
    /// Malformed or over-limit request.
    Invalid(String),
    /// Table at capacity.
    Full {
        /// Live reservations counted after pruning.
        active: usize,
        /// Configured ceiling.
        max: usize,
    },
    /// Estimated cost exceeds remaining budget.
    Budget(String),
}

impl ReserveError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl std::fmt::Display for ReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "{message}"),
            Self::Full { active, max } => write!(
                f,
                "reservation table full ({active} active, max {max}); \
                 retry after expiry or release"
            ),
            Self::Budget(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ReserveError {}

impl TryFrom<&ReserveHostResourcesArgs> for ReservationRequest {
    type Error = String;

    /// Normalize v1 and/or v2 wire args into the canonical envelope.
    /// v2 fields (`memory_mb`, `duration_secs`, `priority`) take
    /// precedence when present; legacy `ram_gb`/`duration_minutes`
    /// convert otherwise. Fails closed on missing, non-positive, or
    /// overflowing inputs (including a `duration_minutes` value whose
    /// seconds conversion would overflow `u64`).
    fn try_from(args: &ReserveHostResourcesArgs) -> Result<Self, String> {
        if !args.cores.is_finite() || args.cores <= 0.0 {
            return Err("cores must be a finite value > 0".to_string());
        }
        let memory_mb = match args.memory_mb {
            Some(mb) => mb,
            None => {
                if !args.ram_gb.is_finite() || args.ram_gb <= 0.0 {
                    return Err("memory allocation must be > 0 (memory_mb or ram_gb)".to_string());
                }
                (args.ram_gb * 1024.0) as u64
            }
        };
        if memory_mb == 0 {
            return Err("memory allocation must be > 0 (memory_mb or ram_gb)".to_string());
        }
        let duration_secs = match args.duration_secs {
            Some(secs) => secs,
            None => {
                if args.duration_minutes == 0 {
                    return Err(
                        "duration must be > 0 (duration_secs or duration_minutes)".to_string()
                    );
                }
                args.duration_minutes
                    .checked_mul(60)
                    .ok_or_else(|| "duration_minutes overflows the seconds range".to_string())?
            }
        };
        if duration_secs == 0 {
            return Err("duration must be > 0 (duration_secs or duration_minutes)".to_string());
        }
        Ok(ReservationRequest {
            cores: args.cores,
            memory_mb,
            priority: args.priority.unwrap_or_default(),
            duration_secs,
            reason: args.reason.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::supervisor::ReservationPriority::*;

    fn v1_args(cores: f64, ram_gb: f64, mins: u64) -> ReserveHostResourcesArgs {
        ReserveHostResourcesArgs {
            cores,
            ram_gb,
            duration_minutes: mins,
            reason: "t".to_string(),
            memory_mb: None,
            duration_secs: None,
            priority: None,
        }
    }

    #[test]
    fn normalize_v1_shape_converts_units() {
        let request = ReservationRequest::try_from(&v1_args(2.0, 4.0, 10)).unwrap();
        assert_eq!(request.cores, 2.0);
        assert_eq!(request.memory_mb, 4096);
        assert_eq!(request.priority, Normal);
        assert_eq!(request.duration_secs, 600);
        assert_eq!(request.duration(), Duration::from_secs(600));
    }

    #[test]
    fn normalize_v2_shape_ignores_legacy_zeros() {
        let args = ReserveHostResourcesArgs {
            cores: 1.5,
            ram_gb: 0.0,
            duration_minutes: 0,
            reason: String::new(),
            memory_mb: Some(2048),
            duration_secs: Some(90),
            priority: Some(High),
        };
        let request = ReservationRequest::try_from(&args).unwrap();
        assert_eq!(
            request,
            ReservationRequest {
                cores: 1.5,
                memory_mb: 2048,
                priority: High,
                duration_secs: 90,
                reason: String::new(),
            }
        );
    }

    #[test]
    fn normalize_v2_wins_over_legacy() {
        let args = ReserveHostResourcesArgs {
            cores: 2.0,
            ram_gb: 4.0,
            duration_minutes: 10,
            reason: "t".to_string(),
            memory_mb: Some(8192),
            duration_secs: Some(30),
            priority: Some(Critical),
        };
        let request = ReservationRequest::try_from(&args).unwrap();
        assert_eq!(request.memory_mb, 8192);
        assert_eq!(request.duration_secs, 30);
        assert_eq!(request.priority, Critical);
    }

    #[test]
    fn normalize_rejects_garbage_fail_closed() {
        // No memory from either generation.
        assert!(ReservationRequest::try_from(&v1_args(2.0, 0.0, 10)).is_err());
        let mut no_mem = v1_args(2.0, 4.0, 10);
        no_mem.memory_mb = Some(0);
        assert!(ReservationRequest::try_from(&no_mem).is_err());
        // No duration from either generation.
        assert!(ReservationRequest::try_from(&v1_args(2.0, 4.0, 0)).is_err());
        // Bad cores.
        for cores in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(
                ReservationRequest::try_from(&v1_args(cores, 4.0, 10)).is_err(),
                "cores={cores}"
            );
        }
        // Legacy minutes that would overflow seconds (v1 wrapped in
        // release / panicked in debug).
        assert!(ReservationRequest::try_from(&v1_args(2.0, 4.0, u64::MAX)).is_err());
        // Truncation-to-zero legacy memory.
        assert!(ReservationRequest::try_from(&v1_args(2.0, 1e-9, 10)).is_err());
    }

    #[test]
    fn validate_enforces_limits_and_capacity() {
        let limits = ReservationLimits::default();
        let request = ReservationRequest::try_from(&v1_args(2.0, 4.0, 10)).unwrap();
        assert!(request.validate(&limits, 0).is_ok());
        assert!(request.validate(&limits, limits.max_active).is_err());
        let over = ReservationRequest {
            cores: limits.max_cores + 1.0,
            ..request.clone()
        };
        assert!(matches!(
            over.validate(&limits, 0),
            Err(ReserveError::Invalid(_))
        ));
        let full = request.validate(&limits, limits.max_active).unwrap_err();
        assert!(matches!(full, ReserveError::Full { .. }));
        assert!(full.to_string().contains("table full"));
    }

    #[test]
    fn priority_orders_and_defaults() {
        assert!(Low < Normal && Normal < High && High < Critical);
        assert_eq!(ReservationPriority::default(), Normal);
        assert_eq!(serde_json::to_value(High).unwrap(), "high");
        assert_eq!(
            serde_json::from_value::<ReservationPriority>(serde_json::json!("critical")).unwrap(),
            Critical
        );
    }

    fn reservation(
        id: &str,
        cores: f64,
        ram_mb: u64,
        priority: ReservationPriority,
    ) -> Reservation {
        Reservation {
            id: id.to_string(),
            cores,
            ram_mb,
            reason: String::new(),
            expires_at: std::time::Instant::now() + Duration::from_secs(60),
            priority,
        }
    }

    #[test]
    fn preemptible_by_requires_strictly_higher_rank() {
        let low = reservation("a", 1.0, 512, Low);
        assert!(!low.preemptible_by(Low));
        assert!(low.preemptible_by(Normal));
        assert!(low.preemptible_by(Critical));
        let critical = reservation("b", 1.0, 512, Critical);
        assert!(!critical.preemptible_by(Critical));
        assert!(!critical.preemptible_by(High));
    }

    #[test]
    fn victims_cover_needs_lowest_first_or_nothing() {
        let table = vec![
            reservation("low-big", 8.0, 8192, Low),
            reservation("normal", 2.0, 2048, Normal),
            reservation("low-small", 1.0, 512, Low),
        ];
        // High incomer needing 2 cores / 2 GiB: lowest rank first.
        let victims = select_preemption_victims(&table, 2.0, 2048, High);
        assert_eq!(victims, vec!["low-big".to_string()]);
        // Normal incomer cannot touch the Normal incumbent.
        let victims = select_preemption_victims(&table, 1.0, 512, Normal);
        assert_eq!(victims.len(), 1);
        assert_ne!(victims[0], "normal");
        // Unmeetable needs evict nothing (all-or-nothing).
        assert!(select_preemption_victims(&table, 64.0, 65536, Critical).is_empty());
        // Nothing needed, nothing evicted.
        assert!(select_preemption_victims(&table, 0.0, 0, Critical).is_empty());
    }

    #[test]
    fn ledger_inputs_derive_from_envelope() {
        let request = ReservationRequest::try_from(&v1_args(2.0, 4.0, 60)).unwrap();
        assert_eq!(request.billable_core_hours(), 2.0);
        assert_eq!(request.estimated_cost_usd(0.05), 0.1);
    }
}
