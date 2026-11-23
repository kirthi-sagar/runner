//! Autonomous agent swarm protocol (v2.12.0 Phase 1).
//!
//! Membership and shared resource pooling for agent swarms:
//! agents register under a shared `swarm_id`, draw a fixed headroom
//! slice from the swarm's capacity pool, and hold it under a lease
//! until they leave or expire. Total swarm allocations across every
//! session can never exceed the physical host limits.
//!
//! Later phases add dynamic reallocation, tier dispatch, and event
//! broadcast; the daemon IPC arm converges then (Phase 1 tools run
//! against MCP-server-local state only).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::DEFAULT_HOST_CORE_HOUR_USD;
use crate::governor::topology::{detect_slots, JOB_MIN_CORES, JOB_MIN_MEM_MB};

/// CPU weight drawn per registered agent: the scheduler's minimum
/// job slice, so every member can always dispatch at least one job.
pub const SWARM_AGENT_CORES: f64 = JOB_MIN_CORES;
/// Memory drawn per registered agent, MiB (same minimum-slice rule).
pub const SWARM_AGENT_MEM_MB: u64 = JOB_MIN_MEM_MB;
/// Lease hold per registration, seconds (renewed by re-registering;
/// expiry returns the slice to the pool on the next mutation).
pub const SWARM_LEASE_SECS: u64 = 1800;

/// Physical host capacity ceiling: logical CPUs plus total RAM, MiB.
/// Detection failure fails the registration closed (unknown capacity
/// must never mint headroom).
pub fn host_capacity() -> Result<(f64, u64), String> {
    let report = detect_slots(false).map_err(|e| format!("cannot read host capacity: {e}"))?;
    Ok((f64::from(report.topology.logical), report.mem_total_mb))
}

/// Swarm lifecycle: registrations land only while `Active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwarmStatus {
    /// Accepting registrations.
    #[default]
    Active,
    /// No new members; incumbents run to lease end.
    Draining,
    /// Dissolved; the record lingers for audit, not dispatch.
    Terminated,
}

/// One registered swarm member.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmAgent {
    pub agent_id: String,
    /// Free-form capability tag (`builder`, `tester`, `auditor`).
    pub role: String,
    /// Intra-swarm rank: higher preempts lower for execution slices.
    pub priority: u32,
    /// Membership returns to the pool when this passes.
    pub lease_expires_at: Instant,
    /// True while the member holds an execution slice (drawn at
    /// registration; released by yield, preemption, leave, or
    /// expiry — the lease survives all but the last two).
    pub holds_slice: bool,
    /// Slice draw time for spend accrual (`None` while yielded).
    pub slice_acquired_at: Option<Instant>,
}

/// Shared resource pool: allocated vs maximum CPU weight and memory.
/// Remaining headroom is the session's active budget.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmPool {
    /// Maximum CPU weight (host logical cores at creation).
    pub cpu_weight_max: f64,
    /// Currently allocated CPU weight.
    pub cpu_weight_allocated: f64,
    /// Maximum memory, MiB (host total RAM at creation).
    pub memory_max_mb: u64,
    /// Currently allocated memory, MiB.
    pub memory_allocated_mb: u64,
}

impl SwarmPool {
    pub fn new(cpu_weight_max: f64, memory_max_mb: u64) -> Self {
        Self {
            cpu_weight_max,
            cpu_weight_allocated: 0.0,
            memory_max_mb,
            memory_allocated_mb: 0,
        }
    }

    /// Remaining headroom: the session's active budget.
    pub fn active_budget(&self) -> (f64, u64) {
        (
            (self.cpu_weight_max - self.cpu_weight_allocated).max(0.0),
            self.memory_max_mb.saturating_sub(self.memory_allocated_mb),
        )
    }

    /// True when one more agent slice fits.
    pub fn fits_agent(&self) -> bool {
        self.cpu_weight_allocated + SWARM_AGENT_CORES <= self.cpu_weight_max
            && self.memory_allocated_mb.saturating_add(SWARM_AGENT_MEM_MB) <= self.memory_max_mb
    }

    fn alloc_agent(&mut self) {
        self.cpu_weight_allocated += SWARM_AGENT_CORES;
        self.memory_allocated_mb = self.memory_allocated_mb.saturating_add(SWARM_AGENT_MEM_MB);
    }

    fn dealloc_agent(&mut self) {
        self.cpu_weight_allocated = (self.cpu_weight_allocated - SWARM_AGENT_CORES).max(0.0);
        self.memory_allocated_mb = self.memory_allocated_mb.saturating_sub(SWARM_AGENT_MEM_MB);
    }
}

/// Aggregated swarm spend ledger: core-hours and dollars across
/// every member. Slices accrue on release (yield, preemption,
/// leave, expiry) from the injected clock, so accounting is
/// deterministic under test.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmBudget {
    /// Spend ceiling, USD (0 = unenforced).
    pub cap_usd: f64,
    /// Transfer rate, USD per core-hour.
    pub rate_usd_per_core_hour: f64,
    /// Cumulative core-hours consumed by released slices.
    pub spent_core_hours: f64,
    /// Cumulative dollars consumed by released slices.
    pub spent_usd: f64,
}

/// Spend policy for sessions created on first use (cap plus
/// transfer rate, seeded from `[swarm]` by the tools path).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetPolicy {
    pub cap_usd: f64,
    pub rate_usd_per_core_hour: f64,
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            cap_usd: 0.0,
            rate_usd_per_core_hour: DEFAULT_HOST_CORE_HOUR_USD,
        }
    }
}

impl SwarmBudget {
    pub fn new(cap_usd: f64, rate_usd_per_core_hour: f64) -> Self {
        Self {
            cap_usd,
            rate_usd_per_core_hour,
            spent_core_hours: 0.0,
            spent_usd: 0.0,
        }
    }

    fn record(&mut self, core_hours: f64) {
        self.spent_core_hours += core_hours;
        self.spent_usd += core_hours * self.rate_usd_per_core_hour;
    }

    /// Fail closed once cumulative spend reaches a configured cap.
    pub fn check(&self) -> Result<(), SwarmError> {
        if self.cap_usd > 0.0 && self.spent_usd >= self.cap_usd {
            return Err(SwarmError::BudgetExceeded(format!(
                "BudgetExceeded: swarm spend ${:.2} reached the ${:.2} cap",
                self.spent_usd, self.cap_usd
            )));
        }
        Ok(())
    }
}

/// One agent swarm: membership, its shared capacity pool, its spend
/// ledger, and the FIFO execution wait queue (priority governs
/// preemption; FIFO governs the queue).
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmSession {
    pub swarm_id: String,
    pub members: HashMap<String, SwarmAgent>,
    pub capacity_pool: SwarmPool,
    pub status: SwarmStatus,
    pub budget: SwarmBudget,
    pub waiters: VecDeque<String>,
}

impl SwarmSession {
    pub fn new(swarm_id: String, cpu_weight_max: f64, memory_max_mb: u64) -> Self {
        Self {
            swarm_id,
            members: HashMap::new(),
            capacity_pool: SwarmPool::new(cpu_weight_max, memory_max_mb),
            status: SwarmStatus::Active,
            budget: SwarmBudget::new(0.0, DEFAULT_HOST_CORE_HOUR_USD),
            waiters: VecDeque::new(),
        }
    }

    pub fn with_budget(mut self, cap_usd: f64, rate_usd_per_core_hour: f64) -> Self {
        self.budget = SwarmBudget::new(cap_usd, rate_usd_per_core_hour);
        self
    }

    /// Accrue one member's held slice to the spend ledger (elapsed
    /// hold × slice cores × rate; clock-injected for determinism).
    fn accrue(&mut self, agent_id: &str, now: Instant) {
        let (holds, acquired) = match self.members.get(agent_id) {
            Some(agent) => (agent.holds_slice, agent.slice_acquired_at),
            None => return,
        };
        if !holds {
            return;
        }
        let elapsed_secs = acquired
            .map(|taken| now.saturating_duration_since(taken).as_secs_f64())
            .unwrap_or(0.0);
        self.budget
            .record(SWARM_AGENT_CORES * elapsed_secs / 3600.0);
    }

    /// Drop expired leases, accruing and returning their slices, and
    /// scrub them from the wait queue. Returns the pruned count.
    pub fn prune_expired(&mut self, now: Instant) -> usize {
        let expired: Vec<String> = self
            .members
            .iter()
            .filter(|(_, agent)| agent.lease_expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.accrue(id, now);
            let held = self.members.get(id).is_some_and(|agent| agent.holds_slice);
            self.members.remove(id);
            if held {
                self.capacity_pool.dealloc_agent();
            }
            self.waiters.retain(|waiter| waiter != id);
        }
        expired.len()
    }

    /// Remove one id from the wait queue wherever it sits.
    fn dequeue(&mut self, agent_id: &str) {
        self.waiters.retain(|waiter| waiter != agent_id);
    }
}

/// Registration confirmation: the member plus the pool state after
/// the draw (flat shape for agent parsing).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmLease {
    pub swarm_id: String,
    pub agent_id: String,
    pub role: String,
    pub priority: u32,
    pub lease_secs: u64,
    pub holds_slice: bool,
    pub cpu_weight_allocated: f64,
    pub cpu_weight_max: f64,
    pub memory_allocated_mb: u64,
    pub memory_max_mb: u64,
    pub active_members: usize,
    pub spent_usd: f64,
    pub spend_cap_usd: f64,
}

impl SwarmLease {
    fn grant(session: &SwarmSession, agent: &SwarmAgent) -> Self {
        Self {
            swarm_id: session.swarm_id.clone(),
            agent_id: agent.agent_id.clone(),
            role: agent.role.clone(),
            priority: agent.priority,
            lease_secs: SWARM_LEASE_SECS,
            holds_slice: agent.holds_slice,
            cpu_weight_allocated: session.capacity_pool.cpu_weight_allocated,
            cpu_weight_max: session.capacity_pool.cpu_weight_max,
            memory_allocated_mb: session.capacity_pool.memory_allocated_mb,
            memory_max_mb: session.capacity_pool.memory_max_mb,
            active_members: session.members.len(),
            spent_usd: session.budget.spent_usd,
            spend_cap_usd: session.budget.cap_usd,
        }
    }
}

/// Swarm membership failure: invalid requests (`-32602`) versus
/// retryable `-32603` capacity and host-probe denials. Budget
/// exhaustion is `-32602` per contract (the cap is a request
/// precondition, like an unknown id — not a transient shortage).
#[derive(Debug, Clone, PartialEq)]
pub enum SwarmError {
    /// Malformed request, duplicate, unknown id, or closed swarm.
    Invalid(String),
    /// No headroom left (session pool or host-global).
    Full(String),
    /// Host capacity unreadable; fail closed without minting.
    Internal(String),
    /// Cumulative spend reached the configured cap.
    BudgetExceeded(String),
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::Full(message)
            | Self::Internal(message)
            | Self::BudgetExceeded(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SwarmError {}

/// Register one agent: validate, prune expired leases, create the
/// session on first use (host ceilings, unenforced budget), then
/// draw the slice. Duplicate ids within a swarm reject; closed
/// swarms reject; the draw must fit both the session pool and the
/// host-global totals across every session.
pub fn register_agent(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    role: &str,
    priority: u32,
    now: Instant,
) -> Result<SwarmLease, SwarmError> {
    register_agent_with_budget(
        sessions,
        swarm_id,
        agent_id,
        role,
        priority,
        BudgetPolicy::default(),
        now,
    )
}

/// [`register_agent`] with an explicit spend policy for sessions
/// created on first use (the tools path passes the configured
/// `[swarm]` seeds).
pub fn register_agent_with_budget(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    role: &str,
    priority: u32,
    policy: BudgetPolicy,
    now: Instant,
) -> Result<SwarmLease, SwarmError> {
    if swarm_id.trim().is_empty() {
        return Err(SwarmError::Invalid(
            "swarm_id must not be empty".to_string(),
        ));
    }
    if agent_id.trim().is_empty() {
        return Err(SwarmError::Invalid(
            "agent_id must not be empty".to_string(),
        ));
    }
    if role.trim().is_empty() {
        return Err(SwarmError::Invalid("role must not be empty".to_string()));
    }
    for session in sessions.values_mut() {
        session.prune_expired(now);
    }
    // Host-global remaining across every live session.
    let (host_cores, host_mem_mb) = host_capacity().map_err(SwarmError::Internal)?;
    let (used_cores, used_mem_mb) = sessions.values().fold((0.0, 0), |totals, session| {
        (
            totals.0 + session.capacity_pool.cpu_weight_allocated,
            totals.1 + session.capacity_pool.memory_allocated_mb,
        )
    });
    if used_cores + SWARM_AGENT_CORES > host_cores
        || used_mem_mb.saturating_add(SWARM_AGENT_MEM_MB) > host_mem_mb
    {
        return Err(SwarmError::Full(format!(
            "host swarm capacity exhausted ({used_cores:.1}/{host_cores:.0} cores, \
             {used_mem_mb}/{host_mem_mb} MiB); retry after leave or expiry"
        )));
    }
    let session = match sessions.get(swarm_id) {
        Some(existing) => existing,
        None => {
            sessions.insert(
                swarm_id.to_string(),
                SwarmSession::new(swarm_id.to_string(), host_cores, host_mem_mb)
                    .with_budget(policy.cap_usd, policy.rate_usd_per_core_hour),
            );
            &sessions[swarm_id]
        }
    };
    if session.status != SwarmStatus::Active {
        return Err(SwarmError::Invalid(format!(
            "swarm '{swarm_id}' is {:?}; registrations closed",
            session.status
        )));
    }
    if session.members.contains_key(agent_id) {
        return Err(SwarmError::Invalid(format!(
            "agent '{agent_id}' is already registered in swarm '{swarm_id}'"
        )));
    }
    // Registration draws a slice (execution capacity), so a blown
    // budget fails the join closed, like a dispatch.
    session.budget.check()?;
    if !session.capacity_pool.fits_agent() {
        return Err(SwarmError::Full(format!(
            "swarm '{swarm_id}' pool exhausted; retry after leave or expiry"
        )));
    }
    let session = sessions
        .get_mut(swarm_id)
        .expect("just inserted or matched");
    let agent = SwarmAgent {
        agent_id: agent_id.to_string(),
        role: role.to_string(),
        priority,
        lease_expires_at: now + Duration::from_secs(SWARM_LEASE_SECS),
        holds_slice: true,
        slice_acquired_at: Some(now),
    };
    session.members.insert(agent_id.to_string(), agent.clone());
    session.capacity_pool.alloc_agent();
    Ok(SwarmLease::grant(session, &agent))
}

/// Release one agent's membership and (when held) its slice back to
/// the pool, accruing the hold to the spend ledger. Unknown swarms
/// and ids fail closed (`-32602`, mirroring reservation release).
pub fn leave_swarm(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    now: Instant,
) -> Result<SwarmLease, SwarmError> {
    let session = sessions
        .get_mut(swarm_id)
        .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
    session.prune_expired(now);
    if !session.members.contains_key(agent_id) {
        return Err(SwarmError::Invalid(format!(
            "agent '{agent_id}' is not registered in swarm '{swarm_id}'"
        )));
    }
    session.accrue(agent_id, now);
    let agent = session
        .members
        .remove(agent_id)
        .expect("membership checked");
    if agent.holds_slice {
        session.capacity_pool.dealloc_agent();
    }
    session.dequeue(agent_id);
    // The lease reports the pool after release (the agent record is
    // the removed one).
    Ok(SwarmLease::grant(session, &agent))
}

/// Outcome of a [`yield_execution_slice`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YieldOutcome {
    /// Front waiter instantly granted the freed slice, if any (0ms:
    /// granted synchronously under the same lock, no polling).
    pub granted_to: Option<String>,
}

/// Instant slice return: the member keeps its lease but its slice
/// accrues to the ledger and returns to the pool, and the front
/// waiter (if any) is granted it immediately.
pub fn yield_execution_slice(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    now: Instant,
) -> Result<YieldOutcome, SwarmError> {
    let session = sessions
        .get_mut(swarm_id)
        .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
    session.prune_expired(now);
    let holds = session
        .members
        .get(agent_id)
        .ok_or_else(|| {
            SwarmError::Invalid(format!(
                "agent '{agent_id}' is not registered in swarm '{swarm_id}'"
            ))
        })?
        .holds_slice;
    if !holds {
        return Err(SwarmError::Invalid(format!(
            "agent '{agent_id}' holds no execution slice to yield"
        )));
    }
    // Accrue before clearing: the hold timestamp gates the ledger.
    session.accrue(agent_id, now);
    if let Some(agent) = session.members.get_mut(agent_id) {
        agent.holds_slice = false;
        agent.slice_acquired_at = None;
    }
    session.capacity_pool.dealloc_agent();
    let granted_to = grant_front_waiter(session, now);
    Ok(YieldOutcome { granted_to })
}

/// Outcome of a [`request_execution_slice`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionGrant {
    /// Slice held now; `preempted` names the evicted lower-priority
    /// holder when one was displaced (`None` on a clean grant).
    Granted { preempted: Option<String> },
    /// No room and nothing preemptible: the member waits at this
    /// 1-based FIFO position until a yield frees a slice.
    Queued { position: usize },
}

/// Request an execution slice: budget-gated, then granted from free
/// pool, else by preempting the lowest-priority strictly-lower
/// holder (ties break by smallest id), else queued FIFO.
/// Already-holding members re-grant idempotently.
pub fn request_execution_slice(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    now: Instant,
) -> Result<ExecutionGrant, SwarmError> {
    let session = sessions
        .get_mut(swarm_id)
        .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
    session.prune_expired(now);
    let agent = session.members.get(agent_id).ok_or_else(|| {
        SwarmError::Invalid(format!(
            "agent '{agent_id}' is not registered in swarm '{swarm_id}'"
        ))
    })?;
    if agent.holds_slice {
        session.dequeue(agent_id);
        return Ok(ExecutionGrant::Granted { preempted: None });
    }
    let priority = agent.priority;
    session.budget.check()?;
    if session.capacity_pool.fits_agent() {
        grant_slice(session, agent_id, now);
        return Ok(ExecutionGrant::Granted { preempted: None });
    }
    // Fully subscribed: evict the lowest strictly-lower holder
    // (deterministic by id within a rank), re-queueing the victim
    // at the front so preempted work resumes first.
    let victim = session
        .members
        .values()
        .filter(|holder| holder.holds_slice && holder.priority < priority)
        .min_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.agent_id.cmp(&b.agent_id))
        })
        .map(|holder| holder.agent_id.clone());
    match victim {
        Some(victim) => {
            session.accrue(&victim, now);
            if let Some(holder) = session.members.get_mut(&victim) {
                holder.holds_slice = false;
                holder.slice_acquired_at = None;
            }
            session.capacity_pool.dealloc_agent();
            session.dequeue(&victim);
            session.waiters.push_front(victim.clone());
            grant_slice(session, agent_id, now);
            Ok(ExecutionGrant::Granted {
                preempted: Some(victim),
            })
        }
        None => {
            session.dequeue(agent_id);
            session.waiters.push_back(agent_id.to_string());
            Ok(ExecutionGrant::Queued {
                position: session.waiters.len(),
            })
        }
    }
}

/// Draw one slice for a member known to fit (pool checked by the
/// caller): stamp, allocate, dequeue.
fn grant_slice(session: &mut SwarmSession, agent_id: &str, now: Instant) {
    if let Some(agent) = session.members.get_mut(agent_id) {
        agent.holds_slice = true;
        agent.slice_acquired_at = Some(now);
    }
    session.capacity_pool.alloc_agent();
    session.dequeue(agent_id);
}

/// Grant the freed slice to the front waiter (skipping stale ids);
/// returns the grantee, if any.
fn grant_front_waiter(session: &mut SwarmSession, now: Instant) -> Option<String> {
    while let Some(next) = session.waiters.pop_front() {
        let waiting = session
            .members
            .get(&next)
            .is_some_and(|agent| !agent.holds_slice);
        if waiting {
            grant_slice(session, &next, now);
            return Some(next);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions() -> HashMap<String, SwarmSession> {
        HashMap::new()
    }

    #[test]
    fn register_creates_session_and_draws_slice() {
        let mut table = sessions();
        let lease = register_agent(
            &mut table,
            "swarm-a",
            "agent-1",
            "builder",
            3,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(lease.swarm_id, "swarm-a");
        assert_eq!(lease.agent_id, "agent-1");
        assert_eq!(lease.role, "builder");
        assert_eq!(lease.priority, 3);
        assert_eq!(lease.lease_secs, SWARM_LEASE_SECS);
        assert_eq!(lease.cpu_weight_allocated, SWARM_AGENT_CORES);
        assert_eq!(lease.memory_allocated_mb, SWARM_AGENT_MEM_MB);
        assert_eq!(lease.active_members, 1);
        let (host_cores, host_mem) = host_capacity().unwrap();
        assert_eq!(lease.cpu_weight_max, host_cores);
        assert_eq!(lease.memory_max_mb, host_mem);
        let session = &table["swarm-a"];
        assert_eq!(session.status, SwarmStatus::Active);
        assert_eq!(session.members.len(), 1);
        let (budget_cores, budget_mem) = session.capacity_pool.active_budget();
        assert_eq!(budget_cores, host_cores - SWARM_AGENT_CORES);
        assert_eq!(budget_mem, host_mem - SWARM_AGENT_MEM_MB);
    }

    #[test]
    fn register_rejects_garbage_fail_closed() {
        let mut table = sessions();
        let now = Instant::now();
        for (swarm, agent, role) in [
            ("", "a", "builder"),
            ("  ", "a", "builder"),
            ("s", "", "builder"),
            ("s", "a", ""),
            ("s", "a", "   "),
        ] {
            assert!(
                register_agent(&mut table, swarm, agent, role, 0, now).is_err(),
                "{swarm:?}/{agent:?}/{role:?}"
            );
        }
        assert!(table.is_empty());
    }

    #[test]
    fn duplicate_agent_rejects_within_swarm_only() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        let err = register_agent(&mut table, "s", "a", "tester", 9, now).unwrap_err();
        assert!(matches!(err, SwarmError::Invalid(_)));
        assert!(err.to_string().contains("already registered"), "{err}");
        // Same id in another swarm is a distinct membership.
        register_agent(&mut table, "other", "a", "tester", 9, now).unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn closed_swarms_reject_registrations() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        for status in [SwarmStatus::Draining, SwarmStatus::Terminated] {
            table.get_mut("s").unwrap().status = status;
            let err = register_agent(&mut table, "s", "b", "tester", 0, now).unwrap_err();
            assert!(matches!(err, SwarmError::Invalid(_)), "{status:?}");
            assert!(err.to_string().contains("registrations closed"), "{err}");
        }
    }

    #[test]
    fn exhausted_session_pool_denies_retryable() {
        let mut table = sessions();
        // Session ceilings below one agent slice: the global host
        // check passes, the session pool denies.
        table.insert(
            "tiny".to_string(),
            SwarmSession::new("tiny".to_string(), 0.5, 512),
        );
        let err =
            register_agent(&mut table, "tiny", "a", "builder", 0, Instant::now()).unwrap_err();
        assert!(matches!(err, SwarmError::Full(_)), "{err}");
        assert!(err.to_string().contains("pool exhausted"), "{err}");
        assert!(table["tiny"].members.is_empty());
    }

    #[test]
    fn global_capacity_never_oversubscribes_host() {
        let mut table = sessions();
        let now = Instant::now();
        let (host_cores, host_mem) = host_capacity().unwrap();
        // Fill every session until the host denies (bounded: real
        // hosts exhaust in hundreds of draws at most).
        let mut granted = 0;
        for i in 0..10_000 {
            match register_agent(
                &mut table,
                &format!("s{}", i % 4),
                &format!("a{i}"),
                "builder",
                0,
                now,
            ) {
                Ok(_) => granted += 1,
                Err(SwarmError::Full(_)) => break,
                Err(e) => panic!("unexpected: {e}"),
            }
        }
        assert!(granted > 0);
        let (used_cores, used_mem) = table.values().fold((0.0, 0), |totals, session| {
            (
                totals.0 + session.capacity_pool.cpu_weight_allocated,
                totals.1 + session.capacity_pool.memory_allocated_mb,
            )
        });
        assert!(used_cores <= host_cores, "{used_cores} > {host_cores}");
        assert!(used_mem <= host_mem, "{used_mem} > {host_mem}");
        assert_eq!(used_cores, granted as f64 * SWARM_AGENT_CORES);
    }

    #[test]
    fn leave_restores_capacity_and_rejects_unknowns() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        register_agent(&mut table, "s", "b", "tester", 0, now).unwrap();
        let lease = leave_swarm(&mut table, "s", "a", now).unwrap();
        assert_eq!(lease.active_members, 1);
        assert_eq!(lease.cpu_weight_allocated, SWARM_AGENT_CORES);
        assert_eq!(lease.memory_allocated_mb, SWARM_AGENT_MEM_MB);
        let lease = leave_swarm(&mut table, "s", "b", now).unwrap();
        assert_eq!(lease.active_members, 0);
        assert_eq!(lease.cpu_weight_allocated, 0.0);
        assert_eq!(lease.memory_allocated_mb, 0);
        // Unknown swarm and unknown member fail closed.
        assert!(matches!(
            leave_swarm(&mut table, "nope", "a", now).unwrap_err(),
            SwarmError::Invalid(_)
        ));
        assert!(matches!(
            leave_swarm(&mut table, "s", "ghost", now).unwrap_err(),
            SwarmError::Invalid(_)
        ));
    }

    #[test]
    fn expired_leases_prune_on_mutation() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "old", "builder", 0, now).unwrap();
        // Age the lease out by hand (same module: direct access).
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("old")
            .unwrap()
            .lease_expires_at = now - Duration::from_secs(1);
        // Next registration prunes the corpse first: pool holds only
        // the newcomer.
        let lease = register_agent(&mut table, "s", "new", "tester", 0, now).unwrap();
        assert_eq!(lease.active_members, 1);
        assert_eq!(lease.cpu_weight_allocated, SWARM_AGENT_CORES);
        assert!(!table["s"].members.contains_key("old"));
        // Direct prune reports counts.
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("new")
            .unwrap()
            .lease_expires_at = now - Duration::from_secs(1);
        assert_eq!(table.get_mut("s").unwrap().prune_expired(now), 1);
        assert_eq!(table["s"].capacity_pool.cpu_weight_allocated, 0.0);
    }

    /// Direct session with exact slice room (bypasses host ceilings;
    /// the global check still passes: tiny fits any host).
    fn tiny_session(table: &mut HashMap<String, SwarmSession>, slices: u32) {
        table.insert(
            "s".to_string(),
            SwarmSession::new(
                "s".to_string(),
                f64::from(slices) * SWARM_AGENT_CORES,
                u64::from(slices) * SWARM_AGENT_MEM_MB,
            ),
        );
    }

    #[test]
    fn handover_grants_waiter_synchronously() {
        let mut table = sessions();
        tiny_session(&mut table, 1);
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        // A yields; B joins into the free slice (pool full again).
        let outcome = yield_execution_slice(&mut table, "s", "a", now).unwrap();
        assert_eq!(outcome.granted_to, None);
        assert!(!table["s"].members["a"].holds_slice);
        register_agent(&mut table, "s", "b", "tester", 0, now).unwrap();
        // A requests against the full pool: equal rank queues.
        assert_eq!(
            request_execution_slice(&mut table, "s", "a", now).unwrap(),
            ExecutionGrant::Queued { position: 1 }
        );
        // B yields: A is granted under the same call (0ms, no poll).
        let outcome = yield_execution_slice(&mut table, "s", "b", now).unwrap();
        assert_eq!(outcome.granted_to, Some("a".to_string()));
        assert!(table["s"].members["a"].holds_slice);
        assert!(!table["s"].members["b"].holds_slice);
        assert!(table["s"].waiters.is_empty());
        assert_eq!(
            table["s"].capacity_pool.cpu_weight_allocated,
            SWARM_AGENT_CORES
        );
    }

    #[test]
    fn yield_without_slice_rejects() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        yield_execution_slice(&mut table, "s", "a", now).unwrap();
        let err = yield_execution_slice(&mut table, "s", "a", now).unwrap_err();
        assert!(matches!(err, SwarmError::Invalid(_)));
        assert!(
            err.to_string().contains("holds no execution slice"),
            "{err}"
        );
        assert!(matches!(
            yield_execution_slice(&mut table, "nope", "a", now).unwrap_err(),
            SwarmError::Invalid(_)
        ));
    }

    #[test]
    fn request_regrants_idempotently() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        assert_eq!(
            request_execution_slice(&mut table, "s", "a", now).unwrap(),
            ExecutionGrant::Granted { preempted: None }
        );
        assert_eq!(
            table["s"].capacity_pool.cpu_weight_allocated,
            SWARM_AGENT_CORES
        );
    }

    #[test]
    fn preemption_matrix_higher_displaces_lower_equal_queues() {
        // Higher preempts the lowest holder (id order within a rank);
        // the victim re-queues at the front.
        let mut table = sessions();
        tiny_session(&mut table, 2);
        let now = Instant::now();
        register_agent(&mut table, "s", "hi", "builder", 5, now).unwrap();
        register_agent(&mut table, "s", "low-b", "tester", 0, now).unwrap();
        yield_execution_slice(&mut table, "s", "hi", now).unwrap();
        register_agent(&mut table, "s", "low-a", "tester", 0, now).unwrap();
        assert_eq!(
            request_execution_slice(&mut table, "s", "hi", now).unwrap(),
            ExecutionGrant::Granted {
                preempted: Some("low-a".to_string())
            }
        );
        assert!(table["s"].members["hi"].holds_slice);
        assert!(!table["s"].members["low-a"].holds_slice);
        assert!(table["s"].members["low-b"].holds_slice);
        assert_eq!(
            table["s"].waiters.front().map(String::as_str),
            Some("low-a")
        );
        // Lower never preempts higher: it queues instead.
        let mut table = sessions();
        tiny_session(&mut table, 1);
        register_agent(&mut table, "s", "mid", "builder", 1, now).unwrap();
        yield_execution_slice(&mut table, "s", "mid", now).unwrap();
        register_agent(&mut table, "s", "top", "builder", 9, now).unwrap();
        assert_eq!(
            request_execution_slice(&mut table, "s", "mid", now).unwrap(),
            ExecutionGrant::Queued { position: 1 }
        );
        assert!(table["s"].members["top"].holds_slice);
    }

    #[test]
    fn spend_accrues_on_release_and_cap_denies() {
        let mut table = sessions();
        table.insert(
            "s".to_string(),
            SwarmSession::new("s".to_string(), 64.0, 65_536).with_budget(0.5, 0.5),
        );
        let start = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, start).unwrap();
        // Hold past the 1800s lease: extend it (same module access).
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("a")
            .unwrap()
            .lease_expires_at = start + Duration::from_secs(7200);
        // One exact hour of hold: 1.5 core-hours at $0.50 = $0.75.
        yield_execution_slice(&mut table, "s", "a", start + Duration::from_secs(3600)).unwrap();
        let budget = &table["s"].budget;
        assert_eq!(budget.spent_core_hours, SWARM_AGENT_CORES);
        assert_eq!(budget.spent_usd, SWARM_AGENT_CORES * 0.5);
        // Cap reached: joins and execution requests fail closed with
        // the BudgetExceeded marker.
        let err = register_agent(&mut table, "s", "b", "tester", 0, start).unwrap_err();
        assert!(matches!(err, SwarmError::BudgetExceeded(_)), "{err}");
        assert!(err.to_string().contains("BudgetExceeded"), "{err}");
        let err = request_execution_slice(&mut table, "s", "a", start).unwrap_err();
        assert!(matches!(err, SwarmError::BudgetExceeded(_)), "{err}");
        // Uncapped sessions never deny on spend (short hold stays
        // inside the lease).
        let mut free = sessions();
        register_agent(&mut free, "open", "a", "builder", 0, start).unwrap();
        yield_execution_slice(&mut free, "open", "a", start + Duration::from_secs(60)).unwrap();
        assert!(free["open"].budget.spent_usd > 0.0);
        register_agent(&mut free, "open", "b", "tester", 0, start).unwrap();
    }

    #[test]
    fn leave_accrues_spend_and_scrubs_waiters() {
        let mut table = sessions();
        tiny_session(&mut table, 1);
        let start = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, start).unwrap();
        yield_execution_slice(&mut table, "s", "a", start).unwrap();
        register_agent(&mut table, "s", "b", "tester", 0, start).unwrap();
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("b")
            .unwrap()
            .lease_expires_at = start + Duration::from_secs(10_800);
        request_execution_slice(&mut table, "s", "a", start).unwrap();
        assert_eq!(table["s"].waiters.len(), 1);
        // Leaving while queued scrubs the queue; leaving while
        // holding accrues the hold.
        leave_swarm(&mut table, "s", "a", start).unwrap();
        assert!(table["s"].waiters.is_empty());
        let lease = leave_swarm(&mut table, "s", "b", start + Duration::from_secs(7200)).unwrap();
        assert_eq!(lease.spent_usd, 2.0 * SWARM_AGENT_CORES * 0.05);
        assert_eq!(table["s"].capacity_pool.cpu_weight_allocated, 0.0);
    }
}
