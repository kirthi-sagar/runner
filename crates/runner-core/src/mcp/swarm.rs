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
use tokio::sync::broadcast;

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
/// Per-session event bus buffer: lagging receivers drop old events,
/// the sender never blocks (see [`SwarmEvent`]).
pub const SWARM_EVENT_BUFFER: usize = 64;
/// Maximum members per swarm session: holderless joins are cheap
/// records, so an explicit ceiling (not pool exhaustion) bounds
/// table memory against runaway registrants.
pub const SWARM_MAX_MEMBERS: usize = 1024;

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

/// Real-time swarm lifecycle event, broadcast per session.
/// Emission is non-blocking fan-out: [`broadcast::Sender::send`]
/// never waits (receivers absent or lagging only lose events), so
/// publishing under the supervisor write lock cannot stall.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum SwarmEvent {
    StatusChanged {
        swarm_id: String,
        status: SwarmStatus,
    },
    CapacityYielded {
        swarm_id: String,
        agent_id: String,
        granted_to: Option<String>,
    },
    AgentPreempted {
        swarm_id: String,
        victim: String,
        by: String,
    },
    BudgetUpdated {
        swarm_id: String,
        spent_usd: f64,
    },
}

/// Execution tier for a swarm-dispatched job (names mirror the
/// sandbox driver names: `process`, `container`/`oci`,
/// `microvm`/`micro-vm`/`firecracker`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SwarmTier {
    Process,
    Container,
    MicroVm,
}

impl SwarmTier {
    /// Parse a tier name (case-insensitive, driver aliases honored).
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "process" => Ok(Self::Process),
            "microvm" | "micro-vm" | "firecracker" => Ok(Self::MicroVm),
            "container" | "oci" => Ok(Self::Container),
            other => Err(format!(
                "unknown execution tier: '{other}' (want process|container|microvm)"
            )),
        }
    }
}

/// One active swarm-dispatched job: the agent's slice covers its
/// draw (validated at dispatch), the pool accounting stays at the
/// slice level, and completion releases the agent for its next job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmJob {
    pub job_id: String,
    pub agent_id: String,
    pub tier: SwarmTier,
    pub cores: f64,
    pub memory_mb: u64,
}

/// One agent swarm: membership, its shared capacity pool, its spend
/// ledger, the FIFO execution wait queue (priority governs
/// preemption; FIFO governs the queue), active dispatches, and the
/// lifecycle event bus.
#[derive(Debug, Clone)]
pub struct SwarmSession {
    pub swarm_id: String,
    pub members: HashMap<String, SwarmAgent>,
    pub capacity_pool: SwarmPool,
    pub status: SwarmStatus,
    pub budget: SwarmBudget,
    pub waiters: VecDeque<String>,
    pub active_jobs: HashMap<String, SwarmJob>,
    pub next_job: u64,
    event_tx: broadcast::Sender<SwarmEvent>,
}

impl SwarmSession {
    pub fn new(swarm_id: String, cpu_weight_max: f64, memory_max_mb: u64) -> Self {
        let (event_tx, _) = broadcast::channel(SWARM_EVENT_BUFFER);
        Self {
            swarm_id,
            members: HashMap::new(),
            capacity_pool: SwarmPool::new(cpu_weight_max, memory_max_mb),
            status: SwarmStatus::Active,
            budget: SwarmBudget::new(0.0, DEFAULT_HOST_CORE_HOUR_USD),
            waiters: VecDeque::new(),
            active_jobs: HashMap::new(),
            next_job: 1,
            event_tx,
        }
    }

    /// Subscribe to this session's lifecycle events (buffered;
    /// lagging receivers observe `Lagged` and skip, never stall).
    pub fn subscribe(&self) -> broadcast::Receiver<SwarmEvent> {
        self.event_tx.subscribe()
    }

    /// Publish one event (non-blocking; receiver absence is silent).
    fn emit(&self, event: SwarmEvent) {
        let _ = self.event_tx.send(event);
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
        let core_hours = SWARM_AGENT_CORES * elapsed_secs / 3600.0;
        if core_hours > 0.0 {
            self.budget.record(core_hours);
            let spent_usd = self.budget.spent_usd;
            self.emit(SwarmEvent::BudgetUpdated {
                swarm_id: self.swarm_id.clone(),
                spent_usd,
            });
        }
    }

    /// Drop expired leases, accruing and returning their slices,
    /// abandoning their active jobs, and scrubbing the wait queue.
    /// Returns the pruned count.
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
            self.active_jobs.retain(|_, job| job.agent_id != *id);
            self.waiters.retain(|waiter| waiter != id);
        }
        expired.len()
    }

    /// Remove one id from the wait queue wherever it sits.
    fn dequeue(&mut self, agent_id: &str) {
        self.waiters.retain(|waiter| waiter != agent_id);
    }

    /// Serializable snapshot of this session for IPC/CLI surfaces.
    pub fn summarize(&self) -> SwarmSummary {
        SwarmSummary {
            swarm_id: self.swarm_id.clone(),
            status: self.status,
            member_count: self.members.len(),
            waiting_count: self.waiters.len(),
            active_jobs: self.active_jobs.len(),
            cpu_weight_allocated: self.capacity_pool.cpu_weight_allocated,
            cpu_weight_max: self.capacity_pool.cpu_weight_max,
            memory_allocated_mb: self.capacity_pool.memory_allocated_mb,
            memory_max_mb: self.capacity_pool.memory_max_mb,
            spent_usd: self.budget.spent_usd,
            spend_cap_usd: self.budget.cap_usd,
        }
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
/// retryable `-32603` host-probe denials. Capacity shortage never
/// denies: members join holderless and execution requests queue
/// (Phase 3 holderless membership). Budget exhaustion is `-32602`
/// per contract (the cap is a request precondition, like an
/// unknown id — not a transient shortage).
#[derive(Debug, Clone, PartialEq)]
pub enum SwarmError {
    /// Malformed request, duplicate, unknown id, or closed swarm.
    Invalid(String),
    /// Host capacity unreadable; fail closed without minting.
    Internal(String),
    /// Cumulative spend reached the configured cap.
    BudgetExceeded(String),
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Internal(message) | Self::BudgetExceeded(message) => {
                write!(f, "{message}")
            }
        }
    }
}

impl std::error::Error for SwarmError {}

/// Total slices out across every live session, as
/// `(cores, memory_mb)`. Callers prune expired leases first.
fn global_used(sessions: &HashMap<String, SwarmSession>) -> (f64, u64) {
    sessions.values().fold((0.0, 0), |totals, session| {
        (
            totals.0 + session.capacity_pool.cpu_weight_allocated,
            totals.1 + session.capacity_pool.memory_allocated_mb,
        )
    })
}

/// True when one more agent slice fits the host-global totals.
fn global_fits(
    sessions: &HashMap<String, SwarmSession>,
    host_cores: f64,
    host_mem_mb: u64,
) -> bool {
    let (used_cores, used_mem_mb) = global_used(sessions);
    used_cores + SWARM_AGENT_CORES <= host_cores
        && used_mem_mb.saturating_add(SWARM_AGENT_MEM_MB) <= host_mem_mb
}

/// Register one agent: validate, prune expired leases, create the
/// session on first use (host ceilings, policy budget), then draw a
/// slice when one fits — otherwise the member joins holderless and
/// queues (Phase 3 holderless membership: joins never deny on
/// capacity). Duplicate ids within a swarm reject; closed swarms
/// reject; a blown budget fails the join closed.
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
    // Host ceilings seed first-use sessions; the global fit check
    // runs at draw time (below), where holderless joins bypass it.
    let (host_cores, host_mem_mb) = host_capacity().map_err(SwarmError::Internal)?;
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
    if session.members.len() >= SWARM_MAX_MEMBERS {
        return Err(SwarmError::Invalid(format!(
            "swarm '{swarm_id}' is at member capacity ({SWARM_MAX_MEMBERS})"
        )));
    }
    // Joins draw execution capacity when it fits, so a blown budget
    // fails closed even before the fit check.
    session.budget.check()?;
    // Opportunistic draw: room in the session pool and the host
    // totals grants a slice at join; otherwise the member waits
    // holderless (high-priority joins then preempt at request time).
    let draws =
        session.capacity_pool.fits_agent() && global_fits(sessions, host_cores, host_mem_mb);
    let session = sessions
        .get_mut(swarm_id)
        .expect("just inserted or matched");
    let agent = SwarmAgent {
        agent_id: agent_id.to_string(),
        role: role.to_string(),
        priority,
        lease_expires_at: now + Duration::from_secs(SWARM_LEASE_SECS),
        holds_slice: draws,
        slice_acquired_at: draws.then_some(now),
    };
    session.members.insert(agent_id.to_string(), agent.clone());
    if draws {
        session.capacity_pool.alloc_agent();
    } else {
        session.waiters.push_back(agent_id.to_string());
    }
    Ok(SwarmLease::grant(session, &agent))
}

/// Release one agent's membership and (when held) its slice back to
/// the pool, accruing the hold to the spend ledger. Members with an
/// active job must complete it first (protocol discipline; expiry
/// abandons instead). Unknown swarms and ids fail closed (`-32602`,
/// mirroring reservation release).
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
    if session
        .active_jobs
        .values()
        .any(|job| job.agent_id == agent_id)
    {
        return Err(SwarmError::Invalid(format!(
            "agent '{agent_id}' still runs a job; complete it before leaving"
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
    session.emit(SwarmEvent::CapacityYielded {
        swarm_id: session.swarm_id.clone(),
        agent_id: agent_id.to_string(),
        granted_to: granted_to.clone(),
    });
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

/// Request an execution slice: budget-gated, then granted from
/// free pool (session fit and host-global fit), else by preempting
/// the lowest-priority strictly-lower holder (ties break by
/// smallest id), else queued FIFO. Already-holding members
/// re-grant idempotently.
pub fn request_execution_slice(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    now: Instant,
) -> Result<ExecutionGrant, SwarmError> {
    // Phase 1: membership, budget, and session fit (borrow
    // released before the table-wide global check below; the caller
    // holds the supervisor write lock throughout, so no TOCTOU).
    let (priority, session_fits) = {
        let session = sessions
            .get_mut(swarm_id)
            .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
        session.prune_expired(now);
        if session.status == SwarmStatus::Terminated {
            return Err(SwarmError::Invalid(format!(
                "swarm '{swarm_id}' is terminated; execution closed"
            )));
        }
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
        (priority, session.capacity_pool.fits_agent())
    };
    // A clean grant needs room in the session pool and the
    // host-global totals (sessions overcommit the host against each
    // other, so both gates bind every draw).
    if session_fits {
        let (host_cores, host_mem_mb) = host_capacity().map_err(SwarmError::Internal)?;
        if global_fits(sessions, host_cores, host_mem_mb) {
            let session = sessions
                .get_mut(swarm_id)
                .expect("membership checked above");
            grant_slice(session, agent_id, now);
            return Ok(ExecutionGrant::Granted { preempted: None });
        }
    }
    let session = sessions
        .get_mut(swarm_id)
        .expect("membership checked above");
    // Fully subscribed: evict the lowest strictly-lower holder
    // (deterministic by id within a rank), re-queueing the victim
    // at the front so preempted work resumes first. Eviction frees
    // both the session and the global draw, so no re-check fits.
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
            session.emit(SwarmEvent::AgentPreempted {
                swarm_id: session.swarm_id.clone(),
                victim: victim.clone(),
                by: agent_id.to_string(),
            });
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

/// Serializable session snapshot for the daemon IPC surface (the
/// live session holds `Instant`s and a broadcast sender, neither
/// of which crosses the wire).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmSummary {
    pub swarm_id: String,
    pub status: SwarmStatus,
    pub member_count: usize,
    pub waiting_count: usize,
    pub active_jobs: usize,
    pub cpu_weight_allocated: f64,
    pub cpu_weight_max: f64,
    pub memory_allocated_mb: u64,
    pub memory_max_mb: u64,
    pub spent_usd: f64,
    pub spend_cap_usd: f64,
}

/// Outcome of a [`terminate_swarm`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateOutcome {
    pub swarm_id: String,
    pub status: SwarmStatus,
    pub slices_reclaimed: usize,
    pub jobs_abandoned: usize,
}

/// Outcome of a [`dispatch_swarm_job`] call.
#[derive(Debug, Clone, PartialEq)]
pub enum DispatchOutcome {
    /// Job admitted and running (concurrently with any others).
    Dispatched(SwarmJob),
    /// No slice held and none obtainable right now: the member
    /// waits at this 1-based FIFO position; redispatch after a
    /// yield grants it (preemption may also displace it sooner).
    Queued { position: usize },
}

/// Dispatch one job for a swarm member: the member draws an
/// execution slice when holderless (grant, preempt, or queue —
/// shared with [`request_execution_slice`]), then the job draw is
/// validated against the agent's slice (one active job per agent;
/// capped at the slice size). Pool and host ceilings hold
/// transitively: every running job rides a pool-accounted slice.
pub fn dispatch_swarm_job(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    tier: &str,
    cores: f64,
    memory_mb: u64,
    now: Instant,
) -> Result<DispatchOutcome, SwarmError> {
    let session = sessions
        .get_mut(swarm_id)
        .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
    session.prune_expired(now);
    if session.status == SwarmStatus::Terminated {
        return Err(SwarmError::Invalid(format!(
            "swarm '{swarm_id}' is terminated; dispatches closed"
        )));
    }
    if !session.members.contains_key(agent_id) {
        return Err(SwarmError::Invalid(format!(
            "agent '{agent_id}' is not registered in swarm '{swarm_id}'"
        )));
    }
    // Money fail-fast: even a second job for a busy agent reports
    // the blown budget (this is the active-execution enforcement).
    session.budget.check()?;
    let tier = SwarmTier::parse(tier).map_err(SwarmError::Invalid)?;
    if !cores.is_finite() || cores <= 0.0 || memory_mb == 0 {
        return Err(SwarmError::Invalid(
            "job draw must be finite cores > 0 and memory_mb > 0".to_string(),
        ));
    }
    if cores > SWARM_AGENT_CORES || memory_mb > SWARM_AGENT_MEM_MB {
        return Err(SwarmError::Invalid(format!(
            "job draw ({cores} cores, {memory_mb} MiB) exceeds the agent slice \
             ({SWARM_AGENT_CORES} cores, {SWARM_AGENT_MEM_MB} MiB)"
        )));
    }
    if session
        .active_jobs
        .values()
        .any(|job| job.agent_id == agent_id)
    {
        return Err(SwarmError::Invalid(format!(
            "agent '{agent_id}' already runs a job; complete it first"
        )));
    }
    // Draw the slice when holderless (grant, preempt, or queue).
    match request_execution_slice(sessions, swarm_id, agent_id, now)? {
        ExecutionGrant::Queued { position } => return Ok(DispatchOutcome::Queued { position }),
        ExecutionGrant::Granted { .. } => {}
    }
    let session = sessions
        .get_mut(swarm_id)
        .expect("membership checked above");
    let job_id = format!("{swarm_id}-job-{}", session.next_job);
    session.next_job += 1;
    let job = SwarmJob {
        job_id: job_id.clone(),
        agent_id: agent_id.to_string(),
        tier,
        cores,
        memory_mb,
    };
    session.active_jobs.insert(job_id, job.clone());
    Ok(DispatchOutcome::Dispatched(job))
}

/// Complete one active job, releasing its agent for the next
/// dispatch. Spend stays slice-based (the hold accrues when the
/// slice itself releases), so completion only clears the record.
pub fn complete_swarm_job(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    job_id: &str,
    now: Instant,
) -> Result<SwarmJob, SwarmError> {
    let session = sessions
        .get_mut(swarm_id)
        .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
    session.prune_expired(now);
    session.active_jobs.remove(job_id).ok_or_else(|| {
        SwarmError::Invalid(format!("unknown job_id '{job_id}' in swarm '{swarm_id}'"))
    })
}

/// Move a swarm along Active → Draining → Terminated (no
/// resurrection, no post-terminal change). Draining keeps
/// incumbents running to lease end; Terminated closes dispatch
/// while the record lingers for audit.
pub fn transition_swarm_status(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    status: SwarmStatus,
    now: Instant,
) -> Result<(), SwarmError> {
    let session = sessions
        .get_mut(swarm_id)
        .ok_or_else(|| SwarmError::Invalid(format!("unknown swarm_id: '{swarm_id}'")))?;
    session.prune_expired(now);
    if session.status == status {
        return Ok(());
    }
    let legal = matches!(
        (session.status, status),
        (SwarmStatus::Active, SwarmStatus::Draining)
            | (SwarmStatus::Active, SwarmStatus::Terminated)
            | (SwarmStatus::Draining, SwarmStatus::Terminated)
    );
    if !legal {
        return Err(SwarmError::Invalid(format!(
            "illegal swarm transition {:?} -> {status:?}",
            session.status
        )));
    }
    session.status = status;
    session.emit(SwarmEvent::StatusChanged {
        swarm_id: session.swarm_id.clone(),
        status,
    });
    Ok(())
}

/// Terminate a swarm: transition to `Terminated` (from `Active` or
/// `Draining`), accrue and reclaim every held slice, abandon active
/// jobs, and clear the wait queue. Membership and the spend ledger
/// linger for audit. Idempotent: re-killing reports zeros.
pub fn terminate_swarm(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    now: Instant,
) -> Result<TerminateOutcome, SwarmError> {
    transition_swarm_status(sessions, swarm_id, SwarmStatus::Terminated, now)?;
    let session = sessions
        .get_mut(swarm_id)
        .expect("transition checked existence");
    let holders: Vec<String> = session
        .members
        .values()
        .filter(|agent| agent.holds_slice)
        .map(|agent| agent.agent_id.clone())
        .collect();
    for id in &holders {
        session.accrue(id, now);
        if let Some(agent) = session.members.get_mut(id) {
            agent.holds_slice = false;
            agent.slice_acquired_at = None;
        }
        session.capacity_pool.dealloc_agent();
    }
    let jobs_abandoned = session.active_jobs.len();
    session.active_jobs.clear();
    session.waiters.clear();
    Ok(TerminateOutcome {
        swarm_id: session.swarm_id.clone(),
        status: session.status,
        slices_reclaimed: holders.len(),
        jobs_abandoned,
    })
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
    fn subslice_pool_join_queues_holderless() {
        let mut table = sessions();
        // Session ceilings below one agent slice: the global host
        // check passes, the session pool denies.
        table.insert(
            "tiny".to_string(),
            SwarmSession::new("tiny".to_string(), 0.5, 512),
        );
        let lease = register_agent(&mut table, "tiny", "a", "builder", 0, Instant::now()).unwrap();
        // Sub-slice ceilings: the member joins holderless and queues
        // (Phase 3 holderless membership; joins never deny).
        assert!(!lease.holds_slice);
        assert_eq!(table["tiny"].capacity_pool.cpu_weight_allocated, 0.0);
        assert_eq!(table["tiny"].waiters.len(), 1);
    }

    #[test]
    fn full_pool_join_queues_in_order() {
        let mut table = sessions();
        tiny_session(&mut table, 1);
        let now = Instant::now();
        let first = register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        assert!(first.holds_slice);
        // Full pool: joins succeed holderless and queue in order.
        for (id, members) in [("b", 2), ("c", 3)] {
            let lease = register_agent(&mut table, "s", id, "tester", 0, now).unwrap();
            assert!(!lease.holds_slice, "{id}");
            assert_eq!(lease.active_members, members);
        }
        assert_eq!(
            table["s"].capacity_pool.cpu_weight_allocated,
            SWARM_AGENT_CORES
        );
        assert_eq!(
            table["s"].waiters.iter().collect::<Vec<_>>(),
            vec![&"b".to_string(), &"c".to_string()]
        );
        // A yield hands the slice to the front waiter only.
        let outcome = yield_execution_slice(&mut table, "s", "a", now).unwrap();
        assert_eq!(outcome.granted_to, Some("b".to_string()));
        assert!(table["s"].members["b"].holds_slice);
        assert!(!table["s"].members["c"].holds_slice);
    }

    #[test]
    fn global_capacity_never_oversubscribes_host() {
        let mut table = sessions();
        let now = Instant::now();
        let (host_cores, host_mem) = host_capacity().unwrap();
        // Over-join across sessions: joins always land (holderless
        // past capacity), slices stop at the host ceilings.
        let slices = ((host_cores / SWARM_AGENT_CORES).floor() as usize)
            .min((host_mem / SWARM_AGENT_MEM_MB) as usize);
        assert!(slices >= 1);
        for i in 0..slices + 3 {
            register_agent(
                &mut table,
                &format!("s{}", i % 2),
                &format!("a{i}"),
                "builder",
                0,
                now,
            )
            .unwrap();
        }
        let (used_cores, used_mem) = table.values().fold((0.0, 0), |totals, session| {
            (
                totals.0 + session.capacity_pool.cpu_weight_allocated,
                totals.1 + session.capacity_pool.memory_allocated_mb,
            )
        });
        assert!(used_cores <= host_cores, "{used_cores} > {host_cores}");
        assert!(used_mem <= host_mem, "{used_mem} > {host_mem}");
        assert_eq!(used_cores, slices as f64 * SWARM_AGENT_CORES);
        // Holderless members queue on request (nothing preemptible
        // at equal rank, even where the session pool has room: the
        // host-global gate binds too).
        let holderless: Vec<(String, String)> = table
            .values()
            .flat_map(|session| {
                session
                    .members
                    .values()
                    .filter(|member| !member.holds_slice)
                    .map(|member| (session.swarm_id.clone(), member.agent_id.clone()))
            })
            .collect();
        assert_eq!(holderless.len(), 3);
        for (swarm, id) in &holderless {
            assert!(matches!(
                request_execution_slice(&mut table, swarm, id, now).unwrap(),
                ExecutionGrant::Queued { .. }
            ));
        }
        // Session s0 provably holds a slice (first join drew) and a
        // waiter (its last join landed past capacity): a yield
        // recycles without overshoot.
        let holder = table["s0"]
            .members
            .values()
            .find(|member| member.holds_slice)
            .unwrap()
            .agent_id
            .clone();
        assert!(!table["s0"].waiters.is_empty());
        let outcome = yield_execution_slice(&mut table, "s0", &holder, now).unwrap();
        assert!(outcome.granted_to.is_some());
        let (used_cores, _) = table.values().fold((0.0, 0), |totals, session| {
            (
                totals.0 + session.capacity_pool.cpu_weight_allocated,
                totals.1 + session.capacity_pool.memory_allocated_mb,
            )
        });
        assert!(used_cores <= host_cores);
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

    #[test]
    fn dispatch_runs_multitier_jobs_concurrently() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        register_agent(&mut table, "s", "b", "tester", 0, now).unwrap();
        // Process + container jobs run simultaneously under the pool.
        let first = dispatch_swarm_job(&mut table, "s", "a", "container", 1.0, 1024, now);
        let second = dispatch_swarm_job(&mut table, "s", "b", "process", 0.5, 512, now);
        let (first, second) = match (first.unwrap(), second.unwrap()) {
            (DispatchOutcome::Dispatched(a), DispatchOutcome::Dispatched(b)) => (a, b),
            other => panic!("expected two dispatches, got {other:?}"),
        };
        assert_eq!(first.tier, SwarmTier::Container);
        assert_eq!(second.tier, SwarmTier::Process);
        assert_ne!(first.job_id, second.job_id);
        assert_eq!(table["s"].active_jobs.len(), 2);
        // Tier aliases parse; unknown tiers fail closed.
        assert_eq!(SwarmTier::parse("OCI").unwrap(), SwarmTier::Container);
        assert_eq!(SwarmTier::parse("micro-vm").unwrap(), SwarmTier::MicroVm);
        assert!(SwarmTier::parse("baremetal").is_err());
        // Completion releases agents one at a time.
        complete_swarm_job(&mut table, "s", &first.job_id, now).unwrap();
        assert_eq!(table["s"].active_jobs.len(), 1);
        complete_swarm_job(&mut table, "s", &second.job_id, now).unwrap();
        assert!(table["s"].active_jobs.is_empty());
        assert!(complete_swarm_job(&mut table, "s", &first.job_id, now).is_err());
    }

    #[test]
    fn dispatch_validates_draw_membership_and_busy() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        // Unknown swarm, member, and tier fail closed.
        assert!(dispatch_swarm_job(&mut table, "nope", "a", "process", 1.0, 512, now).is_err());
        assert!(dispatch_swarm_job(&mut table, "s", "ghost", "process", 1.0, 512, now).is_err());
        assert!(dispatch_swarm_job(&mut table, "s", "a", "baremetal", 1.0, 512, now).is_err());
        // Garbage and over-slice draws fail closed.
        for (cores, mem) in [(0.0, 512), (f64::NAN, 512), (1.0, 0)] {
            assert!(
                dispatch_swarm_job(&mut table, "s", "a", "process", cores, mem, now).is_err(),
                "{cores}/{mem}"
            );
        }
        let err = dispatch_swarm_job(&mut table, "s", "a", "process", 64.0, 512, now).unwrap_err();
        assert!(err.to_string().contains("exceeds the agent slice"), "{err}");
        // One active job per agent.
        dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, now).unwrap();
        let err = dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, now).unwrap_err();
        assert!(err.to_string().contains("already runs a job"), "{err}");
        // Members with active jobs must complete before leaving.
        let err = leave_swarm(&mut table, "s", "a", now).unwrap_err();
        assert!(err.to_string().contains("still runs a job"), "{err}");
    }

    #[test]
    fn dispatch_draws_slice_for_holderless_members() {
        let mut table = sessions();
        tiny_session(&mut table, 1);
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        register_agent(&mut table, "s", "b", "tester", 0, now).unwrap();
        assert!(!table["s"].members["b"].holds_slice);
        dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, now).unwrap();
        // B dispatches while sliceless against the full pool: queued.
        assert!(matches!(
            dispatch_swarm_job(&mut table, "s", "b", "container", 1.0, 512, now).unwrap(),
            DispatchOutcome::Queued { position: 1 }
        ));
        // A completes and yields: B redispatches into the free slice.
        let job = table["s"]
            .active_jobs
            .values()
            .next()
            .unwrap()
            .job_id
            .clone();
        complete_swarm_job(&mut table, "s", &job, now).unwrap();
        yield_execution_slice(&mut table, "s", "a", now).unwrap();
        assert!(matches!(
            dispatch_swarm_job(&mut table, "s", "b", "container", 1.0, 512, now).unwrap(),
            DispatchOutcome::Dispatched(_)
        ));
    }

    #[test]
    fn budget_blocks_dispatch_during_active_execution() {
        let mut table = sessions();
        table.insert(
            "s".to_string(),
            SwarmSession::new("s".to_string(), 64.0, 65_536).with_budget(0.5, 0.5),
        );
        let start = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, start).unwrap();
        register_agent(&mut table, "s", "b", "tester", 0, start).unwrap();
        // Two jobs running across tiers; A outlives the accrual jump.
        dispatch_swarm_job(&mut table, "s", "a", "container", 1.0, 512, start).unwrap();
        dispatch_swarm_job(&mut table, "s", "b", "process", 1.0, 512, start).unwrap();
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("a")
            .unwrap()
            .lease_expires_at = start + Duration::from_secs(7200);
        // B's hour-long hold accrues past the cap on yield (two
        // slices fit every CI host; a third member would overcommit
        // small runners).
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("b")
            .unwrap()
            .lease_expires_at = start + Duration::from_secs(7200);
        // B completes, then its hour-long hold accrues past the cap
        // on yield; B leaves the way clear.
        let job = table["s"]
            .active_jobs
            .values()
            .find(|job| job.agent_id == "b")
            .unwrap()
            .job_id
            .clone();
        complete_swarm_job(&mut table, "s", &job, start).unwrap();
        yield_execution_slice(&mut table, "s", "b", start + Duration::from_secs(3600)).unwrap();
        leave_swarm(&mut table, "s", "b", start + Duration::from_secs(3600)).unwrap();
        assert!(table["s"].budget.spent_usd >= 0.5);
        // A's job keeps running, but new dispatches fail closed with
        // the BudgetExceeded marker — even for busy agents.
        assert_eq!(table["s"].active_jobs.len(), 1);
        let err = dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, start).unwrap_err();
        assert!(matches!(err, SwarmError::BudgetExceeded(_)), "{err}");
        register_agent(&mut table, "s", "d", "builder", 0, start).unwrap_err();
    }

    #[tokio::test]
    async fn event_bus_delivers_lifecycle_in_order() {
        let mut table = sessions();
        tiny_session(&mut table, 1);
        let start = Instant::now();
        register_agent(&mut table, "s", "lo", "tester", 0, start).unwrap();
        register_agent(&mut table, "s", "hi", "builder", 9, start).unwrap();
        // Every lease outlives the hour-long accrual jump below.
        for id in ["lo", "hi"] {
            table
                .get_mut("s")
                .unwrap()
                .members
                .get_mut(id)
                .unwrap()
                .lease_expires_at = start + Duration::from_secs(7200);
        }
        let mut events = table["s"].subscribe();
        // Yield (0s hold: no spend event) hands the slice over.
        yield_execution_slice(&mut table, "s", "lo", start).unwrap();
        // High-priority re-dispatch preempts after an hour-long hold
        // accrues spend on the victim's release.
        register_agent(&mut table, "s", "mid", "tester", 0, start).unwrap();
        table
            .get_mut("s")
            .unwrap()
            .members
            .get_mut("mid")
            .unwrap()
            .lease_expires_at = start + Duration::from_secs(7200);
        assert_eq!(
            request_execution_slice(&mut table, "s", "mid", start).unwrap(),
            ExecutionGrant::Queued { position: 1 }
        );
        yield_execution_slice(&mut table, "s", "hi", start + Duration::from_secs(3600)).unwrap();
        assert_eq!(
            request_execution_slice(&mut table, "s", "hi", start + Duration::from_secs(3600))
                .unwrap(),
            ExecutionGrant::Granted {
                preempted: Some("mid".to_string())
            }
        );
        transition_swarm_status(&mut table, "s", SwarmStatus::Draining, start).unwrap();
        // Drain the bus: yield, spend, preemption, and status events
        // arrive in exact emission order.
        let mut got = Vec::new();
        while let Ok(Ok(event)) =
            tokio::time::timeout(Duration::from_millis(50), events.recv()).await
        {
            got.push(event);
        }
        assert_eq!(
            got,
            vec![
                SwarmEvent::CapacityYielded {
                    swarm_id: "s".to_string(),
                    agent_id: "lo".to_string(),
                    granted_to: Some("hi".to_string()),
                },
                SwarmEvent::BudgetUpdated {
                    swarm_id: "s".to_string(),
                    spent_usd: SWARM_AGENT_CORES * 0.05,
                },
                SwarmEvent::CapacityYielded {
                    swarm_id: "s".to_string(),
                    agent_id: "hi".to_string(),
                    granted_to: Some("mid".to_string()),
                },
                SwarmEvent::AgentPreempted {
                    swarm_id: "s".to_string(),
                    victim: "mid".to_string(),
                    by: "hi".to_string(),
                },
                SwarmEvent::StatusChanged {
                    swarm_id: "s".to_string(),
                    status: SwarmStatus::Draining,
                },
            ]
        );
    }

    #[test]
    fn membership_ceiling_rejects_past_1024() {
        let mut table = sessions();
        // Pre-fill directly (same module): 1024 protocol joins
        // would re-probe the host on every call.
        let mut session = SwarmSession::new("s".to_string(), 1_000_000.0, 1 << 40);
        for i in 0..SWARM_MAX_MEMBERS {
            session.members.insert(
                format!("a{i}"),
                SwarmAgent {
                    agent_id: format!("a{i}"),
                    role: "builder".to_string(),
                    priority: 0,
                    lease_expires_at: Instant::now() + Duration::from_secs(3600),
                    holds_slice: false,
                    slice_acquired_at: None,
                },
            );
        }
        table.insert("s".to_string(), session);
        let err =
            register_agent(&mut table, "s", "overflow", "builder", 0, Instant::now()).unwrap_err();
        assert!(matches!(err, SwarmError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("member capacity"), "{err}");
        assert_eq!(table["s"].members.len(), SWARM_MAX_MEMBERS);
    }

    #[test]
    fn terminate_reclaims_slices_jobs_and_waiters() {
        let mut table = sessions();
        tiny_session(&mut table, 2);
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        register_agent(&mut table, "s", "b", "tester", 0, now).unwrap();
        register_agent(&mut table, "s", "c", "auditor", 0, now).unwrap();
        dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, now).unwrap();
        let mut events = table["s"].subscribe();
        let outcome = terminate_swarm(&mut table, "s", now).unwrap();
        assert_eq!(outcome.status, SwarmStatus::Terminated);
        assert_eq!(outcome.slices_reclaimed, 2);
        assert_eq!(outcome.jobs_abandoned, 1);
        let session = &table["s"];
        assert_eq!(session.capacity_pool.cpu_weight_allocated, 0.0);
        assert!(session.active_jobs.is_empty());
        assert!(session.waiters.is_empty());
        assert!(session.members.values().all(|m| !m.holds_slice));
        // Membership lingers for audit; termination broadcasts.
        assert_eq!(session.members.len(), 3);
        assert!(matches!(
            events.try_recv(),
            Ok(SwarmEvent::StatusChanged { .. })
        ));
        // Re-killing is idempotent, unknown swarms fail closed.
        let again = terminate_swarm(&mut table, "s", now).unwrap();
        assert_eq!(again.slices_reclaimed, 0);
        assert_eq!(again.jobs_abandoned, 0);
        assert!(terminate_swarm(&mut table, "nope", now).is_err());
    }

    #[test]
    fn status_transitions_move_forward_only() {
        let mut table = sessions();
        let now = Instant::now();
        register_agent(&mut table, "s", "a", "builder", 0, now).unwrap();
        // Same-state transitions are idempotent no-ops.
        transition_swarm_status(&mut table, "s", SwarmStatus::Active, now).unwrap();
        transition_swarm_status(&mut table, "s", SwarmStatus::Draining, now).unwrap();
        // Draining incumbents keep running; joins close.
        dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, now).unwrap();
        assert!(register_agent(&mut table, "s", "b", "tester", 0, now).is_err());
        // No resurrection, no post-terminal change.
        assert!(transition_swarm_status(&mut table, "s", SwarmStatus::Active, now).is_err());
        transition_swarm_status(&mut table, "s", SwarmStatus::Terminated, now).unwrap();
        assert!(transition_swarm_status(&mut table, "s", SwarmStatus::Draining, now).is_err());
        // Terminated closes requests and dispatches; cleanup still flows.
        assert!(request_execution_slice(&mut table, "s", "a", now).is_err());
        assert!(dispatch_swarm_job(&mut table, "s", "a", "process", 1.0, 512, now).is_err());
        assert!(transition_swarm_status(&mut table, "nope", SwarmStatus::Active, now).is_err());
    }
}
