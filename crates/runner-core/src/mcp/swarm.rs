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

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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
    /// Intra-swarm rank: higher preempts lower (mechanics land with
    /// dynamic reallocation; Phase 1 stores and reports it).
    pub priority: u32,
    /// Slice returns to the pool when this passes.
    pub lease_expires_at: Instant,
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

/// One agent swarm: membership plus its shared capacity pool.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmSession {
    pub swarm_id: String,
    pub members: HashMap<String, SwarmAgent>,
    pub capacity_pool: SwarmPool,
    pub status: SwarmStatus,
}

impl SwarmSession {
    pub fn new(swarm_id: String, cpu_weight_max: f64, memory_max_mb: u64) -> Self {
        Self {
            swarm_id,
            members: HashMap::new(),
            capacity_pool: SwarmPool::new(cpu_weight_max, memory_max_mb),
            status: SwarmStatus::Active,
        }
    }

    /// Drop expired leases, returning their slices. Returns the
    /// pruned member count.
    pub fn prune_expired(&mut self, now: Instant) -> usize {
        let expired: Vec<String> = self
            .members
            .iter()
            .filter(|(_, agent)| agent.lease_expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.members.remove(id);
            self.capacity_pool.dealloc_agent();
        }
        expired.len()
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
    pub cpu_weight_allocated: f64,
    pub cpu_weight_max: f64,
    pub memory_allocated_mb: u64,
    pub memory_max_mb: u64,
    pub active_members: usize,
}

impl SwarmLease {
    fn grant(session: &SwarmSession, agent: &SwarmAgent) -> Self {
        Self {
            swarm_id: session.swarm_id.clone(),
            agent_id: agent.agent_id.clone(),
            role: agent.role.clone(),
            priority: agent.priority,
            lease_secs: SWARM_LEASE_SECS,
            cpu_weight_allocated: session.capacity_pool.cpu_weight_allocated,
            cpu_weight_max: session.capacity_pool.cpu_weight_max,
            memory_allocated_mb: session.capacity_pool.memory_allocated_mb,
            memory_max_mb: session.capacity_pool.memory_max_mb,
            active_members: session.members.len(),
        }
    }
}

/// Swarm membership failure: invalid requests (`-32602`) versus
/// retryable `-32603` capacity and host-probe denials.
#[derive(Debug, Clone, PartialEq)]
pub enum SwarmError {
    /// Malformed request, duplicate, unknown id, or closed swarm.
    Invalid(String),
    /// No headroom left (session pool or host-global).
    Full(String),
    /// Host capacity unreadable; fail closed without minting.
    Internal(String),
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::Full(message) | Self::Internal(message) => {
                write!(f, "{message}")
            }
        }
    }
}

impl std::error::Error for SwarmError {}

/// Register one agent: validate, prune expired leases, create the
/// session on first use (host ceilings), then draw the slice.
/// Duplicate ids within a swarm reject; closed swarms reject; the
/// draw must fit both the session pool and the host-global totals
/// across every session.
pub fn register_agent(
    sessions: &mut HashMap<String, SwarmSession>,
    swarm_id: &str,
    agent_id: &str,
    role: &str,
    priority: u32,
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
                SwarmSession::new(swarm_id.to_string(), host_cores, host_mem_mb),
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
    };
    session.members.insert(agent_id.to_string(), agent.clone());
    session.capacity_pool.alloc_agent();
    Ok(SwarmLease::grant(session, &agent))
}

/// Release one agent's slice back to the pool. Unknown swarms and
/// ids fail closed (`-32602`, mirroring reservation release).
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
    let agent = session.members.remove(agent_id).ok_or_else(|| {
        SwarmError::Invalid(format!(
            "agent '{agent_id}' is not registered in swarm '{swarm_id}'"
        ))
    })?;
    session.capacity_pool.dealloc_agent();
    // The lease reports the pool after release (the agent record is
    // the removed one).
    Ok(SwarmLease::grant(session, &agent))
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
}
