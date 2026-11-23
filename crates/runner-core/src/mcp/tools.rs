//! MCP tool definitions + executors for the AI-agent admin tier.
//!
//! Seven tools per the Phase 2 contract (`get_ci_status`,
//! `get_fleet_topology`, `reserve_host_resources`,
//! `release_host_resources`, `throttle_runner`, `request_cloud_capacity`,
//! `drain_node`) plus three Phase 8 agent-native tools (`diagnose_system`,
//! `test_provider`, `exec_command`), Phase 10 `manage_cloud_capacity`,
//! and v0.5.0 `get_cache_stats`, dispatched through [`AgentTools`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::reservation::{ReservationRequest, ReserveError};
use crate::config::RunnerConfig;
use crate::governor::cgroup::{WEIGHT_TRICKLE, WEIGHT_WARNING};
use crate::governor::supervisor::SharedState;
use crate::mesh::cloud::CloudPool;

pub const TOOL_GET_CI_STATUS: &str = "get_ci_status";
pub const TOOL_GET_FLEET_TOPOLOGY: &str = "get_fleet_topology";
pub const TOOL_RESERVE_HOST_RESOURCES: &str = "reserve_host_resources";
pub const TOOL_RELEASE_HOST_RESOURCES: &str = "release_host_resources";
pub const TOOL_THROTTLE_RUNNER: &str = "throttle_runner";
pub const TOOL_REQUEST_CLOUD_CAPACITY: &str = "request_cloud_capacity";
pub const TOOL_DRAIN_NODE: &str = "drain_node";
pub const TOOL_DIAGNOSE_SYSTEM: &str = "diagnose_system";
pub const TOOL_TEST_PROVIDER: &str = "test_provider";
pub const TOOL_EXEC_COMMAND: &str = "exec_command";
pub const TOOL_MANAGE_CLOUD_CAPACITY: &str = "manage_cloud_capacity";
pub const TOOL_GET_CACHE_STATS: &str = "get_cache_stats";
pub const TOOL_REGISTER_SWARM_AGENT: &str = "register_swarm_agent";
pub const TOOL_LEAVE_SWARM: &str = "leave_swarm";

/// All tool names, in contract order.
pub const ALL_TOOLS: [&str; 14] = [
    TOOL_GET_CI_STATUS,
    TOOL_GET_FLEET_TOPOLOGY,
    TOOL_RESERVE_HOST_RESOURCES,
    TOOL_RELEASE_HOST_RESOURCES,
    TOOL_THROTTLE_RUNNER,
    TOOL_REQUEST_CLOUD_CAPACITY,
    TOOL_DRAIN_NODE,
    TOOL_DIAGNOSE_SYSTEM,
    TOOL_TEST_PROVIDER,
    TOOL_EXEC_COMMAND,
    TOOL_MANAGE_CLOUD_CAPACITY,
    TOOL_GET_CACHE_STATS,
    TOOL_REGISTER_SWARM_AGENT,
    TOOL_LEAVE_SWARM,
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReserveHostResourcesArgs {
    pub cores: f64,
    /// Legacy memory unit (v1); `memory_mb` wins when present.
    #[serde(default)]
    pub ram_gb: f64,
    /// Legacy duration unit (v1); `duration_secs` wins when present.
    #[serde(default)]
    pub duration_minutes: u64,
    #[serde(default)]
    pub reason: String,
    /// Canonical memory unit, MiB (v2; precedence over `ram_gb`).
    #[serde(default)]
    pub memory_mb: Option<u64>,
    /// Canonical duration unit, seconds (v2; precedence over
    /// `duration_minutes`).
    #[serde(default)]
    pub duration_secs: Option<u64>,
    /// Preemption rank (v2; default Normal).
    #[serde(default)]
    pub priority: Option<crate::governor::supervisor::ReservationPriority>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleaseHostResourcesArgs {
    pub reservation_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThrottleRunnerArgs {
    /// `"warning"` (weight 25) or `"critical"` (weight 1).
    pub level: String,
    pub duration_minutes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestCloudCapacityArgs {
    /// `"digitalocean"` or `"render"`.
    pub provider: String,
    pub max_instances: u32,
    pub duration_hours: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DrainNodeArgs {
    pub node_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DiagnoseSystemArgs {
    #[serde(default)]
    pub egress: Option<bool>,
    #[serde(default)]
    pub enterprise: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestProviderArgs {
    pub provider: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecCommandArgs {
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    /// Execution tier: `process` (default) or `container`.
    #[serde(default)]
    pub driver: Option<String>,
    /// Container image (container tier; falls back to the
    /// configured default image, fail closed when neither).
    #[serde(default)]
    pub image: Option<String>,
    /// Container tier: loopback-only networking.
    #[serde(default)]
    pub no_network: Option<bool>,
    /// Container bind mounts (`host:container[:ro]`).
    #[serde(default)]
    pub volumes: Option<Vec<String>>,
}

/// Normalized exec request: validated driver plus container options.
/// Raw volume specs parse at execution (the OCI parser lives in
/// `runner-sandbox`, which this crate cannot depend on).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: Vec<String>,
    pub timeout_secs: u64,
    pub env: Vec<(String, String)>,
    /// Validated: `process` or `container`.
    pub driver: String,
    pub image: Option<String>,
    pub no_network: bool,
    pub volumes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManageCloudCapacityArgs {
    /// `"list"`, `"terminate"`, or `"purge"`.
    pub action: String,
    #[serde(default)]
    pub instance_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterSwarmAgentArgs {
    pub swarm_id: String,
    pub agent_id: String,
    pub role: String,
    /// Intra-swarm rank (default 0; higher preempts lower).
    #[serde(default)]
    pub priority: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaveSwarmArgs {
    pub swarm_id: String,
    pub agent_id: String,
}

/// Agent-native capabilities, implemented outside `runner-core`.
///
/// The provider, sandbox, and CLI crates all depend on this one, so
/// core cannot call their doctor/provider/exec implementations
/// directly. The production impl lives in `runner-cli` (`agent.rs`)
/// and delegates to those existing modules; [`ToolContext::new`]
/// installs [`StubAgentTools`] until the host wires the real one via
/// [`ToolContext::with_agent`].
#[async_trait::async_trait]
pub trait AgentTools: Send + Sync + std::fmt::Debug {
    /// Run system diagnostics; mirrors `runner doctor` output as JSON.
    async fn diagnose(
        &self,
        egress: bool,
        enterprise: bool,
    ) -> Result<serde_json::Value, ToolError>;
    /// Check one provider's credentials and connectivity (`provider`
    /// is pre-validated to a known name). Never exposes secrets.
    async fn test_provider(&self, provider: &str) -> Result<serde_json::Value, ToolError>;
    /// Run a command under cgroup governance with captured output.
    /// The request arrives normalized: non-empty `command`,
    /// `timeout_secs >= 1`, validated `process|container` driver.
    /// Container-only fields are rejected for other drivers at
    /// dispatch; malformed volume specs fail at execution.
    async fn exec(&self, request: ExecRequest) -> Result<serde_json::Value, ToolError>;
    /// Manage daemon cloud workers (`action` pre-validated; `terminate`
    /// always carries an id). Goes through daemon IPC: the MCP server's
    /// local state never tracks cloud nodes.
    async fn manage_cloud(
        &self,
        action: &str,
        instance_id: Option<&str>,
    ) -> Result<serde_json::Value, ToolError>;
    /// Report LAN cache counters. Goes through daemon IPC: the cache
    /// store lives in the daemon, not the MCP server process.
    async fn cache_stats(&self) -> Result<serde_json::Value, ToolError>;
    /// Reserve headroom on the live daemon (the envelope arrives
    /// normalized; semantic checks run daemon-side).
    /// Returns [`ToolError::offline`] when the daemon is unreachable.
    async fn reserve(&self, request: ReservationRequest) -> Result<serde_json::Value, ToolError>;
    /// Release a daemon reservation by id.
    async fn release(&self, reservation_id: &str) -> Result<serde_json::Value, ToolError>;
    /// Engage a timed daemon throttle (`level` pre-validated to the
    /// frozen MCP enum by the dispatcher).
    async fn throttle(
        &self,
        level: &str,
        duration_minutes: u64,
    ) -> Result<serde_json::Value, ToolError>;
    /// Drain a node on the live daemon.
    async fn drain(&self, node_id: &str, reason: &str) -> Result<serde_json::Value, ToolError>;
    /// Request cloud burst from the live daemon (inputs pre-validated).
    async fn request_cloud(
        &self,
        provider: &str,
        max_instances: u32,
        duration_hours: f64,
        reason: &str,
    ) -> Result<serde_json::Value, ToolError>;
    /// Live daemon CI status (same shape as the local report).
    async fn ci_status(&self) -> Result<serde_json::Value, ToolError>;
    /// Live daemon fleet topology (same shape as the local report).
    async fn fleet_topology(&self) -> Result<serde_json::Value, ToolError>;
}

/// Placeholder impl used until the host wires the real agent tools.
#[derive(Debug, Default)]
pub struct StubAgentTools;

#[async_trait::async_trait]
impl AgentTools for StubAgentTools {
    async fn diagnose(
        &self,
        _egress: bool,
        _enterprise: bool,
    ) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::internal("agent tools not configured"))
    }

    async fn test_provider(&self, _provider: &str) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::internal("agent tools not configured"))
    }

    async fn exec(&self, _request: ExecRequest) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::internal("agent tools not configured"))
    }

    async fn manage_cloud(
        &self,
        _action: &str,
        _instance_id: Option<&str>,
    ) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::internal("agent tools not configured"))
    }

    async fn cache_stats(&self) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::internal("agent tools not configured"))
    }

    // Daemon-backed tools: the stub always reports offline so the
    // dispatcher deterministically uses local state (hermetic tests).
    async fn reserve(&self, _request: ReservationRequest) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }

    async fn release(&self, _reservation_id: &str) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }

    async fn throttle(
        &self,
        _level: &str,
        _duration_minutes: u64,
    ) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }

    async fn drain(&self, _node_id: &str, _reason: &str) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }

    async fn request_cloud(
        &self,
        _provider: &str,
        _max_instances: u32,
        _duration_hours: f64,
        _reason: &str,
    ) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }

    async fn ci_status(&self) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }

    async fn fleet_topology(&self) -> Result<serde_json::Value, ToolError> {
        Err(ToolError::offline("agent tools not configured"))
    }
}

/// Execution context: shared daemon state + Super Admin policy + cloud.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub state: SharedState,
    pub config: RunnerConfig,
    pub cloud: CloudPool,
    pub agent: Arc<dyn AgentTools>,
}

impl ToolContext {
    pub fn new(state: SharedState, config: RunnerConfig) -> Self {
        let cloud = CloudPool::from_config(&config);
        Self {
            state,
            config,
            cloud,
            agent: Arc::new(StubAgentTools),
        }
    }

    /// Attach the production agent-tools implementation.
    pub fn with_agent(mut self, agent: Arc<dyn AgentTools>) -> Self {
        self.agent = agent;
        self
    }
}

/// Tool failure: JSON-RPC error code + message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    pub code: i64,
    pub message: String,
}

impl ToolError {
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: -32603,
            message: message.into(),
        }
    }

    /// Daemon unreachable over IPC. Internal control flow only:
    /// [`execute_tool`] converts it into a local-state attempt, so it
    /// never surfaces to MCP clients.
    pub fn offline(message: impl Into<String>) -> Self {
        Self {
            code: -32000,
            message: message.into(),
        }
    }

    pub fn is_offline(&self) -> bool {
        self.code == -32000
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}

impl std::error::Error for ToolError {}

fn parse_args<T: for<'de> Deserialize<'de>>(
    args: Option<&serde_json::Value>,
) -> Result<T, ToolError> {
    let args = args.cloned().unwrap_or(serde_json::Value::Null);
    serde_json::from_value(args).map_err(|e| ToolError::invalid_params(e.to_string()))
}

/// Shared state operations used by BOTH the local MCP path and the
/// daemon IPC arms (`reserve`, `release`, `drain`, `cloud_capacity`,
/// `ci_status`, `fleet_topology`), so verdicts, messages, and shapes
/// stay identical whichever path executes. Normalization and
/// validation live in the reservation envelope; [`ReserveError`]
/// variants are caller-mapped (`Invalid` → `invalid_params` locally /
/// `-32602` over IPC, `Full` → internal / `-32603`).
/// Granted reservation plus the ids it preempted (empty when the
/// table had room).
pub(crate) struct ReserveOutcome {
    pub reservation: crate::governor::supervisor::Reservation,
    pub preempted: Vec<String>,
}

pub(crate) async fn reserve_on(
    state: &SharedState,
    request: &ReservationRequest,
) -> Result<ReserveOutcome, ReserveError> {
    let now = Instant::now();
    let mut guard = state.write().await;
    guard.prune_expired(now);
    // Configured ceilings (daemon-seeded; owned clone so the later
    // mutable borrows below don't conflict).
    let limits = guard.reservation_limits().clone();
    if let Err(e) = request.validate(&limits, guard.reservation_count()) {
        match e {
            // Malformed or over-limit requests never evict anyone.
            invalid @ ReserveError::Invalid(_) => return Err(invalid),
            ReserveError::Full { .. } => {
                let preempted =
                    guard.preempt_for(request.cores, request.memory_mb, request.priority);
                if preempted.is_empty() {
                    return Err(ReserveError::Full {
                        active: guard.reservation_count(),
                        max: limits.max_active,
                    });
                }
                // Recount after eviction (a zero cap still denies).
                request.validate(&limits, guard.reservation_count())?;
                return grant_with_hooks(&mut guard, request, preempted, now);
            }
            // validate() never emits Budget (budget gates below).
            budget @ ReserveError::Budget(_) => return Err(budget),
        }
    }
    grant_with_hooks(&mut guard, request, Vec::new(), now)
}

/// Budget-gate, grant, and account one validated request. Everything
/// runs under the caller's write lock, so the budget check, the
/// grant, and the ledger write are atomic: no TOCTOU overshoot
/// between concurrent reserves. Hook failures roll the grant back.
fn grant_with_hooks(
    guard: &mut crate::governor::supervisor::SupervisorState,
    request: &ReservationRequest,
    preempted: Vec<String>,
    now: Instant,
) -> Result<ReserveOutcome, ReserveError> {
    let hooks = guard.reservation_hooks();
    if let Some(hooks) = &hooks {
        if let Err(message) = hooks.check_budget(request) {
            return Err(ReserveError::Budget(message));
        }
    }
    let reservation = guard.reserve(
        request.cores,
        request.memory_mb,
        request.duration(),
        request.reason.clone(),
        request.priority,
        now,
    );
    if let Some(hooks) = &hooks {
        if !preempted.is_empty() {
            if let Err(e) = hooks.on_preempt(&preempted, request) {
                guard.release(&reservation.id);
                return Err(ReserveError::Budget(format!(
                    "preemption accounting failed, grant rolled back: {e}"
                )));
            }
        }
        if let Err(e) = hooks.on_grant(&reservation, request) {
            guard.release(&reservation.id);
            eprintln!(
                "runner: reservation grant rolled back for {}: {e}",
                reservation.id
            );
            return Err(ReserveError::Budget(format!(
                "grant accounting failed, rolled back: {e}"
            )));
        }
    }
    Ok(ReserveOutcome {
        reservation,
        preempted,
    })
}

pub(crate) async fn release_on(state: &SharedState, id: &str) -> bool {
    let mut guard = state.write().await;
    let Some(reservation) = guard.take_reservation(id) else {
        return false;
    };
    // Best-effort accounting: the release stands (capacity freed) —
    // cleanup must not strand leases over a bookkeeping hiccup.
    if let Some(hooks) = guard.reservation_hooks() {
        if let Err(e) = hooks.on_release(&reservation) {
            eprintln!(
                "runner: reservation release accounting failed for {}: {e} (release stands)",
                reservation.id
            );
        }
    }
    true
}

pub(crate) async fn drain_on(state: &SharedState, node_id: String, reason: String) {
    state.write().await.drain_node(node_id, reason);
}

pub(crate) fn validate_cloud_request(
    provider: &str,
    max_instances: u32,
    duration_hours: f64,
) -> Result<(), String> {
    if provider != "digitalocean" && provider != "render" {
        return Err(format!(
            "provider must be \"digitalocean\" or \"render\", got {provider:?}"
        ));
    }
    if max_instances == 0 {
        return Err("max_instances must be > 0".to_string());
    }
    if !duration_hours.is_finite() || duration_hours <= 0.0 {
        return Err("duration_hours must be a finite value > 0".to_string());
    }
    Ok(())
}

/// Shared provision flow over an explicit pool + spend cap. The local
/// path passes `ctx.cloud` + the config ceiling; the daemon arm passes
/// the state's pool + ledgered cap. `Err` is provision failure only
/// (callers map it to internal errors); denials are `Ok` values.
pub(crate) async fn request_cloud_with(
    pool: &CloudPool,
    cap_usd: f64,
    state: &SharedState,
    provider: &str,
    max_instances: u32,
    duration_hours: f64,
) -> Result<serde_json::Value, String> {
    // Dual-tier governance: agents can never exceed the Super Admin ceiling.
    // A zero ceiling means no cloud spend is pre-approved.
    if cap_usd <= 0.0 {
        return Ok(serde_json::json!({
            "approved": false,
            "reason": "no cloud spend pre-approved: Super Admin must set cloud.max_monthly_spend > 0",
        }));
    }
    if !pool.has_provider(provider) {
        return Ok(serde_json::json!({
            "approved": false,
            "reason": format!(
                "provider {provider:?} has no token in config.toml; Super Admin must approve credentials"
            ),
        }));
    }
    // Ledger gate: month-to-date spend is read from the shared spend
    // file on every call (no cached totals anywhere), so both the
    // daemon arm and the offline MCP fallback enforce the same cap
    // and neither can provision off-ledger. Unreadable ledgers deny
    // rather than spending blind.
    match pool.month_spend() {
        Ok(spend) if spend < cap_usd => {}
        Ok(spend) => {
            return Ok(serde_json::json!({
                "approved": false,
                "reason": format!(
                    "monthly cloud spend ${spend:.2} has reached the ${cap_usd:.2} cap; \
                     Super Admin must raise cloud.max_monthly_spend",
                ),
            }));
        }
        Err(e) => {
            return Ok(serde_json::json!({
                "approved": false,
                "reason": format!(
                    "cannot verify cloud spend against the ledger ({e}); refusing to provision blind"
                ),
            }));
        }
    }
    // Provision live within budget, one instance per call. The
    // caller repeats the call (bounded by max_instances) as the backlog
    // persists; each node self-terminates after 5 idle minutes.
    let name = format!("runner-ci-{}", now_millis());
    let node = pool
        .provision(provider, &name)
        .await
        .map_err(|e| e.to_string())?;
    state.write().await.add_cloud_node(node.clone());
    Ok(serde_json::json!({
        "approved": true,
        "provider": provider,
        "node_id": node.id,
        "node_status": node.status,
        "max_instances": max_instances,
        "duration_hours": duration_hours,
        "budget_cap_usd": cap_usd,
    }))
}

pub(crate) async fn ci_status_value(state: &SharedState) -> serde_json::Value {
    let report = crate::status::status_report();
    let guard = state.read().await;
    serde_json::json!({
        "status": report.status,
        "version": report.version,
        "host": report.host,
        "concurrency": report.concurrency,
        "governor": {
            "last_weight": guard.last_weight,
            "last_slots": guard.last_slots,
            "afk_boost": guard.afk.boosted(),
            "afk_mode": guard.afk_mode.name(),
        },
        "reservations": guard.reservations().iter().map(|r| serde_json::json!({
            "id": r.id, "cores": r.cores, "ram_mb": r.ram_mb,
            "priority": r.priority, "reason": r.reason,
        })).collect::<Vec<_>>(),
        "drained_nodes": guard.drained_nodes(),
        "forges": guard.forge_health(),
    })
}

pub(crate) async fn fleet_topology_value(state: &SharedState) -> serde_json::Value {
    let report = crate::status::status_report();
    let guard = state.read().await;
    serde_json::json!({
        "local": {
            "total_cores": report.host.total_cores,
            "physical_cores": report.host.physical_cores,
            "available_memory_bytes": report.host.available_memory_bytes,
            "max_slots": report.concurrency.max_slots,
            "cpu_level": report.host.psi_pressure.cpu_level,
        },
        "wan_peers": guard.peers(),
        "cloud_nodes": guard.cloud_nodes(),
        "drained_nodes": guard.drained_nodes(),
    })
}

/// Run an agent call, falling back to the local-state attempt when the
/// agent reports the daemon offline. The local future is lazy: it is
/// constructed here but polled only on the fallback path.
async fn with_daemon_fallback(
    tool: &str,
    agent_result: Result<serde_json::Value, ToolError>,
    local: impl std::future::Future<Output = Result<serde_json::Value, ToolError>>,
) -> Result<serde_json::Value, ToolError> {
    match agent_result {
        Ok(value) => Ok(value),
        Err(e) if e.is_offline() => {
            // stderr is a safe side-channel (stdio carries JSON-RPC).
            eprintln!("runner: mcp {tool}: daemon unreachable, using local state");
            local.await
        }
        Err(e) => Err(e),
    }
}

/// Dispatch one `tools/call` by name. Returns the JSON value rendered into
/// the text content block.
pub async fn execute_tool(
    name: &str,
    args: Option<&serde_json::Value>,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    match name {
        TOOL_GET_CI_STATUS => {
            with_daemon_fallback(
                TOOL_GET_CI_STATUS,
                ctx.agent.ci_status().await,
                get_ci_status(ctx),
            )
            .await
        }
        TOOL_GET_CACHE_STATS => ctx.agent.cache_stats().await,
        TOOL_GET_FLEET_TOPOLOGY => {
            with_daemon_fallback(
                TOOL_GET_FLEET_TOPOLOGY,
                ctx.agent.fleet_topology().await,
                get_fleet_topology(ctx),
            )
            .await
        }
        TOOL_RESERVE_HOST_RESOURCES => {
            let args: ReserveHostResourcesArgs = parse_args(args)?;
            let request = ReservationRequest::try_from(&args).map_err(ToolError::invalid_params)?;
            with_daemon_fallback(
                TOOL_RESERVE_HOST_RESOURCES,
                ctx.agent.reserve(request.clone()).await,
                reserve_host_resources(&request, ctx),
            )
            .await
        }
        TOOL_RELEASE_HOST_RESOURCES => {
            let args: ReleaseHostResourcesArgs = parse_args(args)?;
            with_daemon_fallback(
                TOOL_RELEASE_HOST_RESOURCES,
                ctx.agent.release(&args.reservation_id).await,
                release_host_resources(&args, ctx),
            )
            .await
        }
        TOOL_THROTTLE_RUNNER => {
            let args: ThrottleRunnerArgs = parse_args(args)?;
            // Frozen MCP contract: only warning|critical (the CLI/IPC
            // surface additionally accepts `high`; see `throttle_set`).
            if args.level != "warning" && args.level != "critical" {
                return Err(ToolError::invalid_params(format!(
                    "level must be \"warning\" or \"critical\", got {:?}",
                    args.level
                )));
            }
            with_daemon_fallback(
                TOOL_THROTTLE_RUNNER,
                ctx.agent.throttle(&args.level, args.duration_minutes).await,
                throttle_runner(&args, ctx),
            )
            .await
        }
        TOOL_REQUEST_CLOUD_CAPACITY => {
            let args: RequestCloudCapacityArgs = parse_args(args)?;
            with_daemon_fallback(
                TOOL_REQUEST_CLOUD_CAPACITY,
                ctx.agent
                    .request_cloud(
                        &args.provider,
                        args.max_instances,
                        args.duration_hours,
                        &args.reason,
                    )
                    .await,
                request_cloud_capacity(&args, ctx),
            )
            .await
        }
        TOOL_DRAIN_NODE => {
            let args: DrainNodeArgs = parse_args(args)?;
            with_daemon_fallback(
                TOOL_DRAIN_NODE,
                ctx.agent.drain(&args.node_id, &args.reason).await,
                drain_node(&args, ctx),
            )
            .await
        }
        TOOL_DIAGNOSE_SYSTEM => {
            // All flags optional: omitted arguments mean all-defaults.
            let args: DiagnoseSystemArgs = match args {
                None => DiagnoseSystemArgs::default(),
                Some(_) => parse_args(args)?,
            };
            let mut out = ctx
                .agent
                .diagnose(
                    args.egress.unwrap_or(false),
                    args.enterprise.unwrap_or(false),
                )
                .await?;
            // Merge forge health here: agent impls hold no daemon state.
            if let Some(map) = out.as_object_mut() {
                map.insert(
                    "forges".to_string(),
                    serde_json::to_value(ctx.state.read().await.forge_health())
                        .unwrap_or(serde_json::Value::Null),
                );
            }
            Ok(out)
        }
        TOOL_TEST_PROVIDER => {
            let args: TestProviderArgs = parse_args(args)?;
            let name = args.provider.trim().to_ascii_lowercase();
            match name.as_str() {
                "github" | "gitlab" | "bitbucket" | "local" => ctx.agent.test_provider(&name).await,
                other => Err(ToolError::invalid_params(format!(
                    "unknown provider: '{other}' (want github|gitlab|bitbucket|local)"
                ))),
            }
        }
        TOOL_EXEC_COMMAND => {
            let args: ExecCommandArgs = parse_args(args)?;
            if args.command.is_empty() || args.command.iter().any(|c| c.trim().is_empty()) {
                return Err(ToolError::invalid_params("command must not be empty"));
            }
            let timeout_secs = args.timeout_secs.unwrap_or(60);
            if timeout_secs == 0 {
                return Err(ToolError::invalid_params("timeout_secs must be >= 1"));
            }
            let driver = args
                .driver
                .as_deref()
                .map(str::trim)
                .filter(|driver| !driver.is_empty())
                .map(str::to_ascii_lowercase)
                .unwrap_or_else(|| "process".to_string());
            if driver != "process" && driver != "container" {
                return Err(ToolError::invalid_params(format!(
                    "unknown driver: '{driver}' (want process|container)"
                )));
            }
            let volumes = args.volumes.unwrap_or_default();
            if volumes.iter().any(|spec| spec.trim().is_empty()) {
                return Err(ToolError::invalid_params("volumes must not be empty"));
            }
            // Container-only fields with another driver fail closed
            // (never silently ignored).
            let has_extras = args
                .image
                .as_ref()
                .is_some_and(|image| !image.trim().is_empty())
                || !volumes.is_empty()
                || args.no_network == Some(true);
            if driver != "container" && has_extras {
                return Err(ToolError::invalid_params(
                    "image/no_network/volumes require driver \"container\"",
                ));
            }
            let env: Vec<(String, String)> = args.env.unwrap_or_default().into_iter().collect();
            ctx.agent
                .exec(ExecRequest {
                    command: args.command,
                    timeout_secs,
                    env,
                    driver,
                    image: args.image,
                    no_network: args.no_network.unwrap_or(false),
                    volumes,
                })
                .await
        }
        TOOL_MANAGE_CLOUD_CAPACITY => {
            let args: ManageCloudCapacityArgs = parse_args(args)?;
            let action = args.action.trim().to_ascii_lowercase();
            match action.as_str() {
                "list" | "purge" => ctx.agent.manage_cloud(&action, None).await,
                "terminate" => match args.instance_id.as_deref().map(str::trim) {
                    Some(id) if !id.is_empty() => ctx.agent.manage_cloud(&action, Some(id)).await,
                    _ => Err(ToolError::invalid_params(
                        "terminate requires a non-empty instance_id",
                    )),
                },
                other => Err(ToolError::invalid_params(format!(
                    "unknown action: '{other}' (want list|terminate|purge)"
                ))),
            }
        }
        TOOL_REGISTER_SWARM_AGENT => {
            let args: RegisterSwarmAgentArgs = parse_args(args)?;
            // Local state only: no daemon swarm arm exists yet (Phase
            // 1 protocol; daemon convergence lands with dispatch).
            register_swarm_agent(&args, ctx).await
        }
        TOOL_LEAVE_SWARM => {
            let args: LeaveSwarmArgs = parse_args(args)?;
            leave_swarm(&args, ctx).await
        }
        _ => Err(ToolError {
            code: -32601,
            message: format!("unknown tool: {name}"),
        }),
    }
}

async fn get_ci_status(ctx: &ToolContext) -> Result<serde_json::Value, ToolError> {
    Ok(ci_status_value(&ctx.state).await)
}

async fn get_fleet_topology(ctx: &ToolContext) -> Result<serde_json::Value, ToolError> {
    Ok(fleet_topology_value(&ctx.state).await)
}

async fn reserve_host_resources(
    request: &ReservationRequest,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    let outcome = reserve_on(&ctx.state, request).await.map_err(|e| match e {
        ReserveError::Invalid(message) => ToolError::invalid_params(message),
        full @ (ReserveError::Full { .. } | ReserveError::Budget(_)) => {
            ToolError::internal(full.to_string())
        }
    })?;
    Ok(serde_json::json!({
        "reservation_id": outcome.reservation.id,
        "cores": outcome.reservation.cores,
        "ram_mb": outcome.reservation.ram_mb,
        "priority": outcome.reservation.priority,
        "duration_secs": request.duration_secs,
        "preempted": outcome.preempted,
        "reason": outcome.reservation.reason,
    }))
}

async fn release_host_resources(
    args: &ReleaseHostResourcesArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    if release_on(&ctx.state, &args.reservation_id).await {
        Ok(serde_json::json!({ "released": args.reservation_id }))
    } else {
        Err(ToolError::invalid_params(format!(
            "unknown reservation_id: {}",
            args.reservation_id
        )))
    }
}

fn swarm_error(e: super::swarm::SwarmError) -> ToolError {
    use super::swarm::SwarmError;
    match e {
        SwarmError::Invalid(message) | SwarmError::BudgetExceeded(message) => {
            ToolError::invalid_params(message)
        }
        full @ (SwarmError::Full(_) | SwarmError::Internal(_)) => {
            ToolError::internal(full.to_string())
        }
    }
}

async fn register_swarm_agent(
    args: &RegisterSwarmAgentArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    let mut guard = ctx.state.write().await;
    let policy = super::swarm::BudgetPolicy {
        cap_usd: guard.swarm_spend_cap_usd(),
        rate_usd_per_core_hour: guard.swarm_rate_usd(),
    };
    let lease = super::swarm::register_agent_with_budget(
        guard.swarms_mut(),
        &args.swarm_id,
        &args.agent_id,
        &args.role,
        args.priority.unwrap_or(0),
        policy,
        Instant::now(),
    )
    .map_err(swarm_error)?;
    serde_json::to_value(&lease).map_err(|e| ToolError::internal(e.to_string()))
}

async fn leave_swarm(
    args: &LeaveSwarmArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    let mut guard = ctx.state.write().await;
    let lease = super::swarm::leave_swarm(
        guard.swarms_mut(),
        &args.swarm_id,
        &args.agent_id,
        Instant::now(),
    )
    .map_err(swarm_error)?;
    let mut value = serde_json::to_value(&lease).map_err(|e| ToolError::internal(e.to_string()))?;
    // The lease shape reports the pool after release; mark the
    // mutation explicitly for agent parsing.
    if let Some(map) = value.as_object_mut() {
        map.insert("left".to_string(), serde_json::Value::from(true));
    }
    Ok(value)
}

async fn throttle_runner(
    args: &ThrottleRunnerArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    let weight = match args.level.as_str() {
        "warning" => WEIGHT_WARNING,
        "critical" => WEIGHT_TRICKLE,
        other => {
            return Err(ToolError::invalid_params(format!(
                "level must be \"warning\" or \"critical\", got {other:?}"
            )));
        }
    };
    if args.duration_minutes == 0 {
        return Err(ToolError::invalid_params("duration_minutes must be > 0"));
    }
    let mut state = ctx.state.write().await;
    state.set_throttle(
        weight,
        Duration::from_secs(args.duration_minutes * 60),
        Instant::now(),
    );
    Ok(serde_json::json!({
        "level": args.level,
        "cpu_weight": weight,
        "duration_minutes": args.duration_minutes,
    }))
}

async fn request_cloud_capacity(
    args: &RequestCloudCapacityArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    validate_cloud_request(&args.provider, args.max_instances, args.duration_hours)
        .map_err(ToolError::invalid_params)?;
    request_cloud_with(
        &ctx.cloud,
        ctx.config.cloud.max_monthly_spend,
        &ctx.state,
        &args.provider,
        args.max_instances,
        args.duration_hours,
    )
    .await
    .map_err(ToolError::internal)
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

async fn drain_node(
    args: &DrainNodeArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    if args.node_id.trim().is_empty() {
        return Err(ToolError::invalid_params("node_id must not be empty"));
    }
    drain_on(&ctx.state, args.node_id.clone(), args.reason.clone()).await;
    Ok(serde_json::json!({ "drained": args.node_id }))
}

/// JSON Schema (`inputSchema`) for one tool, served by `tools/list`.
pub fn tool_schema(name: &str) -> serde_json::Value {
    let (props, required): (serde_json::Value, Vec<&str>) = match name {
        TOOL_RESERVE_HOST_RESOURCES => (
            serde_json::json!({
                "cores": { "type": "number" },
                "ram_gb": { "type": "number" },
                "duration_minutes": { "type": "integer" },
                "reason": { "type": "string" },
                "memory_mb": { "type": "integer" },
                "duration_secs": { "type": "integer" },
                "priority": { "type": "string",
                    "enum": ["low", "normal", "high", "critical"] },
            }),
            vec!["cores"],
        ),
        TOOL_RELEASE_HOST_RESOURCES => (
            serde_json::json!({ "reservation_id": { "type": "string" } }),
            vec!["reservation_id"],
        ),
        TOOL_THROTTLE_RUNNER => (
            serde_json::json!({
                "level": { "type": "string", "enum": ["warning", "critical"] },
                "duration_minutes": { "type": "integer" },
            }),
            vec!["level", "duration_minutes"],
        ),
        TOOL_REQUEST_CLOUD_CAPACITY => (
            serde_json::json!({
                "provider": { "type": "string", "enum": ["digitalocean", "render"] },
                "max_instances": { "type": "integer" },
                "duration_hours": { "type": "number" },
                "reason": { "type": "string" },
            }),
            vec!["provider", "max_instances", "duration_hours", "reason"],
        ),
        TOOL_DRAIN_NODE => (
            serde_json::json!({
                "node_id": { "type": "string" },
                "reason": { "type": "string" },
            }),
            vec!["node_id", "reason"],
        ),
        TOOL_DIAGNOSE_SYSTEM => (
            serde_json::json!({
                "egress": { "type": "boolean" },
                "enterprise": { "type": "boolean" },
            }),
            vec![],
        ),
        TOOL_TEST_PROVIDER => (
            serde_json::json!({
                "provider": {
                    "type": "string",
                    "enum": ["github", "gitlab", "bitbucket", "local"],
                },
            }),
            vec!["provider"],
        ),
        TOOL_EXEC_COMMAND => (
            serde_json::json!({
                "command": { "type": "array", "items": { "type": "string" } },
                "timeout_secs": { "type": "integer" },
                "env": { "type": "object" },
                "driver": { "type": "string", "enum": ["process", "container"] },
                "image": { "type": "string" },
                "no_network": { "type": "boolean" },
                "volumes": { "type": "array", "items": { "type": "string" } },
            }),
            vec!["command"],
        ),
        TOOL_MANAGE_CLOUD_CAPACITY => (
            serde_json::json!({
                "action": { "type": "string", "enum": ["list", "terminate", "purge"] },
                "instance_id": { "type": "string" },
            }),
            vec!["action"],
        ),
        TOOL_REGISTER_SWARM_AGENT => (
            serde_json::json!({
                "swarm_id": { "type": "string" },
                "agent_id": { "type": "string" },
                "role": { "type": "string" },
                "priority": { "type": "integer" },
            }),
            vec!["swarm_id", "agent_id", "role"],
        ),
        TOOL_LEAVE_SWARM => (
            serde_json::json!({
                "swarm_id": { "type": "string" },
                "agent_id": { "type": "string" },
            }),
            vec!["swarm_id", "agent_id"],
        ),
        _ => (serde_json::json!({}), vec![]),
    };
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

/// One-line description per tool for `tools/list`.
pub fn tool_description(name: &str) -> &'static str {
    match name {
        TOOL_GET_CI_STATUS => "Host health, PSI pressure, slots, queue counts, reservations.",
        TOOL_GET_FLEET_TOPOLOGY => "Compute split across local, WAN peers, and cloud nodes.",
        TOOL_RESERVE_HOST_RESOURCES => "Hold CPU/RAM headroom for local agent work. v2 fields (memory_mb, duration_secs, priority) take precedence over ram_gb/duration_minutes.",
        TOOL_RELEASE_HOST_RESOURCES => "Release a host resource reservation.",
        TOOL_THROTTLE_RUNNER => "Force runner weights down for a duration (never freezes).",
        TOOL_REQUEST_CLOUD_CAPACITY => "Request cloud burst within the pre-approved budget.",
        TOOL_DRAIN_NODE => "Stop dispatching new jobs to a node.",
        TOOL_DIAGNOSE_SYSTEM => "Host diagnostics: kernel, cgroups, KVM, eBPF, daemon, egress.",
        TOOL_TEST_PROVIDER => "Verify CI provider credentials and connectivity.",
        TOOL_EXEC_COMMAND => "Run a command under zero-freeze governance; capture output.",
        TOOL_MANAGE_CLOUD_CAPACITY => "List, terminate, or purge daemon cloud burst workers.",
        TOOL_GET_CACHE_STATS => "LAN cache entries, size, hits, misses, and bandwidth saved.",
        TOOL_REGISTER_SWARM_AGENT => "Join an agent swarm; draw a headroom slice under a lease.",
        TOOL_LEAVE_SWARM => "Leave an agent swarm; return the headroom slice.",
        _ => "Unknown tool.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::supervisor::new_shared_state;

    fn ctx() -> ToolContext {
        ToolContext::new(new_shared_state(), RunnerConfig::default())
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    // Month-to-date spend at the cap denies before any provisioning
    // (no provider traffic: hermetic). The seed terminates in the
    // future so it stays in-month with fixed cost whatever the wall
    // clock says — no month-boundary flake.
    #[tokio::test]
    async fn cloud_spend_gate_denies_exhausted_ledger() {
        use crate::mesh::cloud::digitalocean::DoClient;
        use crate::mesh::cloud::ledger::{LedgerEntry, SpendLedger, RATE_DIGITALOCEAN_PER_HOUR};

        let dir = crate::test_support::TempDir::new("spend-gate").unwrap();
        let ledger = SpendLedger::new(dir.path().join("ledger.json"));
        let now = now_secs();
        ledger
            .store(&[LedgerEntry {
                node_id: "i-1".to_string(),
                provider: "digitalocean".to_string(),
                launched_at: now,
                terminated_at: Some(now + 7200),
            }])
            .unwrap();
        let pool =
            CloudPool::from_clients(Some(DoClient::new("fake").unwrap()), None).with_ledger(ledger);
        let out = request_cloud_with(
            &pool,
            RATE_DIGITALOCEAN_PER_HOUR,
            &new_shared_state(),
            "digitalocean",
            1,
            1.0,
        )
        .await
        .unwrap();
        assert_eq!(out["approved"], false);
        assert!(
            out["reason"].as_str().unwrap().contains("has reached the"),
            "wrong denial arm: {out}"
        );
    }

    // An unreadable ledger denies rather than spending blind (also
    // provision-free: hermetic).
    #[tokio::test]
    async fn cloud_spend_gate_denies_unreadable_ledger() {
        use crate::mesh::cloud::digitalocean::DoClient;
        use crate::mesh::cloud::ledger::SpendLedger;

        let dir = crate::test_support::TempDir::new("spend-gate-corrupt").unwrap();
        let path = dir.path().join("ledger.json");
        std::fs::write(&path, "{not json").unwrap();
        let pool = CloudPool::from_clients(Some(DoClient::new("fake").unwrap()), None)
            .with_ledger(SpendLedger::new(path));
        let out = request_cloud_with(&pool, 25.0, &new_shared_state(), "digitalocean", 1, 1.0)
            .await
            .unwrap();
        assert_eq!(out["approved"], false);
        assert!(
            out["reason"]
                .as_str()
                .unwrap()
                .contains("refusing to provision blind"),
            "wrong denial arm: {out}"
        );
    }

    #[tokio::test]
    async fn reserve_release_roundtrip() {
        let ctx = ctx();
        let args = serde_json::json!({
            "cores": 2.0, "ram_gb": 4.0, "duration_minutes": 10, "reason": "t"
        });
        let out = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
            .await
            .unwrap();
        let id = out["reservation_id"].as_str().unwrap().to_string();
        let rel = serde_json::json!({ "reservation_id": id });
        let out = execute_tool(TOOL_RELEASE_HOST_RESOURCES, Some(&rel), &ctx)
            .await
            .unwrap();
        assert_eq!(out["released"], id);
    }

    #[tokio::test]
    async fn reserve_v2_envelope_roundtrip() {
        let ctx = ctx();
        let args = serde_json::json!({
            "cores": 1.5, "memory_mb": 2048, "duration_secs": 90,
            "priority": "high", "reason": "v2",
        });
        let out = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(out["cores"], 1.5);
        assert_eq!(out["ram_mb"], 2048);
        assert_eq!(out["priority"], "high");
        assert_eq!(out["duration_secs"], 90);
        let id = out["reservation_id"].as_str().unwrap().to_string();
        let rel = serde_json::json!({ "reservation_id": id });
        let out = execute_tool(TOOL_RELEASE_HOST_RESOURCES, Some(&rel), &ctx)
            .await
            .unwrap();
        assert_eq!(out["released"], id);
    }

    #[tokio::test]
    async fn reserve_daemon_arm_receives_normalized_envelope() {
        let (ctx, agent) = agent_ctx();
        // Mixed generations: v2 wins, legacy ignored.
        let args = serde_json::json!({
            "cores": 2.0, "ram_gb": 4.0, "duration_minutes": 10,
            "memory_mb": 8192, "duration_secs": 30, "priority": "critical",
        });
        execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
            .await
            .unwrap();
        let calls = agent.reserves.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].memory_mb, 8192);
        assert_eq!(calls[0].duration_secs, 30);
        assert_eq!(
            calls[0].priority,
            crate::governor::supervisor::ReservationPriority::Critical
        );
    }

    #[tokio::test]
    async fn reserve_invalid_shapes_reject_without_dispatch() {
        let (ctx, agent) = agent_ctx();
        for bad in [
            serde_json::json!({ "cores": 0.0, "ram_gb": 4.0, "duration_minutes": 10 }),
            serde_json::json!({ "cores": 2.0, "duration_minutes": 10 }),
            serde_json::json!({ "cores": 2.0, "ram_gb": 4.0 }),
            serde_json::json!({
                "cores": 2.0, "memory_mb": 1024,
                "duration_secs": 60, "priority": "urgent",
            }),
        ] {
            let err = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&bad), &ctx)
                .await
                .unwrap_err();
            assert_eq!(err.code, -32602, "{bad}");
        }
        // Rejected before delegation: the daemon arm never fires.
        assert!(agent.reserves.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reserve_configured_ceilings_reject_with_invalid() {
        let state = new_shared_state();
        let mut config = RunnerConfig::default();
        config.reservations.limits = Some(crate::config::ReservationLimitsConfig {
            max_cores: Some(1.0),
            ..crate::config::ReservationLimitsConfig::default()
        });
        state.write().await.seed_from_config(&config);
        let ctx = ToolContext::new(state, config);
        // Over the configured 1-core ceiling (but far under the
        // 1024-core default): rejected as an invalid request.
        let over = serde_json::json!({
            "cores": 2.0, "memory_mb": 64, "duration_secs": 60,
        });
        let err = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&over), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("exceeds max"), "{}", err.message);
        // Within the configured ceiling: granted.
        let ok = serde_json::json!({
            "cores": 1.0, "memory_mb": 64, "duration_secs": 60,
        });
        execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&ok), &ctx)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn swarm_register_leave_roundtrip_reports_pool() {
        use crate::mcp::swarm::{SWARM_AGENT_CORES, SWARM_AGENT_MEM_MB};
        let ctx = ctx();
        let args = serde_json::json!({
            "swarm_id": "alpha", "agent_id": "builder-1", "role": "builder",
        });
        // Priority defaults to 0 when omitted.
        let lease = execute_tool(TOOL_REGISTER_SWARM_AGENT, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(lease["swarm_id"], "alpha");
        assert_eq!(lease["agent_id"], "builder-1");
        assert_eq!(lease["role"], "builder");
        assert_eq!(lease["priority"], 0);
        assert_eq!(lease["lease_secs"], 1800);
        assert_eq!(lease["cpu_weight_allocated"], SWARM_AGENT_CORES);
        assert_eq!(lease["memory_allocated_mb"], SWARM_AGENT_MEM_MB);
        assert_eq!(lease["active_members"], 1);
        assert!(lease["cpu_weight_max"].as_f64().unwrap() > 0.0);
        // Duplicate registration rejects without double-draw.
        let err = execute_tool(TOOL_REGISTER_SWARM_AGENT, Some(&args), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(
            err.message.contains("already registered"),
            "{}",
            err.message
        );
        // Leave restores the slice and marks the mutation.
        let left = execute_tool(
            TOOL_LEAVE_SWARM,
            Some(&serde_json::json!({"swarm_id": "alpha", "agent_id": "builder-1"})),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(left["left"], true);
        assert_eq!(left["active_members"], 0);
        assert_eq!(left["cpu_weight_allocated"], 0.0);
        assert_eq!(left["memory_allocated_mb"], 0);
        // Leaving twice fails closed (mirrors reservation release).
        let err = execute_tool(
            TOOL_LEAVE_SWARM,
            Some(&serde_json::json!({"swarm_id": "alpha", "agent_id": "builder-1"})),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("not registered"), "{}", err.message);
    }

    #[tokio::test]
    async fn swarm_blank_fields_reject_without_dispatch() {
        let ctx = ctx();
        for args in [
            serde_json::json!({"swarm_id": "  ", "agent_id": "a", "role": "builder"}),
            serde_json::json!({"swarm_id": "s", "agent_id": "", "role": "builder"}),
            serde_json::json!({"swarm_id": "s", "agent_id": "a", "role": ""}),
        ] {
            let err = execute_tool(TOOL_REGISTER_SWARM_AGENT, Some(&args), &ctx)
                .await
                .unwrap_err();
            assert_eq!(err.code, -32602, "{args}");
        }
        let err = execute_tool(
            TOOL_LEAVE_SWARM,
            Some(&serde_json::json!({"swarm_id": "ghost", "agent_id": "a"})),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("unknown swarm_id"), "{}", err.message);
    }

    #[tokio::test]
    async fn swarm_concurrent_registrations_account_exactly() {
        use crate::mcp::swarm::{host_capacity, SWARM_AGENT_CORES, SWARM_AGENT_MEM_MB};
        // Sized to fit every CI host (floor of host capacity, at
        // least one): all must grant, with no lost draws.
        let (host_cores, host_mem) = host_capacity().unwrap();
        let count = ((host_cores / SWARM_AGENT_CORES).floor() as usize)
            .min((host_mem / SWARM_AGENT_MEM_MB) as usize)
            .clamp(1, 8);
        let ctx = ctx();
        let mut tasks = Vec::with_capacity(count);
        for i in 0..count {
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(async move {
                execute_tool(
                    TOOL_REGISTER_SWARM_AGENT,
                    Some(&serde_json::json!({
                        "swarm_id": "race", "agent_id": format!("agent-{i}"),
                        "role": "builder",
                    })),
                    &ctx,
                )
                .await
            }));
        }
        let mut granted = 0;
        let mut peak_allocated = 0.0f64;
        for task in tasks {
            let lease = task.await.unwrap().unwrap();
            granted += 1;
            peak_allocated = peak_allocated.max(lease["cpu_weight_allocated"].as_f64().unwrap());
        }
        assert_eq!(granted, count);
        // Every draw landed exactly once (a lost update would show a
        // lower peak).
        assert_eq!(peak_allocated, count as f64 * SWARM_AGENT_CORES);
    }

    #[tokio::test]
    async fn swarm_register_reports_slice_and_configured_budget() {
        let mut config = RunnerConfig::default();
        config.swarm.monthly_spend_cap_usd = 25.0;
        config.swarm.rate_usd_per_core_hour = Some(0.12);
        let state = new_shared_state();
        state.write().await.seed_from_config(&config);
        let seeded = ToolContext::new(state, config);
        let lease = execute_tool(
            TOOL_REGISTER_SWARM_AGENT,
            Some(&serde_json::json!({
                "swarm_id": "beta", "agent_id": "a1", "role": "builder",
            })),
            &seeded,
        )
        .await
        .unwrap();
        assert_eq!(lease["holds_slice"], true);
        assert_eq!(lease["spend_cap_usd"], 25.0);
        assert_eq!(lease["spent_usd"], 0.0);
        // Defaults: unenforced cap, nominal rate. The rate surfaces
        // on first accrual, so assert the seed directly.
        let plain = ctx();
        let lease = execute_tool(
            TOOL_REGISTER_SWARM_AGENT,
            Some(&serde_json::json!({
                "swarm_id": "gamma", "agent_id": "a1", "role": "builder",
            })),
            &plain,
        )
        .await
        .unwrap();
        assert_eq!(lease["spend_cap_usd"], 0.0);
        assert_eq!(
            plain.state.read().await.swarm_rate_usd(),
            crate::config::DEFAULT_HOST_CORE_HOUR_USD
        );
    }

    #[tokio::test]
    async fn reserve_full_table_denies_retryable() {
        let ctx = ctx();
        let args = serde_json::json!({
            "cores": 0.5, "memory_mb": 64, "duration_secs": 3600,
        });
        for _ in 0..crate::mcp::reservation::ReservationLimits::default().max_active {
            execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
                .await
                .unwrap();
        }
        let err = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("table full"), "{}", err.message);
    }

    #[tokio::test]
    async fn reserve_preempts_low_when_full() {
        let ctx = ctx();
        let low = serde_json::json!({
            "cores": 0.5, "memory_mb": 64, "duration_secs": 3600,
            "priority": "low",
        });
        for _ in 0..crate::mcp::reservation::ReservationLimits::default().max_active {
            execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&low), &ctx)
                .await
                .unwrap();
        }
        // A High incomer evicts exactly one Low lease and is admitted.
        // (Victim identity depends on expiry tie-breaks, so the test
        // pins the count and the eviction effect, not the id.)
        let high = serde_json::json!({
            "cores": 0.5, "memory_mb": 64, "duration_secs": 3600,
            "priority": "high",
        });
        let out = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&high), &ctx)
            .await
            .unwrap();
        let preempted = out["preempted"].as_array().unwrap();
        assert_eq!(preempted.len(), 1);
        let victim = preempted[0].as_str().unwrap().to_string();
        assert_ne!(out["reservation_id"].as_str().unwrap(), victim);
        // The victim is gone: releasing it now fails unknown-id, and
        // the table sits back at capacity.
        let rel = serde_json::json!({ "reservation_id": victim });
        let err = execute_tool(TOOL_RELEASE_HOST_RESOURCES, Some(&rel), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, -32602);
        assert_eq!(
            ctx.state.read().await.reservation_count(),
            crate::mcp::reservation::ReservationLimits::default().max_active
        );
    }

    #[tokio::test]
    async fn reserve_budget_hooks_fire_and_deny() {
        use crate::mcp::reservation::ScriptHooks;
        let ctx = ctx();
        let hooks = Arc::new(ScriptHooks::default());
        ctx.state.write().await.set_reservation_hooks(hooks.clone());
        let args = serde_json::json!({
            "cores": 2.0, "memory_mb": 2048, "duration_secs": 60,
        });
        // Scripted denial: -32603, nothing granted or recorded.
        *hooks.deny_budget_with.lock().unwrap() = Some("over budget".to_string());
        let err = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, -32603);
        assert!(err.message.contains("over budget"), "{}", err.message);
        assert_eq!(*hooks.calls.lock().unwrap(), vec!["budget".to_string()]);
        // Allowed: budget checked, then granted.
        let out = execute_tool(TOOL_RESERVE_HOST_RESOURCES, Some(&args), &ctx)
            .await
            .unwrap();
        let id = out["reservation_id"].as_str().unwrap().to_string();
        let calls = hooks.calls.lock().unwrap().clone();
        assert_eq!(calls[1], "budget");
        assert_eq!(calls[2], format!("grant:{id}"));
        // Release records too.
        let rel = serde_json::json!({ "reservation_id": id });
        execute_tool(TOOL_RELEASE_HOST_RESOURCES, Some(&rel), &ctx)
            .await
            .unwrap();
        let calls = hooks.calls.lock().unwrap().clone();
        assert!(calls.last().unwrap().starts_with("release:"), "{calls:?}");
    }

    #[test]
    fn reserve_schema_advertises_v2_fields() {
        let schema = tool_schema(TOOL_RESERVE_HOST_RESOURCES);
        let props = schema["properties"].as_object().unwrap();
        for field in [
            "cores",
            "ram_gb",
            "duration_minutes",
            "memory_mb",
            "duration_secs",
            "priority",
        ] {
            assert!(props.contains_key(field), "{field}");
        }
        assert_eq!(
            schema["properties"]["priority"]["enum"],
            serde_json::json!(["low", "normal", "high", "critical"])
        );
        assert_eq!(schema["required"], serde_json::json!(["cores"]));
    }

    #[tokio::test]
    async fn cloud_denied_without_budget() {
        let ctx = ctx();
        let args = serde_json::json!({
            "provider": "digitalocean", "max_instances": 1,
            "duration_hours": 1.0, "reason": "burst"
        });
        let out = execute_tool(TOOL_REQUEST_CLOUD_CAPACITY, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(out["approved"], false);
    }

    #[tokio::test]
    async fn unknown_tool_is_method_error() {
        let err = execute_tool("nope", None, &ctx()).await.unwrap_err();
        assert_eq!(err.code, -32601);
    }

    #[tokio::test]
    async fn cache_stats_delegates_to_agent() {
        let (ctx, _agent) = agent_ctx();
        let out = execute_tool(TOOL_GET_CACHE_STATS, None, &ctx)
            .await
            .unwrap();
        assert_eq!(out["enabled"], true);
        assert_eq!(out["entries"], 3);
    }

    #[test]
    fn all_fourteen_tools_have_schemas_and_descriptions() {
        assert_eq!(ALL_TOOLS.len(), 14);
        for name in ALL_TOOLS {
            let schema = tool_schema(name);
            assert_eq!(schema["type"], "object", "{name}");
            assert!(schema["properties"].is_object(), "{name}");
            assert!(schema["required"].is_array(), "{name}");
            assert_ne!(tool_description(name), "Unknown tool.", "{name}");
        }
        assert_eq!(tool_schema(TOOL_TEST_PROVIDER)["required"][0], "provider");
        assert_eq!(tool_schema(TOOL_EXEC_COMMAND)["required"][0], "command");
        assert!(tool_schema(TOOL_DIAGNOSE_SYSTEM)["required"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    /// One recorded `exec` call.
    type ExecCall = ExecRequest;

    /// Scripted agent impl: records calls, replays canned outputs.
    #[derive(Debug, Default)]
    struct ScriptAgent {
        diagnoses: std::sync::Mutex<Vec<(bool, bool)>>,
        providers: std::sync::Mutex<Vec<String>>,
        execs: std::sync::Mutex<Vec<ExecCall>>,
        clouds: std::sync::Mutex<Vec<(String, Option<String>)>>,
        reserves: std::sync::Mutex<Vec<ReservationRequest>>,
    }

    #[async_trait::async_trait]
    impl AgentTools for ScriptAgent {
        async fn diagnose(
            &self,
            egress: bool,
            enterprise: bool,
        ) -> Result<serde_json::Value, ToolError> {
            self.diagnoses.lock().unwrap().push((egress, enterprise));
            Ok(serde_json::json!({ "ok": true, "checks": [] }))
        }

        async fn test_provider(&self, provider: &str) -> Result<serde_json::Value, ToolError> {
            self.providers.lock().unwrap().push(provider.to_string());
            Ok(serde_json::json!({ "provider": provider, "ok": true, "lines": [] }))
        }

        async fn exec(&self, request: ExecRequest) -> Result<serde_json::Value, ToolError> {
            self.execs.lock().unwrap().push(request);
            Ok(serde_json::json!({
                "code": 0, "stdout": "hi\n", "stderr": "",
                "elapsed_secs": 0.01, "timeout": false,
            }))
        }

        async fn manage_cloud(
            &self,
            action: &str,
            instance_id: Option<&str>,
        ) -> Result<serde_json::Value, ToolError> {
            self.clouds
                .lock()
                .unwrap()
                .push((action.to_string(), instance_id.map(str::to_string)));
            Ok(serde_json::json!({ "action": action, "active_nodes": 0 }))
        }

        async fn cache_stats(&self) -> Result<serde_json::Value, ToolError> {
            Ok(serde_json::json!({ "enabled": true, "entries": 3 }))
        }

        // Daemon-backed tools report offline so dispatch tests exercise
        // the local fallback deterministically.
        async fn reserve(
            &self,
            request: ReservationRequest,
        ) -> Result<serde_json::Value, ToolError> {
            self.reserves.lock().unwrap().push(request);
            Err(ToolError::offline("scripted offline"))
        }

        async fn release(&self, _id: &str) -> Result<serde_json::Value, ToolError> {
            Err(ToolError::offline("scripted offline"))
        }

        async fn throttle(&self, _level: &str, _mins: u64) -> Result<serde_json::Value, ToolError> {
            Err(ToolError::offline("scripted offline"))
        }

        async fn drain(&self, _id: &str, _reason: &str) -> Result<serde_json::Value, ToolError> {
            Err(ToolError::offline("scripted offline"))
        }

        async fn request_cloud(
            &self,
            _provider: &str,
            _max: u32,
            _hours: f64,
            _reason: &str,
        ) -> Result<serde_json::Value, ToolError> {
            Err(ToolError::offline("scripted offline"))
        }

        async fn ci_status(&self) -> Result<serde_json::Value, ToolError> {
            Err(ToolError::offline("scripted offline"))
        }

        async fn fleet_topology(&self) -> Result<serde_json::Value, ToolError> {
            Err(ToolError::offline("scripted offline"))
        }
    }

    fn agent_ctx() -> (ToolContext, Arc<ScriptAgent>) {
        let agent = Arc::new(ScriptAgent::default());
        let ctx = ctx().with_agent(agent.clone());
        (ctx, agent)
    }

    #[tokio::test]
    async fn diagnose_delegates_flags_and_returns_json() {
        let (ctx, agent) = agent_ctx();
        let args = serde_json::json!({ "egress": true });
        let out = execute_tool(TOOL_DIAGNOSE_SYSTEM, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(out["ok"], true);
        assert!(out["checks"].is_array());
        assert_eq!(*agent.diagnoses.lock().unwrap(), vec![(true, false)]);
    }

    #[tokio::test]
    async fn provider_names_normalize_and_unknown_rejects() {
        let (ctx, agent) = agent_ctx();
        let args = serde_json::json!({ "provider": "GitHub" });
        let out = execute_tool(TOOL_TEST_PROVIDER, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(out["provider"], "github");
        assert_eq!(*agent.providers.lock().unwrap(), vec!["github"]);

        let args = serde_json::json!({ "provider": "jenkins" });
        let err = execute_tool(TOOL_TEST_PROVIDER, Some(&args), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("jenkins"));
        // Rejected before delegation: no second call recorded.
        assert_eq!(agent.providers.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn exec_validates_and_delegates_with_defaults() {
        let (ctx, agent) = agent_ctx();
        let args = serde_json::json!({
            "command": ["echo", "hi"], "env": { "A": "b" },
        });
        let out = execute_tool(TOOL_EXEC_COMMAND, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(out["code"], 0);
        assert_eq!(out["stdout"], "hi\n");
        assert_eq!(out["timeout"], false);
        {
            let calls = agent.execs.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].command, vec!["echo", "hi"]);
            assert_eq!(calls[0].timeout_secs, 60);
            assert_eq!(calls[0].env, vec![("A".to_string(), "b".to_string())]);
            assert_eq!(calls[0].driver, "process");
            assert_eq!(calls[0].image, None);
            assert!(!calls[0].no_network);
            assert!(calls[0].volumes.is_empty());
        }

        for bad in [
            serde_json::json!({ "command": [] }),
            serde_json::json!({ "command": ["echo", ""] }),
            serde_json::json!({ "command": ["echo"], "timeout_secs": 0 }),
            // Unknown driver...
            serde_json::json!({ "command": ["echo"], "driver": "gvisor" }),
            // ...microvm is real but not MCP-runnable...
            serde_json::json!({ "command": ["echo"], "driver": "microvm" }),
            // ...container-only fields with another driver...
            serde_json::json!({ "command": ["echo"], "image": "ubuntu:24.04" }),
            serde_json::json!({ "command": ["echo"], "volumes": ["/a:/b"] }),
            serde_json::json!({ "command": ["echo"], "no_network": true }),
            // ...and blank volume specs even for containers.
            serde_json::json!({ "command": ["echo"], "driver": "container", "volumes": ["  "] }),
        ] {
            let err = execute_tool(TOOL_EXEC_COMMAND, Some(&bad), &ctx)
                .await
                .unwrap_err();
            assert_eq!(err.code, -32602, "{bad}");
        }
        assert_eq!(agent.execs.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn exec_container_dispatch_roundtrip() {
        let (ctx, agent) = agent_ctx();
        let args = serde_json::json!({
            "command": ["make", "test"],
            "driver": "Container",
            "image": "ubuntu:24.04",
            "no_network": true,
            "volumes": ["/opt/data:/data:ro"],
            "timeout_secs": 120,
        });
        let out = execute_tool(TOOL_EXEC_COMMAND, Some(&args), &ctx)
            .await
            .unwrap();
        assert_eq!(out["code"], 0);
        let calls = agent.execs.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].driver, "container");
        assert_eq!(calls[0].image.as_deref(), Some("ubuntu:24.04"));
        assert!(calls[0].no_network);
        assert_eq!(calls[0].volumes, vec!["/opt/data:/data:ro"]);
        assert_eq!(calls[0].timeout_secs, 120);
    }

    #[test]
    fn exec_schema_advertises_container_fields() {
        let schema = tool_schema(TOOL_EXEC_COMMAND);
        let props = &schema["properties"];
        assert_eq!(props["driver"]["enum"][1], "container");
        assert_eq!(props["image"]["type"], "string");
        assert_eq!(props["no_network"]["type"], "boolean");
        assert_eq!(props["volumes"]["type"], "array");
        assert!(schema["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("command")));
    }

    #[tokio::test]
    async fn unwired_context_reports_not_configured() {
        let err = execute_tool(TOOL_DIAGNOSE_SYSTEM, None, &ctx())
            .await
            .unwrap_err();
        assert_eq!(err.code, -32603);
    }

    #[tokio::test]
    async fn manage_cloud_validates_action_and_id() {
        let (ctx, agent) = agent_ctx();
        let out = execute_tool(
            TOOL_MANAGE_CLOUD_CAPACITY,
            Some(&serde_json::json!({ "action": "List" })),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(out["action"], "list");
        let out = execute_tool(
            TOOL_MANAGE_CLOUD_CAPACITY,
            Some(&serde_json::json!({ "action": "terminate", "instance_id": "i-1" })),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(out["action"], "terminate");
        assert_eq!(
            *agent.clouds.lock().unwrap(),
            vec![
                ("list".to_string(), None),
                ("terminate".to_string(), Some("i-1".to_string())),
            ]
        );

        for bad in [
            serde_json::json!({ "action": "explode" }),
            serde_json::json!({ "action": "terminate" }),
            serde_json::json!({ "action": "terminate", "instance_id": "  " }),
            serde_json::json!({}),
        ] {
            let err = execute_tool(TOOL_MANAGE_CLOUD_CAPACITY, Some(&bad), &ctx)
                .await
                .unwrap_err();
            assert_eq!(err.code, -32602, "{bad}");
        }
        assert_eq!(agent.clouds.lock().unwrap().len(), 2);
    }
}
