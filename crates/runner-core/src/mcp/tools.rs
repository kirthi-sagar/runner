//! MCP tool definitions + executors for the AI-agent admin tier.
//!
//! Seven tools per the Phase 2 contract: `get_ci_status`,
//! `get_fleet_topology`, `reserve_host_resources`,
//! `release_host_resources`, `throttle_runner`, `request_cloud_capacity`,
//! `drain_node`.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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

/// All tool names, in contract order.
pub const ALL_TOOLS: [&str; 7] = [
    TOOL_GET_CI_STATUS,
    TOOL_GET_FLEET_TOPOLOGY,
    TOOL_RESERVE_HOST_RESOURCES,
    TOOL_RELEASE_HOST_RESOURCES,
    TOOL_THROTTLE_RUNNER,
    TOOL_REQUEST_CLOUD_CAPACITY,
    TOOL_DRAIN_NODE,
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReserveHostResourcesArgs {
    pub cores: f64,
    pub ram_gb: f64,
    pub duration_minutes: u64,
    #[serde(default)]
    pub reason: String,
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

/// Execution context: shared daemon state + Super Admin policy + cloud.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub state: SharedState,
    pub config: RunnerConfig,
    pub cloud: CloudPool,
}

impl ToolContext {
    pub fn new(state: SharedState, config: RunnerConfig) -> Self {
        let cloud = CloudPool::from_config(&config);
        Self {
            state,
            config,
            cloud,
        }
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

/// Dispatch one `tools/call` by name. Returns the JSON value rendered into
/// the text content block.
pub async fn execute_tool(
    name: &str,
    args: Option<&serde_json::Value>,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    match name {
        TOOL_GET_CI_STATUS => get_ci_status(ctx).await,
        TOOL_GET_FLEET_TOPOLOGY => get_fleet_topology(ctx).await,
        TOOL_RESERVE_HOST_RESOURCES => {
            let args: ReserveHostResourcesArgs = parse_args(args)?;
            reserve_host_resources(&args, ctx).await
        }
        TOOL_RELEASE_HOST_RESOURCES => {
            let args: ReleaseHostResourcesArgs = parse_args(args)?;
            release_host_resources(&args, ctx).await
        }
        TOOL_THROTTLE_RUNNER => {
            let args: ThrottleRunnerArgs = parse_args(args)?;
            throttle_runner(&args, ctx).await
        }
        TOOL_REQUEST_CLOUD_CAPACITY => {
            let args: RequestCloudCapacityArgs = parse_args(args)?;
            request_cloud_capacity(&args, ctx).await
        }
        TOOL_DRAIN_NODE => {
            let args: DrainNodeArgs = parse_args(args)?;
            drain_node(&args, ctx).await
        }
        _ => Err(ToolError {
            code: -32601,
            message: format!("unknown tool: {name}"),
        }),
    }
}

async fn get_ci_status(ctx: &ToolContext) -> Result<serde_json::Value, ToolError> {
    let report = crate::status::status_report();
    let state = ctx.state.read().await;
    Ok(serde_json::json!({
        "status": report.status,
        "version": report.version,
        "host": report.host,
        "concurrency": report.concurrency,
        "governor": {
            "last_weight": state.last_weight,
            "last_slots": state.last_slots,
            "afk_boost": state.afk.boosted(),
        },
        "reservations": state.reservations().iter().map(|r| serde_json::json!({
            "id": r.id, "cores": r.cores, "ram_mb": r.ram_mb, "reason": r.reason,
        })).collect::<Vec<_>>(),
        "drained_nodes": state.drained_nodes(),
    }))
}

async fn get_fleet_topology(ctx: &ToolContext) -> Result<serde_json::Value, ToolError> {
    let report = crate::status::status_report();
    let state = ctx.state.read().await;
    Ok(serde_json::json!({
        "local": {
            "total_cores": report.host.total_cores,
            "physical_cores": report.host.physical_cores,
            "available_memory_bytes": report.host.available_memory_bytes,
            "max_slots": report.concurrency.max_slots,
            "cpu_level": report.host.psi_pressure.cpu_level,
        },
        "wan_peers": state.peers(),
        "cloud_nodes": state.cloud_nodes(),
        "drained_nodes": state.drained_nodes(),
    }))
}

async fn reserve_host_resources(
    args: &ReserveHostResourcesArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    if !args.cores.is_finite() || args.cores <= 0.0 {
        return Err(ToolError::invalid_params(
            "cores must be a finite value > 0",
        ));
    }
    if !args.ram_gb.is_finite() || args.ram_gb <= 0.0 {
        return Err(ToolError::invalid_params(
            "ram_gb must be a finite value > 0",
        ));
    }
    if args.duration_minutes == 0 {
        return Err(ToolError::invalid_params("duration_minutes must be > 0"));
    }
    let now = Instant::now();
    let mut state = ctx.state.write().await;
    state.prune_expired(now);
    let reservation = state.reserve(
        args.cores,
        (args.ram_gb * 1024.0) as u64,
        Duration::from_secs(args.duration_minutes * 60),
        args.reason.clone(),
        now,
    );
    Ok(serde_json::json!({
        "reservation_id": reservation.id,
        "cores": reservation.cores,
        "ram_mb": reservation.ram_mb,
        "reason": reservation.reason,
    }))
}

async fn release_host_resources(
    args: &ReleaseHostResourcesArgs,
    ctx: &ToolContext,
) -> Result<serde_json::Value, ToolError> {
    let mut state = ctx.state.write().await;
    if state.release(&args.reservation_id) {
        Ok(serde_json::json!({ "released": args.reservation_id }))
    } else {
        Err(ToolError::invalid_params(format!(
            "unknown reservation_id: {}",
            args.reservation_id
        )))
    }
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
    if args.provider != "digitalocean" && args.provider != "render" {
        return Err(ToolError::invalid_params(format!(
            "provider must be \"digitalocean\" or \"render\", got {:?}",
            args.provider
        )));
    }
    if args.max_instances == 0 {
        return Err(ToolError::invalid_params("max_instances must be > 0"));
    }
    if !args.duration_hours.is_finite() || args.duration_hours <= 0.0 {
        return Err(ToolError::invalid_params(
            "duration_hours must be a finite value > 0",
        ));
    }
    // Dual-tier governance: agents can never exceed the Super Admin ceiling.
    // A zero ceiling means no cloud spend is pre-approved.
    if ctx.config.cloud.max_monthly_spend <= 0.0 {
        return Ok(serde_json::json!({
            "approved": false,
            "reason": "no cloud spend pre-approved: Super Admin must set cloud.max_monthly_spend > 0",
        }));
    }
    if !ctx.cloud.has_provider(&args.provider) {
        return Ok(serde_json::json!({
            "approved": false,
            "reason": format!(
                "provider {:?} has no token in config.toml; Super Admin must approve credentials",
                args.provider
            ),
        }));
    }
    // Phase 3: provision live within budget, one instance per call. The
    // caller repeats the call (bounded by max_instances) as the backlog
    // persists; each node self-terminates after 5 idle minutes.
    let name = format!("runner-ci-{}", now_millis());
    let node = ctx
        .cloud
        .provision(&args.provider, &name)
        .await
        .map_err(ToolError::internal)?;
    ctx.state.write().await.add_cloud_node(node.clone());
    Ok(serde_json::json!({
        "approved": true,
        "provider": args.provider,
        "node_id": node.id,
        "node_status": node.status,
        "max_instances": args.max_instances,
        "duration_hours": args.duration_hours,
        "budget_cap_usd": ctx.config.cloud.max_monthly_spend,
    }))
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
    ctx.state
        .write()
        .await
        .drain_node(args.node_id.clone(), args.reason.clone());
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
            }),
            vec!["cores", "ram_gb", "duration_minutes"],
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
        _ => (serde_json::json!({}), vec![]),
    };
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

/// One-line description per tool for `tools/list`.
pub fn tool_description(name: &str) -> &'static str {
    match name {
        TOOL_GET_CI_STATUS => "Host health, PSI pressure, slots, queue counts, reservations.",
        TOOL_GET_FLEET_TOPOLOGY => "Compute split across local, WAN peers, and cloud nodes.",
        TOOL_RESERVE_HOST_RESOURCES => "Hold CPU/RAM headroom for local agent work.",
        TOOL_RELEASE_HOST_RESOURCES => "Release a host resource reservation.",
        TOOL_THROTTLE_RUNNER => "Force runner weights down for a duration (never freezes).",
        TOOL_REQUEST_CLOUD_CAPACITY => "Request cloud burst within the pre-approved budget.",
        TOOL_DRAIN_NODE => "Stop dispatching new jobs to a node.",
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
}
