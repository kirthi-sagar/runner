//! Production [`AgentTools`](runner_core::mcp::tools::AgentTools)
//! implementation: delegates the Phase 8 MCP tools to the existing
//! `doctor`, `provider`, and local-execution modules (plus Phase 10
//! cloud management over daemon IPC) so CLI and MCP output can never
//! drift apart.

use std::time::{Duration, Instant};

use runner_core::config::RunnerConfig;
use runner_core::ipc::{ipc_call_with, resolve_sock_path};
use runner_core::mcp::tools::{AgentTools, ToolError};

use crate::doctor::{render_json, run_all};
use crate::provider::{test_provider, ProviderName};

/// Agent tools backed by the real doctor/provider/exec implementations.
#[derive(Debug)]
pub struct CliAgentTools {
    config: RunnerConfig,
}

impl CliAgentTools {
    pub fn new(config: RunnerConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl AgentTools for CliAgentTools {
    async fn diagnose(
        &self,
        egress: bool,
        enterprise: bool,
    ) -> Result<serde_json::Value, ToolError> {
        // Reuse the CLI renderer, then parse back: MCP and `doctor
        // --format json` share one schema by construction.
        let checks = run_all(enterprise, egress).await;
        serde_json::from_str(&render_json(&checks)).map_err(|e| ToolError::internal(e.to_string()))
    }

    async fn test_provider(&self, provider: &str) -> Result<serde_json::Value, ToolError> {
        // Core pre-validates the name; re-parse defensively so a direct
        // caller can never smuggle an unknown provider through.
        let name = ProviderName::from_name(provider).map_err(ToolError::invalid_params)?;
        let report = test_provider(name, &self.config).await;
        Ok(serde_json::json!({
            "provider": report.provider,
            "ok": report.ok,
            "lines": report.lines,
        }))
    }

    async fn exec(
        &self,
        command: Vec<String>,
        timeout_secs: u64,
        env: Vec<(String, String)>,
    ) -> Result<serde_json::Value, ToolError> {
        let start = Instant::now();
        // Sandbox when the kernel allows it, governed-direct otherwise —
        // the same default as `runner exec`.
        match runner_providers::providers::local::execute_captured(
            &command,
            &env,
            false,
            Duration::from_secs(timeout_secs),
        )
        .await
        {
            Ok(out) => Ok(serde_json::json!({
                "code": out.code,
                "stdout": String::from_utf8_lossy(&out.stdout),
                "stderr": String::from_utf8_lossy(&out.stderr),
                "elapsed_secs": start.elapsed().as_secs_f64(),
                "timeout": false,
            })),
            Err(e) => {
                let message = format!("{e:#}");
                if message.contains("timed out") {
                    // Timeouts are data, not RPC errors: the agent must be
                    // able to distinguish "slow" from "broken".
                    Ok(serde_json::json!({
                        "timeout": true,
                        "elapsed_secs": start.elapsed().as_secs_f64(),
                    }))
                } else {
                    Err(ToolError::internal(message))
                }
            }
        }
    }

    async fn manage_cloud(
        &self,
        action: &str,
        instance_id: Option<&str>,
    ) -> Result<serde_json::Value, ToolError> {
        // The MCP server's local state never tracks cloud nodes; the
        // daemon owns them, so every action goes over daemon IPC —
        // the same methods `runner cloud` uses.
        let (method, params) = match action {
            "list" => ("cloud_list", None),
            "purge" => ("cloud_purge", None),
            "terminate" => (
                "cloud_terminate",
                Some(serde_json::json!({ "instance_id": instance_id.unwrap_or("") })),
            ),
            other => {
                return Err(ToolError::invalid_params(format!(
                    "unknown action: '{other}'"
                )))
            }
        };
        let sock = resolve_sock_path();
        let res = ipc_call_with(&sock, method, params).await.map_err(|_| {
            ToolError::internal(format!("daemon not reachable at {}", sock.display()))
        })?;
        if let Some(err) = res.get("error") {
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown daemon error");
            return Err(ToolError::internal(format!("daemon error: {message}")));
        }
        let result = res["result"].clone();
        if action == "list" {
            let nodes = result["nodes"].as_array().cloned().unwrap_or_default();
            let providers = ["digitalocean", "render"]
                .into_iter()
                .filter(|p| result["providers"][p].as_bool().unwrap_or(false))
                .collect::<Vec<_>>();
            return Ok(serde_json::json!({
                "action": action,
                "active_nodes": nodes.len(),
                "nodes": nodes,
                "providers": providers,
                "spend_usd": result["spend_usd"],
                "max_monthly_spend_usd": result["max_monthly_spend_usd"],
                "spend_tracked": result["spend_tracked"],
            }));
        }
        Ok(result)
    }
}
