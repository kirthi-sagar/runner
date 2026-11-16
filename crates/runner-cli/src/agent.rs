//! Production [`AgentTools`](runner_core::mcp::tools::AgentTools)
//! implementation: delegates the three Phase 8 MCP tools to the
//! existing `doctor`, `provider`, and local-execution modules so CLI
//! and MCP output can never drift apart.

use std::time::{Duration, Instant};

use runner_core::config::RunnerConfig;
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
}
