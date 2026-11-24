//! Production [`AgentTools`]
//! implementation: delegates the Phase 8 MCP tools to the existing
//! `doctor`, `provider`, and local-execution modules (plus Phase 10
//! cloud management over daemon IPC) so CLI and MCP output can never
//! drift apart.

use std::time::{Duration, Instant};

use runner_core::config::RunnerConfig;
use runner_core::ipc::{ipc_call_with, resolve_sock_path};
use runner_core::mcp::reservation::ReservationRequest;
use runner_core::mcp::tools::{AgentTools, ToolError};

use crate::doctor::{render_json, run_all};
use crate::provider::{test_provider, ProviderName};

/// Agent tools backed by the real doctor/provider/exec implementations.
/// Daemon-backed tools go over IPC; [`with_sock_path`](Self::with_sock_path)
/// redirects them at an isolated socket for tests.
#[derive(Debug)]
pub struct CliAgentTools {
    config: RunnerConfig,
    sock_path: Option<std::path::PathBuf>,
}

impl CliAgentTools {
    pub fn new(config: RunnerConfig) -> Self {
        Self {
            config,
            sock_path: None,
        }
    }

    pub fn with_sock_path(mut self, path: std::path::PathBuf) -> Self {
        self.sock_path = Some(path);
        self
    }

    fn sock(&self) -> std::path::PathBuf {
        self.sock_path.clone().unwrap_or_else(resolve_sock_path)
    }

    /// Call one daemon method. Transport failure maps to
    /// [`ToolError::offline`] (the dispatcher falls back to local
    /// state); daemon error payloads map to params/internal errors
    /// and never fall back.
    async fn daemon(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ToolError> {
        let sock = self.sock();
        let res = ipc_call_with(&sock, method, params).await.map_err(|_| {
            ToolError::offline(format!("daemon not reachable at {}", sock.display()))
        })?;
        if let Some(err) = res.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-32603);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown daemon error")
                .to_string();
            if code == -32602 {
                return Err(ToolError::invalid_params(message));
            }
            return Err(ToolError::internal(format!("daemon error: {message}")));
        }
        Ok(res["result"].clone())
    }

    /// Container-tier exec: resolve image/volumes against config, run
    /// captured. Agent env merges over the host (same contract as the
    /// process tier's inherited-plus-override environment).
    async fn exec_container(
        &self,
        request: runner_core::mcp::tools::ExecRequest,
    ) -> Result<serde_json::Value, ToolError> {
        use runner_sandbox::oci::{
            execute_container_captured, parse_volume_spec, resolve_container_image, ContainerLaunch,
        };

        let mut volumes = Vec::with_capacity(request.volumes.len());
        for spec in &request.volumes {
            match parse_volume_spec(spec) {
                Ok(volume) => volumes.push(volume),
                Err(e) => return Err(ToolError::invalid_params(e)),
            }
        }
        let image =
            match resolve_container_image(request.image.as_deref(), &self.config.sandbox.container)
            {
                Ok(image) => image,
                Err(e) => return Err(ToolError::invalid_params(e)),
            };
        let mut env: std::collections::HashMap<String, String> = std::env::vars().collect();
        for (key, value) in request.env {
            env.insert(key, value);
        }
        let launch = ContainerLaunch {
            runtime_override: self.config.sandbox.container.runtime_path.clone(),
            command: request.command,
            timeout: Duration::from_secs(request.timeout_secs),
            volumes,
            network_egress_filtering: self.config.security.network_egress_filtering,
            image,
            no_network: request.no_network || self.config.sandbox.container.no_network,
            env: Some(env.into_iter().map(|(k, v)| format!("{k}={v}")).collect()),
            auto_pull: self.config.sandbox.container.auto_pull,
            layer_cache_dir: self.config.sandbox.container.cache_dir.clone(),
            gc_policy: Some(runner_sandbox::oci::gc::GcPolicy::from_config(
                &self.config.storage.gc,
            )),
        };
        let start = Instant::now();
        match execute_container_captured(launch).await {
            Ok(out) => Ok(serde_json::json!({
                "code": out.code,
                "stdout": String::from_utf8_lossy(&out.stdout),
                "stderr": String::from_utf8_lossy(&out.stderr),
                "elapsed_secs": start.elapsed().as_secs_f64(),
                "timeout": false,
            })),
            Err(e) => {
                if e.contains("timed out") {
                    Ok(serde_json::json!({
                        "timeout": true,
                        "elapsed_secs": start.elapsed().as_secs_f64(),
                    }))
                } else {
                    Err(ToolError::internal(e))
                }
            }
        }
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
        let checks = run_all(&self.config, enterprise, egress).await;
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
        request: runner_core::mcp::tools::ExecRequest,
    ) -> Result<serde_json::Value, ToolError> {
        if request.driver == "container" {
            return self.exec_container(request).await;
        }
        let start = Instant::now();
        // Sandbox when the kernel allows it, governed-direct otherwise —
        // the same default as `runner exec`.
        match runner_providers::providers::local::execute_captured(
            &request.command,
            &request.env,
            false,
            Duration::from_secs(request.timeout_secs),
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
        let sock = self.sock();
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

    async fn cache_stats(&self) -> Result<serde_json::Value, ToolError> {
        // Same split as manage_cloud: the daemon owns the store, so this
        // goes over daemon IPC — the same method `runner cache` uses.
        let sock = self.sock();
        let res = ipc_call_with(&sock, "cache_stats", None)
            .await
            .map_err(|_| {
                ToolError::internal(format!("daemon not reachable at {}", sock.display()))
            })?;
        if res.get("error").is_some() {
            // Proxy not running in the daemon: honest disabled signal.
            return Ok(serde_json::json!({ "enabled": false }));
        }
        let Some(result) = res.get("result").and_then(|v| v.as_object()) else {
            return Ok(serde_json::json!({ "enabled": false }));
        };
        let mut out = serde_json::Value::Object(result.clone());
        out["enabled"] = serde_json::Value::Bool(true);
        Ok(out)
    }

    async fn reserve(&self, request: ReservationRequest) -> Result<serde_json::Value, ToolError> {
        let out = self
            .daemon(
                "reserve",
                Some(serde_json::json!({
                    "cores": request.cores,
                    // Legacy units for old daemons (exact ram round-trip;
                    // minutes round up, over-holding conservatively).
                    "ram_gb": request.memory_mb as f64 / 1024.0,
                    "duration_minutes": request.duration_secs.div_ceil(60),
                    "memory_mb": request.memory_mb,
                    "duration_secs": request.duration_secs,
                    "priority": request.priority,
                    "reason": request.reason.clone(),
                })),
            )
            .await?;
        // Adapt the IPC shape to the MCP shape, preferring canonical
        // daemon echoes and falling back to request values (old
        // daemons echo v1 inputs only).
        Ok(serde_json::json!({
            "reservation_id": out["reservation_id"],
            "cores": out["cores"],
            "ram_mb": out.get("ram_mb").cloned()
                .unwrap_or(serde_json::json!(request.memory_mb)),
            "priority": out.get("priority").cloned()
                .unwrap_or(serde_json::json!("normal")),
            "duration_secs": out.get("duration_secs").cloned()
                .unwrap_or(serde_json::json!(request.duration_secs)),
            "preempted": out.get("preempted").cloned()
                .unwrap_or(serde_json::json!([])),
            "reason": request.reason,
        }))
    }

    async fn release(&self, reservation_id: &str) -> Result<serde_json::Value, ToolError> {
        let out = self
            .daemon(
                "release",
                Some(serde_json::json!({ "reservation_id": reservation_id })),
            )
            .await?;
        if out["found"].as_bool().unwrap_or(false) {
            Ok(serde_json::json!({ "released": reservation_id }))
        } else {
            Err(ToolError::invalid_params(format!(
                "unknown reservation_id: {reservation_id}"
            )))
        }
    }

    async fn throttle(
        &self,
        level: &str,
        duration_minutes: u64,
    ) -> Result<serde_json::Value, ToolError> {
        self.daemon(
            "throttle_set",
            Some(serde_json::json!({
                "level": level,
                "duration_minutes": duration_minutes,
            })),
        )
        .await
    }

    async fn drain(&self, node_id: &str, reason: &str) -> Result<serde_json::Value, ToolError> {
        self.daemon(
            "drain",
            Some(serde_json::json!({ "node_id": node_id, "reason": reason })),
        )
        .await
        .map(|out| serde_json::json!({ "drained": out["node_id"] }))
    }

    async fn request_cloud(
        &self,
        provider: &str,
        max_instances: u32,
        duration_hours: f64,
        reason: &str,
    ) -> Result<serde_json::Value, ToolError> {
        self.daemon(
            "cloud_capacity",
            Some(serde_json::json!({
                "provider": provider,
                "max_instances": max_instances,
                "duration_hours": duration_hours,
                "reason": reason,
            })),
        )
        .await
    }

    async fn ci_status(&self) -> Result<serde_json::Value, ToolError> {
        self.daemon("ci_status", None).await
    }

    async fn fleet_topology(&self) -> Result<serde_json::Value, ToolError> {
        self.daemon("fleet_topology", None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_core::mcp::tools::{AgentTools, ExecRequest};

    fn container_request() -> ExecRequest {
        ExecRequest {
            command: vec!["true".to_string()],
            timeout_secs: 10,
            env: vec![],
            driver: "container".to_string(),
            image: Some("test:latest".to_string()),
            no_network: false,
            volumes: vec![],
        }
    }

    #[tokio::test]
    async fn exec_container_rejects_bad_inputs_without_spawn() {
        // Hermetic: no registry traffic (config defaults auto_pull on).
        let mut hermetic = RunnerConfig::default();
        hermetic.sandbox.container.auto_pull = false;
        let agent = CliAgentTools::new(hermetic);
        // Malformed volume spec.
        let mut bad_volumes = container_request();
        bad_volumes.volumes = vec![":::".to_string()];
        let err = agent.exec(bad_volumes).await.unwrap_err();
        assert_eq!(err.code, -32602);
        // Missing image and no configured default.
        let mut no_image = container_request();
        no_image.image = None;
        let err = agent.exec(no_image).await.unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("default_image"), "{}", err.message);
        // Bogus runtime override fails at the probe (internal: the
        // inputs parsed, the host lacks the binary).
        let mut config = RunnerConfig::default();
        config.sandbox.container.auto_pull = false;
        config.sandbox.container.runtime_path =
            Some(std::path::PathBuf::from("/nonexistent/oci-runtime"));
        let agent = CliAgentTools::new(config);
        let err = agent.exec(container_request()).await.unwrap_err();
        assert_eq!(err.code, -32603);
        assert!(
            err.message.contains("not a runnable binary"),
            "{}",
            err.message
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_container_captures_shim_output() {
        let dir = runner_core::test_support::TempDir::new("agent-ctr").unwrap();
        let shim = dir.path().join("echo-rt");
        std::fs::write(&shim, "#!/bin/sh\necho OUT; echo ERR >&2; exit 3\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = RunnerConfig::default();
        config.sandbox.container.auto_pull = false;
        config.sandbox.container.runtime_path = Some(shim);
        let agent = CliAgentTools::new(config);
        let out = agent.exec(container_request()).await.unwrap();
        assert_eq!(out["code"], 3);
        assert_eq!(out["stdout"], "OUT\n");
        assert_eq!(out["stderr"], "ERR\n");
        assert_eq!(out["timeout"], false);
        assert!(out["elapsed_secs"].as_f64().unwrap() >= 0.0);
    }
}
