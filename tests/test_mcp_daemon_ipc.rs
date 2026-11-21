//! MCP-over-daemon-IPC convergence: tools invoked through `McpServer`
//! with production `CliAgentTools` must mutate the LIVE daemon state
//! over the socket — never a throwaway local copy. Each test spins an
//! in-process `IpcServer` on an isolated socket and asserts the daemon
//! `SharedState` reflects every mutation immediately.

use std::sync::Arc;

use runner::config::RunnerConfig;
use runner::governor::supervisor::{new_shared_state, SharedState};
use runner::ipc::IpcServer;
use runner::mcp::server::McpServer;
use runner::mcp::tools::ToolContext;
use runner::test_support::TempDir;
use runner_cli::agent::CliAgentTools;

fn call(id: u64, name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": name, "arguments": args },
    })
}

/// Unwrap the text content block MCP renders tool results into.
fn content_text(res: &serde_json::Value) -> serde_json::Value {
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .expect("text content block");
    serde_json::from_str(text).expect("result is JSON")
}

struct DaemonHarness {
    _dir: TempDir,
    _server_task: tokio::task::JoinHandle<()>,
    daemon_state: SharedState,
    mcp: McpServer,
}

impl DaemonHarness {
    async fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag).unwrap();
        let sock = dir.path().join("daemon.sock");
        let daemon_state = new_shared_state();
        let server = Arc::new(IpcServer::bind(&sock, daemon_state.clone()).await.unwrap());
        let server_task = tokio::spawn(async move {
            let _ = server.serve().await;
        });
        // Give the listener a moment to bind (connect retries inside
        // the client cover the rest).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let agent = CliAgentTools::new(RunnerConfig::default()).with_sock_path(sock);
        let mcp = McpServer::new(
            ToolContext::new(new_shared_state(), RunnerConfig::default())
                .with_agent(Arc::new(agent)),
        );
        Self {
            _dir: dir,
            _server_task: server_task,
            daemon_state,
            mcp,
        }
    }

    async fn tool(&self, id: u64, name: &str, args: serde_json::Value) -> serde_json::Value {
        let res = self
            .mcp
            .handle_value(call(id, name, args))
            .await
            .expect("response");
        assert!(res.get("error").is_none(), "unexpected tool error: {res}");
        content_text(&res)
    }
}

#[tokio::test]
async fn reserve_mutates_live_daemon_state() {
    let h = DaemonHarness::new("mcp-ipc-reserve").await;
    let out = h
        .tool(
            1,
            "reserve_host_resources",
            serde_json::json!({
                "cores": 2.0, "ram_gb": 4.0,
                "duration_minutes": 30, "reason": "agent build",
            }),
        )
        .await;
    // Frozen MCP shape preserved over the daemon path.
    assert_eq!(out["cores"], 2.0);
    assert_eq!(out["ram_mb"], 4096);
    assert_eq!(out["reason"], "agent build");
    let id = out["reservation_id"].as_str().unwrap().to_string();
    // ... and the DAEMON state (not a local copy) holds it.
    let reservations = h.daemon_state.read().await.reservations();
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].id, id);

    // Release removes it from the same live state.
    let out = h
        .tool(
            2,
            "release_host_resources",
            serde_json::json!({ "reservation_id": id }),
        )
        .await;
    assert_eq!(out["released"], id);
    assert!(h.daemon_state.read().await.reservations().is_empty());

    // Unknown ids still fail exactly like the local path.
    let res = h
        .mcp
        .handle_value(call(
            3,
            "release_host_resources",
            serde_json::json!({ "reservation_id": "res-nope" }),
        ))
        .await
        .expect("response");
    assert_eq!(res["error"]["code"], -32602);
}

#[tokio::test]
async fn throttle_and_drain_hit_live_daemon_state() {
    let h = DaemonHarness::new("mcp-ipc-throttle").await;
    let out = h
        .tool(
            1,
            "throttle_runner",
            serde_json::json!({ "level": "critical", "duration_minutes": 10 }),
        )
        .await;
    assert_eq!(out["level"], "critical");
    assert_eq!(out["cpu_weight"], 1);
    assert_eq!(
        h.daemon_state
            .read()
            .await
            .throttle_weight(std::time::Instant::now()),
        Some(1)
    );

    h.tool(
        2,
        "drain_node",
        serde_json::json!({ "node_id": "peer-7", "reason": "flaky" }),
    )
    .await;
    assert_eq!(
        h.daemon_state.read().await.drained_nodes().get("peer-7"),
        Some(&"flaky".to_string())
    );
}

#[tokio::test]
async fn status_tools_read_live_daemon_state() {
    let h = DaemonHarness::new("mcp-ipc-status").await;
    // Seed daemon-side state directly, then observe it via MCP.
    h.tool(
        1,
        "reserve_host_resources",
        serde_json::json!({
            "cores": 1.0, "ram_gb": 1.0,
            "duration_minutes": 30, "reason": "probe",
        }),
    )
    .await;
    let status = h.tool(2, "get_ci_status", serde_json::json!({})).await;
    assert_eq!(status["reservations"].as_array().unwrap().len(), 1);
    assert_eq!(status["reservations"][0]["reason"], "probe");
    assert!(status["governor"]["afk_mode"].is_string());

    let fleet = h.tool(3, "get_fleet_topology", serde_json::json!({})).await;
    assert!(fleet["local"]["max_slots"].as_u64().unwrap() >= 1);
    assert!(fleet["wan_peers"].is_array());
}

#[tokio::test]
async fn offline_agent_falls_back_to_local_state() {
    // No daemon behind this socket: the dispatcher must use local MCP
    // state (today's standalone behavior) instead of erroring.
    let dir = TempDir::new("mcp-ipc-offline").unwrap();
    let dead = dir.path().join("nobody.sock");
    let agent = CliAgentTools::new(RunnerConfig::default()).with_sock_path(dead);
    let local = new_shared_state();
    let mcp = McpServer::new(
        ToolContext::new(local.clone(), RunnerConfig::default()).with_agent(Arc::new(agent)),
    );
    let res = mcp
        .handle_value(call(
            1,
            "reserve_host_resources",
            serde_json::json!({
                "cores": 2.0, "ram_gb": 2.0,
                "duration_minutes": 10, "reason": "offline",
            }),
        ))
        .await
        .expect("response");
    assert!(res.get("error").is_none(), "fallback must succeed: {res}");
    let out = content_text(&res);
    assert_eq!(out["reason"], "offline");
    assert_eq!(local.read().await.reservations().len(), 1);
}

#[tokio::test]
async fn cloud_capacity_denial_matches_local_shape() {
    // Zero spend cap: denial without provisioning on either path.
    // The daemon pool is unset here, so the arm denies before touching
    // any provider API.
    let h = DaemonHarness::new("mcp-ipc-cloud").await;
    let out = h
        .tool(
            1,
            "request_cloud_capacity",
            serde_json::json!({
                "provider": "digitalocean", "max_instances": 2,
                "duration_hours": 1.0, "reason": "burst",
            }),
        )
        .await;
    assert_eq!(out["approved"], false);
    assert!(out["reason"].as_str().unwrap().contains("cloud"));
    assert!(h.daemon_state.read().await.cloud_nodes().is_empty());
}
