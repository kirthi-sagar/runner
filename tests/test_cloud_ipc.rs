//! Cloud IPC wiring: a live `IpcServer` on an isolated HOME socket
//! proves `runner cloud` methods and the MCP `manage_cloud_capacity`
//! tool reach real daemon state end to end. Single test, sequential
//! phases: parallel tests cannot share one daemon socket path.

use std::sync::Arc;

use runner::governor::supervisor::new_shared_state;
use runner::ipc::{ipc_call_with, IpcServer};
use runner::mcp::tools::{execute_tool, ToolContext, TOOL_MANAGE_CLOUD_CAPACITY};
use runner::mesh::cloud::CloudNode;
use runner_cli::agent::CliAgentTools;

fn node(id: &str) -> CloudNode {
    CloudNode {
        id: id.to_string(),
        provider: "digitalocean".to_string(),
        status: "active".to_string(),
        launched_at: 0,
        name: String::new(),
    }
}

#[tokio::test]
async fn cloud_ipc_and_mcp_reach_live_daemon_state() {
    // Isolated HOME keeps this off the production socket. This binary
    // holds no other HOME-sensitive assertions, so the process-wide
    // override is contained here.
    let home = std::env::temp_dir().join(format!("runner-cloud-ipc-{}", std::process::id()));
    std::fs::create_dir_all(home.join(".runner")).unwrap();
    std::env::set_var("HOME", &home);
    let sock = home.join(".runner").join("runner.sock");
    let _ = std::fs::remove_file(&sock);

    let state = new_shared_state();
    {
        let mut guard = state.write().await;
        guard.add_cloud_node(node("i-7"));
        guard.set_cloud_pool(runner::mesh::cloud::CloudPool::default(), 25.0);
    }
    let server = Arc::new(IpcServer::bind(&sock, state).await.unwrap());
    tokio::spawn(async move { server.serve().await });
    for _ in 0..50 {
        if ipc_call_with(&sock, "ping", None).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // Phase 1: raw `cloud_list` round-trips daemon state.
    let res = ipc_call_with(&sock, "cloud_list", None).await.unwrap();
    assert!(res.get("error").is_none(), "{res}");
    assert_eq!(res["result"]["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(res["result"]["max_monthly_spend_usd"], 25.0);

    // Phase 2: the real MCP agent impl reaches the same server. On
    // unix it resolves the HOME-isolated socket implicitly; Windows
    // has no HOME-derived pipe (production is a fixed name), so the
    // isolated endpoint is passed explicitly instead.
    let config = runner::config::RunnerConfig::default();
    let agent = CliAgentTools::new(config.clone());
    #[cfg(windows)]
    let agent = agent.with_sock_path(sock.clone());
    let ctx = ToolContext::new(new_shared_state(), config).with_agent(Arc::new(agent));
    let out = execute_tool(
        TOOL_MANAGE_CLOUD_CAPACITY,
        Some(&serde_json::json!({ "action": "list" })),
        &ctx,
    )
    .await
    .unwrap();
    assert_eq!(out["active_nodes"], 1);
    assert_eq!(out["nodes"][0]["id"], "i-7");
    assert_eq!(out["providers"], serde_json::json!([]));
    assert_eq!(out["spend_tracked"], false);
}
