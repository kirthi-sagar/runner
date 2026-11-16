//! MCP agent-tools tests: the three Phase 8 tools dispatched through
//! the REAL `runner-cli` implementation (trait wiring proof — core unit
//! tests cover the same contract with stubs).

use std::sync::Arc;

use runner::config::RunnerConfig;
use runner::governor::supervisor::new_shared_state;
use runner::mcp::server::McpServer;
use runner::mcp::tools::ToolContext;
use runner_cli::agent::CliAgentTools;

fn server() -> McpServer {
    let config = RunnerConfig::default();
    let ctx = ToolContext::new(new_shared_state(), config.clone())
        .with_agent(Arc::new(CliAgentTools::new(config)));
    McpServer::new(ctx)
}

fn call(id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

async fn call_body(
    server: &McpServer,
    id: u64,
    name: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    let res = server
        .handle_value(call(
            id,
            "tools/call",
            serde_json::json!({ "name": name, "arguments": args }),
        ))
        .await
        .expect("response");
    assert!(res.get("error").is_none(), "unexpected error: {res}");
    let text = res["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn diagnose_system_returns_live_checks() {
    let body = call_body(&server(), 1, "diagnose_system", serde_json::json!({})).await;
    assert!(body["ok"].is_boolean());
    let checks = body["checks"].as_array().unwrap();
    assert!(!checks.is_empty());
    assert!(checks.iter().any(|c| c["name"] == "kernel"));
}

#[tokio::test]
async fn test_provider_local_ok_and_unknown_rejected() {
    let server = server();
    let body = call_body(
        &server,
        2,
        "test_provider",
        serde_json::json!({ "provider": "local" }),
    )
    .await;
    assert_eq!(body["provider"], "local");
    assert_eq!(body["ok"], true);

    let res = server
        .handle_value(call(
            3,
            "tools/call",
            serde_json::json!({ "name": "test_provider", "arguments": { "provider": "jenkins" } }),
        ))
        .await
        .expect("response");
    assert_eq!(res["error"]["code"], -32602);
}

#[tokio::test]
async fn exec_command_captures_output_and_enforces_timeout() {
    let server = server();
    let body = call_body(
        &server,
        4,
        "exec_command",
        serde_json::json!({ "command": ["echo", "hi"], "env": { "A": "b" } }),
    )
    .await;
    assert_eq!(body["code"], 0);
    assert_eq!(body["stdout"], "hi\n");
    assert_eq!(body["timeout"], false);
    assert!(body["elapsed_secs"].as_f64().unwrap() >= 0.0);

    let body = call_body(
        &server,
        5,
        "exec_command",
        serde_json::json!({ "command": ["sleep", "30"], "timeout_secs": 1 }),
    )
    .await;
    assert_eq!(body["timeout"], true);
    assert!(body.get("code").is_none());
}
