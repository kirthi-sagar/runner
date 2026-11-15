//! MCP protocol tests: `tools/list` exposes all 7 admin tools and
//! `tools/call` executes them over JSON-RPC 2.0.

use runner::config::RunnerConfig;
use runner::governor::supervisor::new_shared_state;
use runner::mcp::server::McpServer;
use runner::mcp::tools::{ToolContext, ALL_TOOLS};

fn server() -> McpServer {
    McpServer::new(ToolContext::new(
        new_shared_state(),
        RunnerConfig::default(),
    ))
}

fn call(id: u64, method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

#[tokio::test]
async fn tools_list_returns_all_seven_tools() {
    let server = server();
    let res = server
        .handle_value(call(1, "tools/list", serde_json::json!({})))
        .await
        .expect("response");
    let tools = res["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ALL_TOOLS);
    for tool in tools {
        assert!(tool["description"].is_string(), "{}", tool["name"]);
        assert_eq!(tool["inputSchema"]["type"], "object");
    }
}

#[tokio::test]
async fn tools_call_ci_status_reports_host() {
    let server = server();
    let res = server
        .handle_value(call(
            2,
            "tools/call",
            serde_json::json!({ "name": "get_ci_status" }),
        ))
        .await
        .expect("response");
    let text = res["result"]["content"][0]["text"].as_str().unwrap();
    let body: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(body["status"], "healthy");
    assert!(body["host"]["psi_pressure"]["cpu_some_avg10"].is_number());
    assert!(body["concurrency"]["max_slots"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn tools_call_reserve_throttle_drain_cycle() {
    let server = server();
    // Reserve.
    let res = server
        .handle_value(call(
            3,
            "tools/call",
            serde_json::json!({ "name": "reserve_host_resources", "arguments": {
                "cores": 2.0, "ram_gb": 4.0,
                "duration_minutes": 10, "reason": "test" } }),
        ))
        .await
        .expect("response");
    let body: serde_json::Value =
        serde_json::from_str(res["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let id = body["reservation_id"].as_str().unwrap().to_string();

    // Throttle critical.
    let res = server
        .handle_value(call(
            4,
            "tools/call",
            serde_json::json!({ "name": "throttle_runner", "arguments": {
                "level": "critical", "duration_minutes": 5 } }),
        ))
        .await
        .expect("response");
    let body: serde_json::Value =
        serde_json::from_str(res["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["cpu_weight"], 1);

    // Drain + release.
    for (tool, args) in [
        (
            "drain_node",
            serde_json::json!({ "node_id": "n1", "reason": "t" }),
        ),
        (
            "release_host_resources",
            serde_json::json!({ "reservation_id": id }),
        ),
    ] {
        let res = server
            .handle_value(call(
                5,
                "tools/call",
                serde_json::json!({ "name": tool, "arguments": args }),
            ))
            .await
            .expect("response");
        assert!(res.get("error").is_none(), "{res}");
    }
}

#[tokio::test]
async fn tools_call_rejects_unknown_tool_and_bad_args() {
    let server = server();
    let res = server
        .handle_value(call(
            6,
            "tools/call",
            serde_json::json!({ "name": "nope", "arguments": {} }),
        ))
        .await
        .expect("response");
    assert_eq!(res["error"]["code"], -32601);

    let res = server
        .handle_value(call(
            7,
            "tools/call",
            serde_json::json!({ "name": "throttle_runner", "arguments": {
                "level": "mild", "duration_minutes": 5 } }),
        ))
        .await
        .expect("response");
    assert_eq!(res["error"]["code"], -32602);
}

#[tokio::test]
async fn cloud_capacity_denied_without_preapproved_budget() {
    let server = server();
    let res = server
        .handle_value(call(
            8,
            "tools/call",
            serde_json::json!({ "name": "request_cloud_capacity", "arguments": {
                "provider": "render", "max_instances": 2,
                "duration_hours": 1.0, "reason": "burst" } }),
        ))
        .await
        .expect("response");
    let body: serde_json::Value =
        serde_json::from_str(res["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["approved"], false);
}
