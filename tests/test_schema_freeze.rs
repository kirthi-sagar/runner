//! v1.0 schema freeze: pin every machine-readable contract so any
//! shape change breaks the build until docs (`docs/mcp.md`,
//! `docs/cli-json.md`) are updated alongside. Key sets are asserted
//! as exact-or-subset (optional fields may be absent per host), never
//! as loose `contains` checks.

use std::collections::HashSet;

use runner::config::RunnerConfig;
use runner::governor::supervisor::new_shared_state;
use runner::mcp::server::McpServer;
use runner::mcp::tools::ToolContext;

fn keys(value: &serde_json::Value) -> HashSet<String> {
    value.as_object().expect("object").keys().cloned().collect()
}

/// Assert `value` carries exactly `required`, plus only allowlisted
/// `optional` keys. New keys fail; absent optionals pass (host-dependent).
fn assert_key_set(value: &serde_json::Value, required: &[&str], optional: &[&str]) {
    let got = keys(value);
    let required: HashSet<String> = required.iter().map(|s| s.to_string()).collect();
    let allowed: HashSet<String> = required
        .union(&optional.iter().map(|s| s.to_string()).collect())
        .cloned()
        .collect();
    for key in &required {
        assert!(got.contains(key), "missing key: {key}");
    }
    for key in &got {
        assert!(allowed.contains(key), "unfrozen new key: {key}");
    }
}

#[tokio::test]
async fn mcp_tools_list_pins_twelve_names_and_schemas() {
    let server = McpServer::new(ToolContext::new(
        new_shared_state(),
        RunnerConfig::default(),
    ));
    let res = server
        .handle_value(serde_json::json!(
            { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }
        ))
        .await
        .expect("response");
    let tools = res["result"]["tools"].as_array().unwrap();
    // Literal names (not ALL_TOOLS): additions/removals must break here.
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "get_ci_status",
            "get_fleet_topology",
            "reserve_host_resources",
            "release_host_resources",
            "throttle_runner",
            "request_cloud_capacity",
            "drain_node",
            "diagnose_system",
            "test_provider",
            "exec_command",
            "manage_cloud_capacity",
            "get_cache_stats",
        ]
    );
    // Exact served input schemas: any drift breaks the freeze.
    let empty = serde_json::json!({"type": "object", "properties": {}, "required": []});
    let mut expected = std::collections::HashMap::new();
    expected.insert("get_ci_status", empty.clone());
    expected.insert("get_fleet_topology", empty.clone());
    expected.insert("get_cache_stats", empty.clone());
    expected.insert(
        "reserve_host_resources",
        serde_json::json!({"type": "object",
            "properties": {
                "cores": { "type": "number" },
                "ram_gb": { "type": "number" },
                "duration_minutes": { "type": "integer" },
                "reason": { "type": "string" }},
            "required": ["cores", "ram_gb", "duration_minutes"]}),
    );
    expected.insert(
        "release_host_resources",
        serde_json::json!({"type": "object",
            "properties": { "reservation_id": { "type": "string" }},
            "required": ["reservation_id"]}),
    );
    expected.insert(
        "throttle_runner",
        serde_json::json!({"type": "object",
            "properties": {
                "level": { "type": "string", "enum": ["warning", "critical"] },
                "duration_minutes": { "type": "integer" }},
            "required": ["level", "duration_minutes"]}),
    );
    expected.insert(
        "request_cloud_capacity",
        serde_json::json!({"type": "object",
            "properties": {
                "provider": { "type": "string", "enum": ["digitalocean", "render"] },
                "max_instances": { "type": "integer" },
                "duration_hours": { "type": "number" },
                "reason": { "type": "string" }},
            "required": ["provider", "max_instances", "duration_hours", "reason"]}),
    );
    expected.insert(
        "drain_node",
        serde_json::json!({"type": "object",
            "properties": {
                "node_id": { "type": "string" },
                "reason": { "type": "string" }},
            "required": ["node_id", "reason"]}),
    );
    expected.insert(
        "diagnose_system",
        serde_json::json!({"type": "object",
            "properties": {
                "egress": { "type": "boolean" },
                "enterprise": { "type": "boolean" }},
            "required": []}),
    );
    expected.insert(
        "test_provider",
        serde_json::json!({"type": "object",
            "properties": {
                "provider": { "type": "string",
                    "enum": ["github", "gitlab", "bitbucket", "local"] }},
            "required": ["provider"]}),
    );
    expected.insert(
        "exec_command",
        serde_json::json!({"type": "object",
            "properties": {
                "command": { "type": "array", "items": { "type": "string" } },
                "timeout_secs": { "type": "integer" },
                "env": { "type": "object" }},
            "required": ["command"]}),
    );
    expected.insert(
        "manage_cloud_capacity",
        serde_json::json!({"type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["list", "terminate", "purge"] },
                "instance_id": { "type": "string" }},
            "required": ["action"]}),
    );
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        assert!(tool["description"].is_string(), "{name}");
        assert_eq!(
            &tool["inputSchema"], &expected[name],
            "schema drift for {name}"
        );
    }
}

#[test]
fn status_json_pins_key_sets() {
    let report = runner::status::status_report();
    let value = serde_json::to_value(&report).unwrap();
    // `governor_error` appears only on degraded hosts; `forges` only
    // on state-enriched (daemon) reports.
    assert_key_set(
        &value,
        &[
            "status",
            "version",
            "host",
            "concurrency",
            "active_jobs",
            "mesh_nodes",
        ],
        &["governor_error", "forges"],
    );
    assert_key_set(
        &value["host"],
        &[
            "total_cores",
            "physical_cores",
            "available_cores_for_ci",
            "total_memory_bytes",
            "available_memory_bytes",
            "psi_pressure",
            "cgroup_weight",
            "temperature_c",
            "discharging",
        ],
        &[],
    );
    assert_key_set(
        &value["host"]["psi_pressure"],
        &[
            "cpu_some_avg10",
            "memory_some_avg10",
            "io_full_avg10",
            "cpu_level",
        ],
        &[],
    );
    assert_key_set(
        &value["concurrency"],
        &[
            "max_slots",
            "active_slots",
            "queued_github_jobs",
            "afk_boost",
            "afk_mode",
        ],
        &[],
    );
}

#[test]
fn doctor_json_pins_shape() {
    use runner_cli::doctor::{render_json, Check, Status};

    let checks = vec![
        Check {
            name: "cache".to_string(),
            status: Status::Pass,
            detail: "proxy on 127.0.0.1:8787".to_string(),
        },
        Check {
            name: "guards".to_string(),
            status: Status::Warn,
            detail: "power battery".to_string(),
        },
    ];
    let value: serde_json::Value = serde_json::from_str(&render_json(&checks)).unwrap();
    assert_key_set(&value, &["checks", "ok"], &[]);
    assert_eq!(value["ok"], true);
    for item in value["checks"].as_array().unwrap() {
        assert_key_set(item, &["name", "status", "detail"], &[]);
    }
    assert_eq!(value["checks"][0]["status"], "pass");
    assert_eq!(value["checks"][1]["status"], "warn");
}

#[test]
fn cache_stats_json_pins_keys() {
    use runner_cli::cache::{render_stats_json, CacheStats};

    let stats = CacheStats {
        entries: 3,
        size_bytes: 2048,
        hits: 9,
        misses: 1,
        hit_ratio: 0.9,
        bytes_served: 1024,
        bytes_uploaded: 2048,
        remote_hits: 2,
        remote_bytes_imported: 512,
        remote_bytes_served: 256,
    };
    let value: serde_json::Value = serde_json::from_str(&render_stats_json(&stats)).unwrap();
    assert_key_set(
        &value,
        &[
            "entries",
            "size_bytes",
            "hits",
            "misses",
            "hit_ratio",
            "bytes_served",
            "bytes_uploaded",
            "remote_hits",
            "remote_bytes_imported",
            "remote_bytes_served",
        ],
        &[],
    );
}

#[test]
fn cloud_list_json_pins_keys() {
    use runner_cli::cloud::{render_list_json, CloudList, ListedNode};

    let list = CloudList {
        nodes: vec![ListedNode {
            id: "i-1".to_string(),
            provider: "digitalocean".to_string(),
            status: "active".to_string(),
            uptime: "3m".to_string(),
        }],
        spend_usd: 1.5,
        cap_usd: 25.0,
        tracked: true,
        spend_error: None,
    };
    let value: serde_json::Value = serde_json::from_str(&render_list_json(&list)).unwrap();
    // The spend surface: nodes plus ledgered month spend vs cap.
    assert_key_set(
        &value,
        &[
            "nodes",
            "spend_usd",
            "max_monthly_spend_usd",
            "spend_tracked",
            "spend_error",
        ],
        &[],
    );
    assert_key_set(
        &value["nodes"][0],
        &["id", "provider", "status", "uptime"],
        &[],
    );
}
