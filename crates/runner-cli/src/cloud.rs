//! `runner cloud` Helpers: parse daemon `cloud_*` IPC results and
//! render them as text or JSON. Pure functions are unit-tested; the
//! thin IPC calls live in the `main.rs` command handlers.

use runner_core::mesh::cloud::{format_uptime, CloudNode};

/// One listed node with computed uptime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedNode {
    pub id: String,
    pub provider: String,
    pub status: String,
    pub uptime: String,
}

impl ListedNode {
    fn from_node(node: &CloudNode, now_secs: u64) -> Self {
        Self {
            id: node.id.clone(),
            provider: node.provider.clone(),
            status: node.status.clone(),
            uptime: format_uptime(node.uptime_secs(now_secs)),
        }
    }
}

/// Parse the `result` object of a `cloud_list` IPC response.
pub fn parse_list(result: &serde_json::Value, now_secs: u64) -> (Vec<ListedNode>, f64) {
    let nodes = result["nodes"].as_array().cloned().unwrap_or_default();
    let listed = nodes
        .iter()
        .filter_map(|v| serde_json::from_value::<CloudNode>(v.clone()).ok())
        .map(|n| ListedNode::from_node(&n, now_secs))
        .collect();
    let cap = result["max_monthly_spend_usd"].as_f64().unwrap_or(0.0);
    (listed, cap)
}

/// Render `cloud list` text output.
pub fn render_list_text(nodes: &[ListedNode], spend_cap: f64) -> String {
    let mut out = format!(
        "cloud nodes: {} (spend cap ${:.2}/mo, live spend untracked)\n",
        nodes.len(),
        spend_cap
    );
    for node in nodes {
        out.push_str(&format!(
            "  - {} [{}] {} up {}\n",
            node.id, node.provider, node.status, node.uptime
        ));
    }
    out
}

/// Render `cloud list` JSON output.
pub fn render_list_json(nodes: &[ListedNode], spend_cap: f64) -> String {
    let items: Vec<serde_json::Value> = nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.id, "provider": n.provider,
                "status": n.status, "uptime": n.uptime,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "nodes": items,
        "max_monthly_spend_usd": spend_cap,
        "spend_tracked": false,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// Extract the daemon error message from an IPC response, if any.
pub fn daemon_error(res: &serde_json::Value) -> Option<String> {
    res.get("error").map(|e| {
        e.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown daemon error")
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> CloudNode {
        CloudNode {
            id: id.to_string(),
            provider: "digitalocean".to_string(),
            status: "active".to_string(),
            launched_at: 1_000_000,
        }
    }

    #[test]
    fn parse_list_computes_uptime_and_cap() {
        let result = serde_json::json!({
            "nodes": [node("i-1"), {"id": "bogus"}],
            "max_monthly_spend_usd": 25.0,
        });
        let (listed, cap) = parse_list(&result, 1_000_000 + 125);
        assert_eq!(cap, 25.0);
        // Malformed entries are skipped, not fatal.
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "i-1");
        assert_eq!(listed[0].uptime, "2m");
    }

    #[test]
    fn renderers_cover_empty_and_populated() {
        let text = render_list_text(&[], 10.0);
        assert!(text.contains("cloud nodes: 0"));
        assert!(text.contains("$10.00/mo"));
        let nodes = vec![ListedNode {
            id: "i-9".to_string(),
            provider: "render".to_string(),
            status: "active".to_string(),
            uptime: "1h05m".to_string(),
        }];
        let text = render_list_text(&nodes, 10.0);
        assert!(text.contains("i-9 [render] active up 1h05m"));
        let json: serde_json::Value =
            serde_json::from_str(&render_list_json(&nodes, 10.0)).unwrap();
        assert_eq!(json["nodes"][0]["id"], "i-9");
        assert_eq!(json["spend_tracked"], false);
    }

    #[test]
    fn daemon_error_extracts_message() {
        let ok = serde_json::json!({ "result": {} });
        assert_eq!(daemon_error(&ok), None);
        let err = serde_json::json!({ "error": { "code": -32602, "message": "nope" } });
        assert_eq!(daemon_error(&err).as_deref(), Some("nope"));
    }
}
