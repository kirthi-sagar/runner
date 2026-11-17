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

/// Parsed `cloud_list` result: nodes, month spend, cap, tracking flag.
pub struct CloudList {
    pub nodes: Vec<ListedNode>,
    pub spend_usd: f64,
    pub cap_usd: f64,
    pub tracked: bool,
    pub spend_error: Option<String>,
}

/// Parse the `result` object of a `cloud_list` IPC response.
pub fn parse_list(result: &serde_json::Value, now_secs: u64) -> CloudList {
    let nodes = result["nodes"].as_array().cloned().unwrap_or_default();
    let listed = nodes
        .iter()
        .filter_map(|v| serde_json::from_value::<CloudNode>(v.clone()).ok())
        .map(|n| ListedNode::from_node(&n, now_secs))
        .collect();
    CloudList {
        nodes: listed,
        spend_usd: result["spend_usd"].as_f64().unwrap_or(0.0),
        cap_usd: result["max_monthly_spend_usd"].as_f64().unwrap_or(0.0),
        tracked: result["spend_tracked"].as_bool().unwrap_or(false),
        spend_error: result["spend_error"].as_str().map(str::to_string),
    }
}

/// Render `cloud list` text output.
pub fn render_list_text(list: &CloudList) -> String {
    let spend = if let Some(err) = &list.spend_error {
        format!("spend ledger error: {err}")
    } else if list.tracked {
        format!("spend ${:.2}", list.spend_usd)
    } else {
        "live spend untracked".to_string()
    };
    let mut out = format!(
        "cloud nodes: {} ({spend} / cap ${:.2}/mo)\n",
        list.nodes.len(),
        list.cap_usd
    );
    for node in &list.nodes {
        out.push_str(&format!(
            "  - {} [{}] {} up {}\n",
            node.id, node.provider, node.status, node.uptime
        ));
    }
    out
}

/// Render `cloud list` JSON output.
pub fn render_list_json(list: &CloudList) -> String {
    let items: Vec<serde_json::Value> = list
        .nodes
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
        "spend_usd": list.spend_usd,
        "max_monthly_spend_usd": list.cap_usd,
        "spend_tracked": list.tracked,
        "spend_error": list.spend_error,
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
            name: String::new(),
        }
    }

    fn listed(id: &str) -> ListedNode {
        ListedNode {
            id: id.to_string(),
            provider: "render".to_string(),
            status: "active".to_string(),
            uptime: "1h05m".to_string(),
        }
    }

    #[test]
    fn parse_list_computes_uptime_cap_and_spend() {
        let result = serde_json::json!({
            "nodes": [node("i-1"), {"id": "bogus"}],
            "max_monthly_spend_usd": 25.0,
            "spend_usd": 1.5,
            "spend_tracked": true,
        });
        let list = parse_list(&result, 1_000_000 + 125);
        assert_eq!(list.cap_usd, 25.0);
        assert_eq!(list.spend_usd, 1.5);
        assert!(list.tracked);
        // Malformed entries are skipped, not fatal.
        assert_eq!(list.nodes.len(), 1);
        assert_eq!(list.nodes[0].id, "i-1");
        assert_eq!(list.nodes[0].uptime, "2m");
        // Old daemons without the new keys parse as untracked.
        let legacy = parse_list(&serde_json::json!({"nodes": []}), 0);
        assert!(!legacy.tracked);
        assert_eq!(legacy.spend_usd, 0.0);
    }

    #[test]
    fn ledger_error_renders_honestly() {
        let list = parse_list(
            &serde_json::json!({
                "nodes": [],
                "max_monthly_spend_usd": 25.0,
                "spend_usd": 0.0,
                "spend_tracked": true,
                "spend_error": "cannot parse ledger",
            }),
            0,
        );
        assert_eq!(list.spend_error.as_deref(), Some("cannot parse ledger"));
        let text = render_list_text(&list);
        assert!(text.contains("spend ledger error"), "got: {text}");
        assert!(!text.contains("live spend untracked"));
        let json: serde_json::Value = serde_json::from_str(&render_list_json(&list)).unwrap();
        assert_eq!(json["spend_error"], "cannot parse ledger");
    }

    #[test]
    fn renderers_cover_empty_populated_and_untracked() {
        let empty = CloudList {
            nodes: vec![],
            spend_usd: 0.0,
            cap_usd: 10.0,
            tracked: true,
            spend_error: None,
        };
        let text = render_list_text(&empty);
        assert!(text.contains("cloud nodes: 0"));
        assert!(text.contains("spend $0.00 / cap $10.00/mo"));
        let full = CloudList {
            nodes: vec![listed("i-9")],
            spend_usd: 0.05,
            cap_usd: 10.0,
            tracked: true,
            spend_error: None,
        };
        let text = render_list_text(&full);
        assert!(text.contains("i-9 [render] active up 1h05m"));
        assert!(text.contains("spend $0.05"));
        let json: serde_json::Value = serde_json::from_str(&render_list_json(&full)).unwrap();
        assert_eq!(json["nodes"][0]["id"], "i-9");
        assert_eq!(json["spend_usd"], 0.05);
        assert_eq!(json["spend_tracked"], true);
        let untracked = CloudList {
            tracked: false,
            ..full
        };
        assert!(render_list_text(&untracked).contains("live spend untracked"));
    }

    #[test]
    fn daemon_error_extracts_message() {
        let ok = serde_json::json!({ "result": {} });
        assert_eq!(daemon_error(&ok), None);
        let err = serde_json::json!({ "error": { "code": -32602, "message": "nope" } });
        assert_eq!(daemon_error(&err).as_deref(), Some("nope"));
    }
}
