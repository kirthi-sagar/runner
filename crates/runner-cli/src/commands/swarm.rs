//! `runner swarm`: list daemon swarms and terminate them. The
//! daemon owns swarm state; this module only parses its JSON and
//! renders it (pure for tests).

use serde::{Deserialize, Serialize};

/// One daemon swarm row, parsed defensively (missing keys default;
/// the daemon contract owns the truth).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmRow {
    #[serde(default)]
    pub swarm_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub member_count: usize,
    #[serde(default)]
    pub waiting_count: usize,
    #[serde(default)]
    pub active_jobs: usize,
    #[serde(default)]
    pub cpu_weight_allocated: f64,
    #[serde(default)]
    pub cpu_weight_max: f64,
    #[serde(default)]
    pub memory_allocated_mb: u64,
    #[serde(default)]
    pub memory_max_mb: u64,
    #[serde(default)]
    pub spent_usd: f64,
    #[serde(default)]
    pub spend_cap_usd: f64,
}

/// Parse the `swarm_list` result object (`{ "swarms": [...] }`).
pub fn parse_list(result: &serde_json::Value) -> Vec<SwarmRow> {
    result
        .get("swarms")
        .and_then(|swarms| swarms.as_array())
        .map(|swarms| {
            swarms
                .iter()
                .filter_map(|row| serde_json::from_value(row.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Human-readable swarm table (sorted by the daemon).
pub fn render_list_text(rows: &[SwarmRow]) -> String {
    if rows.is_empty() {
        return "no active swarms\n".to_string();
    }
    let mut out = String::new();
    for row in rows {
        let spend = if row.spend_cap_usd > 0.0 {
            format!("${:.2}/${:.2}", row.spent_usd, row.spend_cap_usd)
        } else {
            format!("${:.2}/unenforced", row.spent_usd)
        };
        out.push_str(&format!(
            "{} [{}] members={} waiting={} jobs={} cpu={:.1}/{:.0} mem={}/{} spend={}\n",
            row.swarm_id,
            row.status,
            row.member_count,
            row.waiting_count,
            row.active_jobs,
            row.cpu_weight_allocated,
            row.cpu_weight_max,
            crate::cache::format_bytes(row.memory_allocated_mb * 1024 * 1024),
            crate::cache::format_bytes(row.memory_max_mb * 1024 * 1024),
            spend,
        ));
    }
    out
}

/// JSON swarm listing.
pub fn render_list_json(rows: &[SwarmRow]) -> String {
    serde_json::to_string_pretty(rows).unwrap_or_else(|_| "[]".to_string())
}

/// Parsed `swarm_kill` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillOutcome {
    pub swarm_id: String,
    pub status: String,
    pub slices_reclaimed: usize,
    pub jobs_abandoned: usize,
}

/// Parse the `swarm_kill` result object.
pub fn parse_kill(result: &serde_json::Value) -> KillOutcome {
    KillOutcome {
        swarm_id: result
            .get("swarm_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        status: result
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("terminated")
            .to_string(),
        slices_reclaimed: result
            .get("slices_reclaimed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
        jobs_abandoned: result
            .get("jobs_abandoned")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
    }
}

/// Human-readable kill confirmation.
pub fn render_kill_text(outcome: &KillOutcome) -> String {
    format!(
        "swarm {} {} ({} slices reclaimed, {} jobs abandoned)\n",
        outcome.swarm_id, outcome.status, outcome.slices_reclaimed, outcome.jobs_abandoned
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> SwarmRow {
        SwarmRow {
            swarm_id: "alpha".to_string(),
            status: "active".to_string(),
            member_count: 3,
            waiting_count: 1,
            active_jobs: 2,
            cpu_weight_allocated: 3.0,
            cpu_weight_max: 8.0,
            memory_allocated_mb: 4096,
            memory_max_mb: 16384,
            spent_usd: 1.25,
            spend_cap_usd: 25.0,
        }
    }

    #[test]
    fn list_renders_text_json_and_empty() {
        let rows = vec![row()];
        let text = render_list_text(&rows);
        assert!(text.contains("alpha"), "{text}");
        assert!(text.contains("[active]"), "{text}");
        assert!(text.contains("members=3"), "{text}");
        assert!(text.contains("waiting=1"), "{text}");
        assert!(text.contains("jobs=2"), "{text}");
        assert!(text.contains("cpu=3.0/8"), "{text}");
        assert!(text.contains("$1.25/$25.00"), "{text}");
        let json: serde_json::Value = serde_json::from_str(&render_list_json(&rows)).unwrap();
        assert_eq!(json[0]["swarm_id"], "alpha");
        assert_eq!(render_list_text(&[]), "no active swarms\n");
        assert_eq!(render_list_json(&[]), "[]");
    }

    #[test]
    fn list_shows_unenforced_spend() {
        let mut rows = vec![row()];
        rows[0].spend_cap_usd = 0.0;
        let text = render_list_text(&rows);
        assert!(text.contains("$1.25/unenforced"), "{text}");
    }

    #[test]
    fn parse_list_skips_corrupt_rows() {
        let value = serde_json::json!({
            "swarms": [
                { "swarm_id": "ok", "status": "active" },
                { "swarm_id": 42 },
                "garbage",
            ]
        });
        let rows = parse_list(&value);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].swarm_id, "ok");
        assert_eq!(rows[0].member_count, 0);
        assert!(parse_list(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn kill_parses_and_renders() {
        let outcome = parse_kill(&serde_json::json!({
            "swarm_id": "alpha",
            "status": "terminated",
            "slices_reclaimed": 2,
            "jobs_abandoned": 1,
        }));
        assert_eq!(
            outcome,
            KillOutcome {
                swarm_id: "alpha".to_string(),
                status: "terminated".to_string(),
                slices_reclaimed: 2,
                jobs_abandoned: 1,
            }
        );
        let text = render_kill_text(&outcome);
        assert!(text.contains("alpha terminated"), "{text}");
        assert!(text.contains("2 slices reclaimed"), "{text}");
        assert!(text.contains("1 jobs abandoned"), "{text}");
        // Missing keys default; unknown ids still render.
        let outcome = parse_kill(&serde_json::json!({}));
        assert_eq!(outcome.status, "terminated");
    }
}
