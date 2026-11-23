//! `runner cache` rendering: stats shapes parsed from the daemon's
//! `cache_stats` IPC result plus text/JSON renderers.

/// Cache counters snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheStats {
    pub entries: usize,
    pub size_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: f64,
    pub bytes_served: u64,
    pub bytes_uploaded: u64,
    pub remote_hits: u64,
    pub remote_bytes_imported: u64,
    pub remote_bytes_served: u64,
}

/// Parse the `result` object of a `cache_stats` IPC response.
pub fn parse_stats(result: &serde_json::Value) -> CacheStats {
    let hits = result["hits"].as_u64().unwrap_or(0);
    let misses = result["misses"].as_u64().unwrap_or(0);
    let total = hits + misses;
    CacheStats {
        entries: result["entries"].as_u64().unwrap_or(0) as usize,
        size_bytes: result["size_bytes"].as_u64().unwrap_or(0),
        hits,
        misses,
        hit_ratio: result["hit_ratio"].as_f64().unwrap_or(if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }),
        bytes_served: result["bytes_served"].as_u64().unwrap_or(0),
        bytes_uploaded: result["bytes_uploaded"].as_u64().unwrap_or(0),
        remote_hits: result["remote_hits"].as_u64().unwrap_or(0),
        remote_bytes_imported: result["remote_bytes_imported"].as_u64().unwrap_or(0),
        remote_bytes_served: result["remote_bytes_served"].as_u64().unwrap_or(0),
    }
}

/// Human byte count: `512 B`, `1.5 KB`, `3.2 GB`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Render `cache stats` text output.
pub fn render_stats_text(stats: &CacheStats) -> String {
    format!(
        "cache entries: {} ({})\nhits: {}  misses: {}  hit ratio: {:.1}%\nbandwidth saved: {} served, {} uploaded\nmesh: {} peer hits, {} imported, {} served to peers\n",
        stats.entries,
        format_bytes(stats.size_bytes),
        stats.hits,
        stats.misses,
        stats.hit_ratio * 100.0,
        format_bytes(stats.bytes_served),
        format_bytes(stats.bytes_uploaded),
        stats.remote_hits,
        format_bytes(stats.remote_bytes_imported),
        format_bytes(stats.remote_bytes_served),
    )
}

/// Render `cache stats` JSON output.
pub fn render_stats_json(stats: &CacheStats) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "entries": stats.entries,
        "size_bytes": stats.size_bytes,
        "hits": stats.hits,
        "misses": stats.misses,
        "hit_ratio": stats.hit_ratio,
        "bytes_served": stats.bytes_served,
        "bytes_uploaded": stats.bytes_uploaded,
        "remote_hits": stats.remote_hits,
        "remote_bytes_imported": stats.remote_bytes_imported,
        "remote_bytes_served": stats.remote_bytes_served,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// One inspected LAN cache peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePeerInfo {
    pub node_id: String,
    pub base_url: String,
    pub port: Option<u16>,
    pub cache_enabled: bool,
    pub last_seen_secs: u64,
}

/// Parse the `result` object of a `cache_peers` IPC response.
pub fn parse_peers(result: &serde_json::Value) -> Vec<CachePeerInfo> {
    result["peers"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| CachePeerInfo {
                    node_id: row["node_id"].as_str().unwrap_or("").to_string(),
                    base_url: row["base_url"].as_str().unwrap_or("").to_string(),
                    port: row["port"].as_u64().and_then(|p| u16::try_from(p).ok()),
                    cache_enabled: row["cache_enabled"].as_bool().unwrap_or(false),
                    last_seen_secs: row["last_seen_secs"].as_u64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Human heartbeat age: `3s`, `2m`, `1h`.
pub fn format_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Render `cache peers` text output (aligned table, `-` for blanks).
pub fn render_peers_text(peers: &[CachePeerInfo]) -> String {
    if peers.is_empty() {
        return "no LAN cache peers discovered\n".to_string();
    }
    let mut out = format!(
        "{:<24} {:<28} {:<6} {:<7} {:<6}\n",
        "NODE ID", "BASE URL", "PORT", "CACHE", "SEEN"
    );
    for peer in peers {
        out.push_str(&format!(
            "{:<24} {:<28} {:<6} {:<7} {:<6}\n",
            truncate(&peer.node_id, 24),
            truncate(display_or_dash(&peer.base_url), 28),
            peer.port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            if peer.cache_enabled { "yes" } else { "no" },
            format_age(peer.last_seen_secs),
        ));
    }
    out
}

fn display_or_dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        // Char-boundary safe: peer names arrive over unauthenticated mDNS.
        let head: String = value.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

/// Render `cache peers` JSON output.
pub fn render_peers_json(peers: &[CachePeerInfo]) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "peers": peers
            .iter()
            .map(|p| serde_json::json!({
                "node_id": p.node_id,
                "base_url": p.base_url,
                "port": p.port,
                "cache_enabled": p.cache_enabled,
                "last_seen_secs": p.last_seen_secs,
            }))
            .collect::<Vec<_>>(),
    }))
    .unwrap_or_else(|_| "{\"peers\":[]}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_parse_render_roundtrip() {
        let stats = parse_stats(&serde_json::json!({
            "entries": 3,
            "size_bytes": 2048,
            "hits": 9,
            "misses": 1,
            "hit_ratio": 0.9,
            "bytes_served": 3072,
            "bytes_uploaded": 2048,
            "remote_hits": 2,
            "remote_bytes_imported": 1024,
            "remote_bytes_served": 512,
        }));
        assert_eq!(stats.entries, 3);
        assert_eq!(stats.remote_hits, 2);
        let text = render_stats_text(&stats);
        assert!(text.contains("cache entries: 3 (2.0 KB)"), "got: {text}");
        assert!(text.contains("hit ratio: 90.0%"), "got: {text}");
        assert!(text.contains("3.0 KB served"), "got: {text}");
        assert!(text.contains("2 peer hits"), "got: {text}");
        let json: serde_json::Value = serde_json::from_str(&render_stats_json(&stats)).unwrap();
        assert_eq!(json["hit_ratio"], 0.9);
        assert_eq!(json["remote_bytes_imported"], 1024);
        // Missing keys default to a zero snapshot.
        let empty = parse_stats(&serde_json::json!({}));
        assert_eq!((empty.entries, empty.hits, empty.misses), (0, 0, 0));
        assert_eq!(empty.hit_ratio, 0.0);
    }

    #[test]
    fn byte_units_scale() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn peers_parse_render_roundtrip() {
        let peers = parse_peers(&serde_json::json!({
            "peers": [
                {
                    "node_id": "node-a",
                    "base_url": "http://10.0.0.2:8787",
                    "port": 8787,
                    "cache_enabled": true,
                    "last_seen_secs": 3,
                },
                {
                    "node_id": "legacy._runner._tcp.local.",
                    "base_url": "",
                    "port": null,
                    "cache_enabled": false,
                    "last_seen_secs": 125,
                },
            ],
        }));
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].port, Some(8787));
        assert_eq!(peers[1].port, None);
        let text = render_peers_text(&peers);
        assert!(text.contains("NODE ID"), "got: {text}");
        assert!(text.contains("node-a"), "got: {text}");
        assert!(text.contains("http://10.0.0.2:8787"), "got: {text}");
        assert!(text.contains("yes"), "got: {text}");
        assert!(text.contains("3s"), "got: {text}");
        assert!(text.contains("2m"), "got: {text}");
        assert!(text.contains("no"), "got: {text}");
        let json: serde_json::Value = serde_json::from_str(&render_peers_json(&peers)).unwrap();
        assert_eq!(json["peers"][0]["node_id"], "node-a");
        assert_eq!(json["peers"][0]["port"], 8787);
        assert!(json["peers"][1]["port"].is_null());
        // Missing keys default to an empty list; empty renders kindly.
        assert!(parse_peers(&serde_json::json!({})).is_empty());
        assert!(render_peers_text(&[]).contains("no LAN cache peers"));
        let json: serde_json::Value = serde_json::from_str(&render_peers_json(&[])).unwrap();
        assert_eq!(json["peers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn peers_text_truncates_safely() {
        // Overlong + non-ASCII names truncate on char boundaries (never panic).
        let peers = vec![CachePeerInfo {
            node_id: "node-".to_string() + &"é".repeat(40),
            base_url: "http://10.0.0.2:8787/".to_string() + &"x".repeat(60),
            port: Some(8787),
            cache_enabled: true,
            last_seen_secs: 3700,
        }];
        let text = render_peers_text(&peers);
        assert!(text.contains("…"), "got: {text}");
        assert!(text.contains("1h"), "got: {text}");
        assert_eq!(format_age(0), "0s");
        assert_eq!(format_age(59), "59s");
        assert_eq!(format_age(60), "1m");
        assert_eq!(format_age(3600), "1h");
    }
}
