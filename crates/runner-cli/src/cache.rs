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
}
