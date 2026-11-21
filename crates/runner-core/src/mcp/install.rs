//! Agent auto-registration: install the runner MCP server entry into
//! standard agent config files (merge-only, never clobbers), or print the
//! JSON snippet when the destination is missing or unwritable.

use std::path::{Path, PathBuf};

/// Agent config target for `runner mcp install`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTarget {
    /// Cursor user config (`~/.cursor/mcp.json`).
    Cursor,
    /// Claude Desktop config (`~/.config/Claude/claude_desktop_config.json`).
    Claude,
    /// No file: print the snippet to stdout.
    Generic,
}

impl McpTarget {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "cursor" => Ok(Self::Cursor),
            "claude" => Ok(Self::Claude),
            "generic" => Ok(Self::Generic),
            other => Err(format!(
                "unknown mcp target: '{other}' (want cursor|claude|generic)"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::Claude => "claude",
            Self::Generic => "generic",
        }
    }
}

/// Config file for file-backed targets (`None` = stdout snippet).
pub fn default_target_path(target: McpTarget) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    match target {
        McpTarget::Cursor => Some(home.join(".cursor").join("mcp.json")),
        McpTarget::Claude => Some(
            home.join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
        ),
        McpTarget::Generic => None,
    }
}

/// Absolute path of this binary (falls back to `runner` on PATH).
pub fn current_exe_string() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| "runner".to_string())
}

/// The `runner` MCP server entry for an `mcpServers` map.
pub fn server_entry(exe: &str) -> serde_json::Value {
    serde_json::json!({ "command": exe, "args": ["mcp"] })
}

/// Full snippet (`{"mcpServers": {"runner": ...}}`) as pretty JSON.
pub fn snippet_json(exe: &str) -> String {
    let doc = serde_json::json!({ "mcpServers": { "runner": server_entry(exe) } });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Merge the runner entry into a config file, preserving every other
/// server. Creates parents; backs up an existing file to `<file>.bak`.
/// Refuses (without touching anything) when the file holds invalid JSON
/// or a non-object `mcpServers`. Returns a human-readable note.
pub fn install_to_file(path: &Path, exe: &str) -> Result<String, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut doc = if path.exists() {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str::<serde_json::Value>(&text).map_err(|e| {
            format!(
                "{} holds invalid JSON ({e}); left untouched",
                path.display()
            )
        })?
    } else {
        serde_json::Value::Null
    };
    if doc.is_null() {
        doc = serde_json::json!({});
    }
    let servers = doc
        .as_object_mut()
        .and_then(|map| {
            map.entry("mcpServers".to_string())
                .or_insert(serde_json::json!({}))
                .as_object_mut()
        })
        .ok_or_else(|| {
            format!(
                "{} has a non-object document or mcpServers; left untouched",
                path.display()
            )
        })?;
    servers.insert("runner".to_string(), server_entry(exe));
    if path.exists() {
        let backup = path.with_extension("json.bak");
        std::fs::copy(path, &backup).map_err(|e| format!("back up {}: {e}", path.display()))?;
    }
    let text = serde_json::to_string_pretty(&doc).map_err(|e| format!("render JSON: {e}"))?;
    std::fs::write(path, format!("{text}\n"))
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(format!(
        "registered runner MCP server in {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_and_resolve() {
        assert_eq!(McpTarget::from_name("cursor").unwrap(), McpTarget::Cursor);
        assert_eq!(McpTarget::from_name("Claude").unwrap(), McpTarget::Claude);
        assert_eq!(McpTarget::from_name("GENERIC").unwrap(), McpTarget::Generic);
        assert!(McpTarget::from_name("antigravity").is_err());
        assert!(default_target_path(McpTarget::Generic).is_none());
        // HOME is set under Unix cargo test; Windows CI leaves it
        // unset, and the path must be absent exactly then.
        match default_target_path(McpTarget::Cursor) {
            Some(cursor) => assert!(cursor.ends_with(".cursor/mcp.json")),
            None => assert!(
                std::env::var_os("HOME").is_none(),
                "cursor path missing while HOME is set"
            ),
        }
    }

    #[test]
    fn snippet_has_stdio_server_entry() {
        let snippet: serde_json::Value =
            serde_json::from_str(&snippet_json("/bin/runner")).unwrap();
        assert_eq!(snippet["mcpServers"]["runner"]["command"], "/bin/runner");
        assert_eq!(snippet["mcpServers"]["runner"]["args"][0], "mcp");
    }

    #[test]
    fn install_merges_preserves_and_backs_up() {
        let dir = crate::test_support::TempDir::new("mcp-install").unwrap();
        let path = dir.path().join("sub").join("mcp.json");
        let note = install_to_file(&path, "/bin/runner").unwrap();
        assert!(note.contains("registered"));
        // Second tool merges alongside; original entry preserved.
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["mcpServers"]["other"] = serde_json::json!({"command": "x"});
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        install_to_file(&path, "/bin/runner").unwrap();
        let merged: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(merged["mcpServers"]["runner"]["command"], "/bin/runner");
        assert_eq!(merged["mcpServers"]["other"]["command"], "x");
        assert!(path.with_extension("json.bak").exists());
    }

    #[test]
    fn install_refuses_foreign_shapes_without_touching() {
        let dir = crate::test_support::TempDir::new("mcp-refuse").unwrap();
        let bad_json = dir.path().join("bad.json");
        std::fs::write(&bad_json, "{nope").unwrap();
        assert!(install_to_file(&bad_json, "/bin/runner").is_err());
        assert_eq!(std::fs::read_to_string(&bad_json).unwrap(), "{nope");

        let bad_shape = dir.path().join("shape.json");
        std::fs::write(&bad_shape, r#"{"mcpServers": []}"#).unwrap();
        assert!(install_to_file(&bad_shape, "/bin/runner").is_err());
    }
}
