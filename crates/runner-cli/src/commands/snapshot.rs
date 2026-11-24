//! `runner snapshot`: named worktree checkpoints for instant
//! rollback. Thin layer over `runner_core::fs::snapshot` (store,
//! discovery, and restore rules live there); rendering is pure for
//! tests.

use runner_core::fs::snapshot::{RestoreStats, SnapshotMeta, WorkspaceSnapshots};

/// Snapshot store for the repository enclosing the current working
/// directory.
pub fn open_workspace_store() -> Result<WorkspaceSnapshots, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot determine working directory: {e}"))?;
    WorkspaceSnapshots::for_repository(&cwd).map_err(|e| e.to_string())
}

/// One captured checkpoint, human-readable.
pub fn render_create_text(meta: &SnapshotMeta, worktree: &std::path::Path) -> String {
    format!(
        "snapshot '{}' captured from {}.\n",
        meta.name,
        worktree.display()
    )
}

/// Human-readable snapshot listing (newest last, one per line).
pub fn render_list_text(metas: &[SnapshotMeta]) -> String {
    if metas.is_empty() {
        return "no snapshots\n".to_string();
    }
    let mut out = String::new();
    for meta in metas {
        out.push_str(&format!("{} (created {})\n", meta.name, meta.created_secs));
    }
    out
}

/// Machine-readable snapshot listing.
pub fn render_list_json(metas: &[SnapshotMeta]) -> String {
    serde_json::to_string_pretty(metas).unwrap_or_else(|_| "[]".to_string())
}

/// Human-readable restore outcome.
pub fn render_restore_text(name: &str, stats: &RestoreStats) -> String {
    format!(
        "restored '{}' ({} files reverted, {} untracked entries removed).\n",
        name, stats.files_restored, stats.entries_removed
    )
}

/// Human-readable snapshot removal.
pub fn render_remove_text(name: &str) -> String {
    format!("removed snapshot '{name}'.\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, created: u64) -> SnapshotMeta {
        SnapshotMeta {
            name: name.to_string(),
            created_secs: created,
            source: std::path::PathBuf::from("/repo"),
        }
    }

    #[test]
    fn renders_cover_empty_and_populated_lists() {
        assert_eq!(render_list_text(&[]), "no snapshots\n");
        let text = render_list_text(&[meta("v1", 100), meta("v2", 200)]);
        assert!(text.contains("v1 (created 100)"), "{text}");
        assert!(text.contains("v2 (created 200)"), "{text}");
        let json: serde_json::Value =
            serde_json::from_str(&render_list_json(&[meta("v1", 100)])).unwrap();
        assert_eq!(json[0]["name"], "v1");
        assert_eq!(
            render_create_text(&meta("v1", 100), std::path::Path::new("/repo")),
            "snapshot 'v1' captured from /repo.\n"
        );
        assert_eq!(
            render_restore_text(
                "v1",
                &RestoreStats {
                    files_restored: 3,
                    entries_removed: 1
                }
            ),
            "restored 'v1' (3 files reverted, 1 untracked entries removed).\n"
        );
        assert_eq!(render_remove_text("v1"), "removed snapshot 'v1'.\n");
    }
}
