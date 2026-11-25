//! Agent workspace snapshots: named checkpoints of a working tree
//! stored under `<repo>/.runner/snapshots/`, captured and restored
//! through hardware CoW clones (instant on supporting filesystems,
//! plain copies elsewhere). Version-control metadata (`.git`) and
//! runner state (`.runner`, including the snapshots themselves)
//! never enter a snapshot — the former would rewrite VCS history on
//! restore, the latter would nest snapshots infinitely (and both
//! would leak secrets into checkpoint payloads).

use super::cow::{
    cow_clone_file, cow_clone_tree_excluding, mirror_mode, mirror_symlink, remove_file_or_symlink,
};
use std::path::{Path, PathBuf};

/// Entry names skipped at every depth during capture (and preserved
/// in the worktree during restore).
pub const WORKSPACE_EXCLUDES: &[&str] = &[".git", ".runner"];

/// Snapshot metadata sidecar (`<name>/meta.json`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotMeta {
    /// User-chosen snapshot name.
    pub name: String,
    /// Creation time, unix seconds.
    pub created_secs: u64,
    /// Worktree the snapshot was captured from.
    pub source: PathBuf,
}

/// Outcome of one restore: content reverted plus untracked extras
/// deleted (the latter only under `force`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreStats {
    /// Files cloned back from the snapshot baseline.
    pub files_restored: u64,
    /// Worktree entries absent from the snapshot, deleted.
    pub entries_removed: u64,
}

/// Named workspace checkpoints rooted at one snapshots directory.
#[derive(Debug, Clone)]
pub struct WorkspaceSnapshots {
    root: PathBuf,
}

/// Snapshot failures: invalid requests (bad names, unknown
/// snapshots, refused force-gated deletes, missing repos) versus
/// operational I/O failures. MCP maps these to `invalid_params`
/// and `internal` respectively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    Invalid(String),
    Io(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Invalid(message) | SnapshotError::Io(message) => {
                write!(f, "{message}")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Fallible snapshot result (see [`SnapshotError`]).
pub type SnapshotResult<T> = Result<T, SnapshotError>;

/// Disambiguates temp paths created within the same nanosecond
/// by concurrent same-process captures.
static STAGING_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Unique per-call tag for staging directories, tombstones, and
/// restore temp files (process + time + counter: no two collide).
fn unique_tag() -> String {
    format!(
        "{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0),
        STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

/// Locate the enclosing repository root by walking up from `start`
/// for a `.git` entry (directory or worktree/submodule file). No git
/// binary involved, so hermetic tests need only plain directories.
/// Anchor a possibly-relative discovery start against an
/// explicit base directory (callers pass the process working
/// directory): relative starts (including `""`) resolve stably,
/// absolute starts pass through untouched. Pure for tests — no
/// ambient working directory reads here.
fn anchor_start(start: &Path, base: &Path) -> PathBuf {
    if start.is_relative() {
        base.join(start)
    } else {
        start.to_path_buf()
    }
}

pub fn discover_repo_root(start: &Path) -> SnapshotResult<PathBuf> {
    let base = std::env::current_dir()
        .map_err(|e| SnapshotError::Invalid(format!("cannot resolve working directory: {e}")))?;
    let mut dir = anchor_start(start, &base);
    loop {
        if dir.join(".git").symlink_metadata().is_ok() {
            return Ok(dir);
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => {
                return Err(SnapshotError::Invalid(format!(
                    "not inside a git repository (no .git above {})",
                    start.display()
                )));
            }
        }
    }
}

/// Validate a user snapshot name: non-empty, no path separators or
/// NUL/control bytes, never `.`/`..`, never trailing dots or spaces
/// (Windows strips those, aliasing distinct names together).
pub fn validate_snapshot_name(name: &str) -> SnapshotResult<()> {
    if name.is_empty() {
        return Err(SnapshotError::Invalid(
            "snapshot name must not be empty".to_string(),
        ));
    }
    if name == "." || name == ".." {
        return Err(SnapshotError::Invalid(format!(
            "snapshot name must not be '{name}'"
        )));
    }
    // Colons stay rejected even though unix permits them: on Windows
    // `C:src` resolves drive-relative and escapes the store.
    if name
        .chars()
        .any(|c| c == '/' || c == '\\' || c == ':' || c == '\0' || c.is_control())
    {
        return Err(SnapshotError::Invalid(format!(
            "snapshot name holds path characters: '{name}'"
        )));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(SnapshotError::Invalid(format!(
            "snapshot name must not end with a dot or space: '{name}'"
        )));
    }
    // Structural backstop: exactly one normal component (no roots,
    // prefixes, or parent escapes on any platform).
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(SnapshotError::Invalid(format!(
            "snapshot name is not a plain file name: '{name}'"
        ))),
    }
}

impl WorkspaceSnapshots {
    /// Snapshot store rooted at an explicit directory (callers pass
    /// `<repo>/.runner/snapshots`).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Snapshot store for the repository enclosing `start`.
    pub fn for_repository(start: &Path) -> SnapshotResult<Self> {
        Ok(Self::new(
            discover_repo_root(start)?.join(".runner").join("snapshots"),
        ))
    }

    /// Store root (created lazily by capture, never here).
    pub fn dir(&self) -> &Path {
        &self.root
    }

    fn snapshot_dir(&self, name: &str) -> SnapshotResult<PathBuf> {
        validate_snapshot_name(name)?;
        Ok(self.root.join(name))
    }

    /// Capture the worktree into a named snapshot (VCS metadata and
    /// runner state excluded). Staging is private (unique per call),
    /// so concurrent captures never share a directory; the atomic
    /// rename arbitrates same-name races (losers see the winner and
    /// fail cleanly), and only the caller's own staging is ever
    /// cleaned — never the final name.
    pub fn create(&self, worktree: &Path, name: &str) -> SnapshotResult<SnapshotMeta> {
        let dir = self.snapshot_dir(name)?;
        if std::fs::symlink_metadata(&dir).is_ok() {
            return Err(SnapshotError::Invalid(format!(
                "snapshot already exists: '{name}'"
            )));
        }
        std::fs::create_dir_all(&self.root)
            .map_err(|e| SnapshotError::Io(format!("cannot create snapshot store: {e}")))?;
        let staging = self.root.join(format!(".tmp.{}", unique_tag()));
        let tree = staging.join("tree");
        if let Err(e) = cow_clone_tree_excluding(worktree, &tree, WORKSPACE_EXCLUDES) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(SnapshotError::Io(format!("snapshot capture failed: {e}")));
        }
        let meta = SnapshotMeta {
            name: name.to_string(),
            created_secs: std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0),
            source: worktree.to_path_buf(),
        };
        let body = serde_json::to_string_pretty(&meta)
            .map_err(|e| SnapshotError::Io(format!("cannot encode snapshot metadata: {e}")))?;
        if let Err(e) = std::fs::write(staging.join("meta.json"), body) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(SnapshotError::Io(format!(
                "cannot record snapshot metadata: {e}"
            )));
        }
        // Atomic publish: a complete snapshot appears under its name
        // in one step (readers never see a partial tree). A lost
        // rename race reports the winner, never wipes it.
        if let Err(e) = std::fs::rename(&staging, &dir) {
            let _ = std::fs::remove_dir_all(&staging);
            if std::fs::symlink_metadata(&dir).is_ok() {
                return Err(SnapshotError::Invalid(format!(
                    "snapshot already exists: '{name}'"
                )));
            }
            return Err(SnapshotError::Io(format!(
                "cannot publish snapshot '{name}': {e}"
            )));
        }
        Ok(meta)
    }

    /// Restore the worktree to a named snapshot in two phases.
    /// First the whole tree is scanned for extras (worktree paths
    /// absent from the snapshot, plus kind-mismatched counterparts
    /// whose content cannot survive); any extras without `force`
    /// abort before a single file is modified. Then the baseline is
    /// reconciled granularly — files overwritten in place, never
    /// wholesale directory replacement — and force-gated extras are
    /// deleted. `.git`/`.runner` are never touched on either side,
    /// and symlinks restore verbatim (never followed).
    pub fn restore(
        &self,
        worktree: &Path,
        name: &str,
        force: bool,
    ) -> SnapshotResult<RestoreStats> {
        let dir = self.snapshot_dir(name)?;
        require_complete_snapshot(&dir, name)?;
        let tree = dir.join("tree");
        let mut stats = RestoreStats::default();
        // Phase A: scan every extra before modifying anything.
        let mut extras = Vec::new();
        collect_extras(&tree, worktree, Path::new(""), &mut extras)?;
        if !extras.is_empty() && !force {
            return Err(SnapshotError::Invalid(format!(
                "restore would delete {} untracked entr{}; pass force to proceed{}",
                extras.len(),
                if extras.len() == 1 { "y" } else { "ies" },
                describe_extras(&extras),
            )));
        }
        // Phase B: reconcile the baseline granularly.
        restore_tree(&tree, worktree, &mut stats)?;
        // Phase C: delete genuine extras (mismatched counterparts
        // were already replaced above and no longer qualify).
        for extra in &extras {
            if tree.join(extra).symlink_metadata().is_ok() {
                continue;
            }
            let target = worktree.join(extra);
            match std::fs::symlink_metadata(&target) {
                Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {
                    std::fs::remove_dir_all(&target).map_err(|e| {
                        SnapshotError::Io(format!("cannot remove {}: {e}", target.display()))
                    })?;
                }
                Ok(_) => {
                    remove_file_or_symlink(&target).map_err(|e| {
                        SnapshotError::Io(format!("cannot remove {}: {e}", target.display()))
                    })?;
                }
                // Vanished between scan and sweep (external actor):
                // already gone is already correct.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(SnapshotError::Io(format!(
                        "cannot inspect {}: {e}",
                        target.display()
                    )));
                }
            }
            stats.entries_removed += 1;
        }
        Ok(stats)
    }

    /// List snapshots newest-last (unreadable records skipped, never
    /// fatal: one corrupt sidecar must not hide the rest). Staging
    /// and tombstone debris (`.tmp.*`) never lists, even mid-flight
    /// with a sidecar already written.
    pub fn list(&self) -> Vec<SnapshotMeta> {
        let mut metas = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return metas;
        };
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with(".tmp.") {
                continue;
            }
            let body = std::fs::read(entry.path().join("meta.json"));
            let Ok(body) = body else {
                continue;
            };
            if let Ok(meta) = serde_json::from_slice::<SnapshotMeta>(&body) {
                metas.push(meta);
            }
        }
        metas.sort_by_key(|meta| meta.created_secs);
        metas
    }

    /// Delete one snapshot by name (missing names fail loudly —
    /// typos must not silently succeed). The baseline renames to a
    /// private tombstone first, so an interrupted deletion can never
    /// leave a truncated snapshot eligible for restore.
    pub fn remove(&self, name: &str) -> SnapshotResult<()> {
        let dir = self.snapshot_dir(name)?;
        if std::fs::symlink_metadata(&dir).is_err() {
            return Err(SnapshotError::Invalid(format!(
                "unknown snapshot: '{name}'"
            )));
        }
        let tombstone = self.root.join(format!(".tmp.del-{}", unique_tag()));
        std::fs::rename(&dir, &tombstone)
            .map_err(|e| SnapshotError::Io(format!("cannot remove snapshot '{name}': {e}")))?;
        std::fs::remove_dir_all(&tombstone)
            .map_err(|e| SnapshotError::Io(format!("cannot remove snapshot '{name}': {e}")))?;
        Ok(())
    }
}

/// Sorted entry names of one directory (missing directories are a
/// loud error: restores never silently operate on nothing).
fn read_names_sorted(dir: &Path) -> SnapshotResult<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| SnapshotError::Io(format!("cannot list {}: {e}", dir.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| SnapshotError::Io(format!("cannot list {}: {e}", dir.display())))?;
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

/// Require a complete, parseable snapshot baseline (atomic
/// captures land whole, so anything else is hand-placed debris or
/// a typo — both fail closed, never restored from).
fn require_complete_snapshot(dir: &Path, name: &str) -> SnapshotResult<()> {
    if std::fs::symlink_metadata(dir).is_err() {
        return Err(SnapshotError::Invalid(format!(
            "unknown snapshot: '{name}'"
        )));
    }
    let body = std::fs::read(dir.join("meta.json")).map_err(|_| {
        SnapshotError::Invalid(format!(
            "snapshot '{name}' is incomplete (missing metadata)"
        ))
    })?;
    serde_json::from_slice::<SnapshotMeta>(&body)
        .map_err(|_| SnapshotError::Invalid(format!("snapshot '{name}' metadata is corrupt")))?;
    if !dir.join("tree").is_dir() {
        return Err(SnapshotError::Invalid(format!(
            "snapshot '{name}' is incomplete (missing baseline)"
        )));
    }
    Ok(())
}

/// Collect every worktree path restore would destroy: paths absent
/// from the snapshot (counted once at the topmost level, never
/// descended) plus kind-mismatched counterparts whose content
/// cannot survive replacement. Exclusions skip on sight at every
/// depth; symlinks never followed. Pure scan — modifies nothing.
fn collect_extras(
    snapshot_dir: &Path,
    worktree_dir: &Path,
    rel: &Path,
    out: &mut Vec<PathBuf>,
) -> SnapshotResult<()> {
    for name in read_names_sorted(worktree_dir)? {
        if is_excluded(&name) {
            continue;
        }
        let work_path = worktree_dir.join(&name);
        let entry_rel = rel.join(&name);
        let work_type = match std::fs::symlink_metadata(&work_path) {
            Ok(meta) => meta.file_type(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(SnapshotError::Io(format!(
                    "cannot inspect {}: {e}",
                    work_path.display()
                )));
            }
        };
        let snap_type = match std::fs::symlink_metadata(snapshot_dir.join(&name)) {
            Ok(meta) => Some(meta.file_type()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(SnapshotError::Io(format!(
                    "cannot inspect {}: {e}",
                    snapshot_dir.join(&name).display()
                )));
            }
        };
        match snap_type {
            None => out.push(entry_rel),
            Some(kind) => {
                let snap_dir = kind.is_dir() && !kind.is_symlink();
                let work_dir = work_type.is_dir() && !work_type.is_symlink();
                if snap_dir && work_dir {
                    collect_extras(&snapshot_dir.join(&name), &work_path, &entry_rel, out)?;
                } else if snap_dir != work_dir {
                    out.push(entry_rel);
                }
            }
        }
    }
    Ok(())
}

/// Short human listing for refusal messages (first five, counted).
fn describe_extras(extras: &[PathBuf]) -> String {
    if extras.is_empty() {
        return String::new();
    }
    let shown: Vec<String> = extras
        .iter()
        .take(5)
        .map(|path| path.display().to_string())
        .collect();
    let mut out = format!(": {}", shown.join(", "));
    if extras.len() > 5 {
        out.push_str(&format!(" and {} more", extras.len() - 5));
    }
    out
}

/// Reconcile one snapshot level into its worktree counterpart:
/// directories merge (created as needed, never wholesale-replaced),
/// files clone over cleared counterparts, links recreate verbatim.
/// Exclusions skip defensively (captures never store them, but
/// hand-built baselines must not touch VCS state either).
fn restore_tree(
    snapshot_dir: &Path,
    worktree_dir: &Path,
    stats: &mut RestoreStats,
) -> SnapshotResult<()> {
    std::fs::create_dir_all(worktree_dir)
        .map_err(|e| SnapshotError::Io(format!("cannot create {}: {e}", worktree_dir.display())))?;
    for name in read_names_sorted(snapshot_dir)? {
        if is_excluded(&name) {
            continue;
        }
        let from = snapshot_dir.join(&name);
        let onto = worktree_dir.join(&name);
        let file_type = std::fs::symlink_metadata(&from)
            .map_err(|e| SnapshotError::Io(format!("cannot read snapshot entry: {e}")))?
            .file_type();
        if file_type.is_dir() && !file_type.is_symlink() {
            if let Ok(meta) = std::fs::symlink_metadata(&onto) {
                if !(meta.file_type().is_dir() && !meta.file_type().is_symlink()) {
                    remove_worktree_entry(&onto)?;
                }
            }
            restore_tree(&from, &onto, stats)?;
            // Captured modes apply post-order: children land before
            // the lockdown, so 0700 directories stay writable while
            // filling and restricted afterwards.
            mirror_mode(&from, &onto).map_err(|e| {
                SnapshotError::Io(format!("cannot restore modes {}: {e}", onto.display()))
            })?;
        } else if file_type.is_file() {
            replace_counterpart_atomic(&onto, stats, |tmp| {
                cow_clone_file(&from, tmp).map_err(|e| {
                    SnapshotError::Io(format!("cannot restore {}: {e}", from.display()))
                })
            })?;
            stats.files_restored += 1;
        } else if file_type.is_symlink() {
            replace_counterpart_atomic(&onto, stats, |tmp| {
                mirror_symlink(&from, tmp).map_err(|e| {
                    SnapshotError::Io(format!("cannot restore {}: {e}", from.display()))
                })
            })?;
            stats.files_restored += 1;
        } else {
            return Err(SnapshotError::Io(format!(
                "cannot restore special file {}",
                from.display()
            )));
        }
    }
    Ok(())
}

/// Replace one restore counterpart atomically: the new content
/// materializes in a unique sibling temp file first, then renames
/// over the target — a failed write never destroys the existing
/// file or link. A real directory in the way is removed first and
/// counted (mismatched subtrees were force-gated during the extras
/// scan); a failed produce or rename cleans up its temp and reports
/// loudly with the original untouched.
fn replace_counterpart_atomic(
    onto: &Path,
    stats: &mut RestoreStats,
    produce: impl FnOnce(&Path) -> SnapshotResult<()>,
) -> SnapshotResult<()> {
    let is_real_dir = match std::fs::symlink_metadata(onto) {
        Ok(meta) => meta.file_type().is_dir() && !meta.file_type().is_symlink(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(SnapshotError::Io(format!(
                "cannot inspect {}: {e}",
                onto.display()
            )));
        }
    };
    if is_real_dir {
        std::fs::remove_dir_all(onto)
            .map_err(|e| SnapshotError::Io(format!("cannot clear {}: {e}", onto.display())))?;
        stats.entries_removed += 1;
    }
    let parent = onto.parent().unwrap_or(Path::new("."));
    let tmp = parent.join(format!(".tmp.restore-{}", unique_tag()));
    if let Err(e) = produce(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, onto) {
        let _ = std::fs::remove_file(&tmp);
        return Err(SnapshotError::Io(format!(
            "cannot install {}: {e}",
            onto.display()
        )));
    }
    Ok(())
}

/// Clear one worktree path for restore-overwrite: directories go
/// recursively, files and links go singly, missing paths pass.
/// Never touches `.git`/`.runner` (callers filter those first).
fn remove_worktree_entry(path: &Path) -> SnapshotResult<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(SnapshotError::Io(format!(
                "cannot inspect {}: {e}",
                path.display()
            )));
        }
    };
    if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
            .map_err(|e| SnapshotError::Io(format!("cannot clear {}: {e}", path.display())))?;
    } else {
        remove_file_or_symlink(path)
            .map_err(|e| SnapshotError::Io(format!("cannot clear {}: {e}", path.display())))?;
    }
    Ok(())
}

/// Uniform exclusion test (mirrors the walker rule).
fn is_excluded(name: &std::ffi::OsStr) -> bool {
    super::cow::name_is_excluded(name, WORKSPACE_EXCLUDES)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake repository: `.git` marker plus two content files.
    fn fake_repo(dir: &Path) -> PathBuf {
        let repo = dir.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".git").join("HEAD"), b"ref: main").unwrap();
        std::fs::write(repo.join("main.rs"), b"fn main() {}").unwrap();
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::write(repo.join("src").join("lib.rs"), b"lib v1").unwrap();
        repo
    }

    fn store_for(repo: &Path) -> WorkspaceSnapshots {
        WorkspaceSnapshots::for_repository(repo).unwrap()
    }

    #[test]
    fn discovery_walks_up_to_git_marker() {
        let dir = crate::test_support::TempDir::new("snap-discover").unwrap();
        let repo = fake_repo(dir.path());
        let nested = repo.join("src");
        assert_eq!(discover_repo_root(&nested).unwrap(), repo);
        assert_eq!(discover_repo_root(&repo).unwrap(), repo);
        // Bare `.git` files (worktrees, submodules) count too.
        let linked = dir.path().join("linked");
        std::fs::create_dir_all(linked.join("sub")).unwrap();
        std::fs::write(linked.join(".git"), b"gitdir: elsewhere").unwrap();
        assert_eq!(discover_repo_root(&linked.join("sub")).unwrap(), linked);
        assert!(discover_repo_root(dir.path()).is_err());
    }

    #[test]
    fn names_reject_paths_and_tricky_shapes() {
        for bad in [
            "", ".", "..", "a/b", "a\\b", "a\0b", "trail.", "C:src", "a:b",
        ] {
            assert!(validate_snapshot_name(bad).is_err(), "{bad:?}");
        }
        for ok in ["v1", "before-refactor", "Agent.Try_2"] {
            assert!(validate_snapshot_name(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn anchor_start_resolves_relative_paths() {
        // Expectations built by joining (never literals), so the
        // assertions hold under every platform's path grammar.
        let base = std::env::temp_dir();
        assert_eq!(anchor_start(Path::new("."), &base), base.join("."));
        assert_eq!(anchor_start(Path::new(""), &base), base.join(""));
        assert_eq!(anchor_start(Path::new("sub"), &base), base.join("sub"));
        // Absolute starts pass through untouched.
        let abs = base.join("there");
        assert_eq!(anchor_start(&abs, Path::new("ignored")), abs);
    }

    #[test]
    fn create_captures_content_without_vcs_or_runner_state() {
        let dir = crate::test_support::TempDir::new("snap-create").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        let meta = store.create(&repo, "v1").unwrap();
        assert_eq!(meta.name, "v1");
        assert!(meta.created_secs > 0);
        let snap = store.dir().join("v1").join("tree");
        assert_eq!(
            std::fs::read(snap.join("main.rs")).unwrap(),
            b"fn main() {}"
        );
        assert_eq!(
            std::fs::read(snap.join("src").join("lib.rs")).unwrap(),
            b"lib v1"
        );
        assert!(!snap.join(".git").exists());
        assert!(!snap.join(".runner").exists());
        // Duplicate names fail loudly; listing shows the one.
        assert!(store.create(&repo, "v1").is_err());
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "v1");
    }

    #[test]
    fn restore_reverts_tracked_and_gates_extras() {
        let dir = crate::test_support::TempDir::new("snap-restore").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        // Mutate tracked content, add an untracked extra, touch VCS.
        std::fs::write(repo.join("src").join("lib.rs"), b"lib v2").unwrap();
        std::fs::write(repo.join("scratch.txt"), b"new work").unwrap();
        std::fs::write(repo.join(".git").join("HEAD"), b"ref: changed").unwrap();
        // Without force: extras block with a loud count.
        let err = store.restore(&repo, "v1", false).unwrap_err();
        assert!(matches!(err, SnapshotError::Invalid(_)));
        assert!(err.to_string().contains('1'), "{err}");
        // Nothing modified: the refusal precedes all writes.
        assert_eq!(
            std::fs::read(repo.join("src").join("lib.rs")).unwrap(),
            b"lib v2"
        );
        assert!(repo.join("scratch.txt").exists());
        // With force: extras go, stats account everything.
        let stats = store.restore(&repo, "v1", true).unwrap();
        assert_eq!(stats.files_restored, 2);
        assert_eq!(stats.entries_removed, 1);
        assert_eq!(
            std::fs::read(repo.join("src").join("lib.rs")).unwrap(),
            b"lib v1"
        );
        assert!(!repo.join("scratch.txt").exists());
        // VCS state never touched either way.
        assert_eq!(
            std::fs::read(repo.join(".git").join("HEAD")).unwrap(),
            b"ref: changed"
        );
        assert!(store.restore(&repo, "missing", true).is_err());
    }

    /// Nested extras block the whole restore with zero modification:
    /// every worktree byte is identical before and after refusal.
    #[test]
    fn restore_refusal_leaves_nested_tree_untouched() {
        let dir = crate::test_support::TempDir::new("snap-nested-block").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        std::fs::write(repo.join("src").join("lib.rs"), b"lib v2").unwrap();
        std::fs::write(repo.join("src").join("new.rs"), b"nested extra").unwrap();
        let before = dir_tree_bytes(&repo);
        let err = store.restore(&repo, "v1", false).unwrap_err();
        assert!(matches!(err, SnapshotError::Invalid(_)));
        assert_eq!(dir_tree_bytes(&repo), before);
        // Forced restore reverts and removes, reporting both.
        let stats = store.restore(&repo, "v1", true).unwrap();
        assert_eq!(stats.files_restored, 2);
        assert_eq!(stats.entries_removed, 1);
        assert!(!repo.join("src").join("new.rs").exists());
    }

    /// Nested VCS databases (submodules) and nested runner state
    /// survive restores at any depth, forced or not.
    #[test]
    fn restore_preserves_nested_vcs_and_runner_state() {
        let dir = crate::test_support::TempDir::new("snap-nested-keep").unwrap();
        let repo = fake_repo(dir.path());
        std::fs::create_dir_all(repo.join("vendor").join("pkg").join(".git")).unwrap();
        std::fs::write(
            repo.join("vendor").join("pkg").join(".git").join("config"),
            b"submodule",
        )
        .unwrap();
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        std::fs::write(
            repo.join("vendor").join("pkg").join(".git").join("config"),
            b"mutated",
        )
        .unwrap();
        std::fs::write(repo.join("vendor").join("extra.txt"), b"x").unwrap();
        store.restore(&repo, "v1", true).unwrap();
        assert_eq!(
            std::fs::read(repo.join("vendor").join("pkg").join(".git").join("config")).unwrap(),
            b"mutated"
        );
        assert!(!repo.join("vendor").join("extra.txt").exists());
    }

    /// Links restore verbatim: same targets, still links — dangling
    /// and absolute links included, host bytes never materialized.
    #[cfg(unix)]
    #[test]
    fn restore_preserves_symlinks_verbatim() {
        let dir = crate::test_support::TempDir::new("snap-links").unwrap();
        let repo = fake_repo(dir.path());
        std::os::unix::fs::symlink("main.rs", repo.join("alias.rs")).unwrap();
        std::os::unix::fs::symlink("no-such-target", repo.join("dangling")).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", repo.join("absolute")).unwrap();
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        // Clobber every link with a real file, then restore.
        for name in ["alias.rs", "dangling", "absolute"] {
            std::fs::remove_file(repo.join(name)).unwrap();
            std::fs::write(repo.join(name), b"clobbered").unwrap();
        }
        let stats = store.restore(&repo, "v1", false).unwrap();
        assert_eq!(stats.files_restored, 5);
        for (name, target) in [
            ("alias.rs", "main.rs"),
            ("dangling", "no-such-target"),
            ("absolute", "/etc/hostname"),
        ] {
            let link = repo.join(name);
            assert!(
                std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{name}"
            );
            assert_eq!(std::fs::read_link(&link).unwrap(), PathBuf::from(target));
        }
    }

    /// Concurrent same-name captures: exactly one wins with intact
    /// bytes; losers fail cleanly without touching the winner.
    #[test]
    fn concurrent_create_yields_single_winner() {
        let dir = crate::test_support::TempDir::new("snap-race").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        let results: Vec<_> = std::thread::scope(|scope| {
            (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let local = WorkspaceSnapshots::for_repository(&repo).unwrap();
                        local.create(&repo, "v1")
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap().is_ok())
                .collect()
        });
        assert_eq!(results.iter().filter(|ok| **ok).count(), 1);
        assert!(store.list().iter().any(|meta| meta.name == "v1"));
        assert_eq!(
            std::fs::read(store.dir().join("v1").join("tree").join("main.rs")).unwrap(),
            b"fn main() {}"
        );
    }

    /// Hand-placed debris without valid metadata is rejected, never
    /// restored from (and listing skips it silently).
    #[test]
    fn incomplete_baselines_reject_loudly() {
        let dir = crate::test_support::TempDir::new("snap-debris").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        let debris = store.dir().join("junk");
        std::fs::create_dir_all(debris.join("tree")).unwrap();
        assert!(matches!(
            store.restore(&repo, "junk", true),
            Err(SnapshotError::Invalid(_))
        ));
        assert!(store.list().is_empty());
        std::fs::write(debris.join("meta.json"), b"{oops").unwrap();
        assert!(matches!(
            store.restore(&repo, "junk", true),
            Err(SnapshotError::Invalid(_))
        ));
    }

    #[test]
    fn capture_excludes_case_folded_vcs_and_runner_state() {
        let dir = crate::test_support::TempDir::new("snap-fold").unwrap();
        let repo = fake_repo(dir.path());
        std::fs::create_dir_all(repo.join(".GIT")).unwrap();
        std::fs::write(repo.join(".GIT").join("evil"), b"x").unwrap();
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        let snap = store.dir().join("v1").join("tree");
        assert!(!snap.join(".GIT").exists());
        assert!(!snap.join(".runner").exists());
        assert!(snap.join("main.rs").exists());
    }

    #[test]
    fn remove_leaves_no_debris_behind() {
        let dir = crate::test_support::TempDir::new("snap-tomb").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        store.remove("v1").unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(store.dir()).unwrap().collect();
        assert!(leftovers.is_empty());
        assert!(store.list().is_empty());
    }

    #[test]
    fn list_skips_staging_and_tombstone_debris() {
        let dir = crate::test_support::TempDir::new("snap-skip").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        // In-flight staging with a sidecar already written, plus a
        // leftover tombstone: neither may ever list.
        let staging = store.dir().join(".tmp.1-2-3");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("meta.json"), b"{}").unwrap();
        let tomb = store.dir().join(".tmp.del-4-5-6");
        std::fs::create_dir_all(&tomb).unwrap();
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "v1");
    }

    /// Restricted directories roundtrip with their restrictions
    /// (modes land post-order, after children fill in).
    #[cfg(unix)]
    #[test]
    fn restore_preserves_restricted_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::test_support::TempDir::new("snap-modes").unwrap();
        let repo = fake_repo(dir.path());
        let locked = repo.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("secret.txt"), b"s").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        // Loosen and mutate, then restore.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(locked.join("secret.txt"), b"mutated").unwrap();
        store.restore(&repo, "v1", true).unwrap();
        let mode = std::fs::metadata(&locked).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert_eq!(std::fs::read(locked.join("secret.txt")).unwrap(), b"s");
    }

    /// Failed restores preserve the worktree: counterparts are
    /// replaced via temp-rename, so a mid-restore failure leaves
    /// originals (and no debris) behind.
    #[cfg(unix)]
    #[test]
    fn restore_failure_preserves_counterparts() {
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::test_support::TempDir::new("snap-atomic").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        // Make the baseline unreadable so the clone fails mid-way.
        let baseline = store.dir().join("v1").join("tree").join("main.rs");
        std::fs::set_permissions(&baseline, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&baseline).is_ok() {
            eprintln!("running privileged; skipping atomic-restore test");
            return;
        }
        std::fs::write(repo.join("main.rs"), b"mutated").unwrap();
        assert!(store.restore(&repo, "v1", true).is_err());
        // Original bytes intact; temp debris cleaned up.
        assert_eq!(std::fs::read(repo.join("main.rs")).unwrap(), b"mutated");
        let debris: Vec<_> = std::fs::read_dir(&repo)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".tmp.restore-"))
            .collect();
        assert!(debris.is_empty());
        std::fs::set_permissions(&baseline, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// Snapshot of a whole tree for before/after refusal proofs.
    fn dir_tree_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let mut names: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            names.sort();
            for path in names {
                // Tag symlinks distinctly so a link/file swap
                // cannot compare equal.
                let file_type = std::fs::symlink_metadata(&path).unwrap().file_type();
                if file_type.is_dir() && !file_type.is_symlink() {
                    stack.push(path);
                } else if file_type.is_symlink() {
                    out.push((path.clone(), b"<symlink>".to_vec()));
                } else if file_type.is_file() {
                    out.push((path.clone(), std::fs::read(&path).unwrap()));
                } else {
                    out.push((path.clone(), b"<special>".to_vec()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn remove_drops_snapshots_loudly() {
        let dir = crate::test_support::TempDir::new("snap-rm").unwrap();
        let repo = fake_repo(dir.path());
        let store = store_for(&repo);
        store.create(&repo, "v1").unwrap();
        store.remove("v1").unwrap();
        assert!(store.list().is_empty());
        assert!(store.remove("v1").is_err());
        assert!(store.remove("../evil").is_err());
    }
}
