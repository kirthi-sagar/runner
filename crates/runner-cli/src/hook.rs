//! Git pre-commit hook management (`runner hook`): route local
//! pre-commit checks through `runner exec` so commits never freeze the
//! workstation. Only hooks carrying the manager marker are touched on
//! uninstall; foreign hooks are preserved via `.bak` backup.
//!
//! Pure helpers (detection, rendering) are unit-tested; filesystem
//! effects are tested against temp dirs, never the caller's repo.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Marker embedded in generated hooks; uninstall only manages scripts
/// that contain it, so foreign hooks are never deleted.
pub const HOOK_MARKER: &str = "# managed by runner hook";

/// Backup suffix for a pre-existing pre-commit hook.
pub const BACKUP_SUFFIX: &str = ".bak";

/// Auto-detect the pre-commit check command for `dir` by probing for
/// well-known project markers. Explicit `--cmd` always wins over this.
pub fn detect_command(dir: &Path) -> Option<String> {
    if dir.join("Cargo.toml").is_file() {
        return Some("cargo test".to_string());
    }
    if dir.join("package.json").is_file() {
        return Some("npm test".to_string());
    }
    if dir.join("pytest.ini").is_file() || dir.join("pyproject.toml").is_file() {
        return Some("pytest".to_string());
    }
    None
}

/// Render the `pre-commit` shell script. It resolves the `runner`
/// binary from `PATH`, runs the check under `runner exec` (cgroup
/// governance, zero-freeze), and propagates the exit code so a
/// failing check blocks the commit.
///
/// `--no-sandbox` is deliberate: a pre-commit check runs the
/// developer's own tree in place (repo cwd), which a mount namespace
/// would hide; governance still applies. Trusted local code needs
/// freeze protection, not untrusted-code isolation.
pub fn render_hook(command: &str) -> String {
    format!(
        "#!/bin/sh\n{HOOK_MARKER}\n# Wraps pre-commit checks in `runner exec` (zero-freeze).\n\
         set -e\nRUNNER_BIN=\"$(command -v runner)\"\n\
         if [ -z \"$RUNNER_BIN\" ]; then\n  echo \"runner not found in PATH; skipping governed pre-commit\" >&2\n  exit 0\nfi\n\
         exec \"$RUNNER_BIN\" exec --no-sandbox -- {command}\n"
    )
}

/// Resolve the `.git/hooks` directory for the repo containing `start`.
/// Walks up until a `.git` dir (or worktree git-file) is found.
pub fn find_hooks_dir(start: &Path) -> Result<PathBuf, String> {
    let mut dir = start.to_path_buf();
    loop {
        let git = dir.join(".git");
        if git.is_dir() || git.is_file() {
            return Ok(dir.join(".git").join("hooks"));
        }
        if !dir.pop() {
            return Err("not inside a git repository (no .git found)".to_string());
        }
    }
}

/// Install the managed `pre-commit` hook. A pre-existing hook is moved
/// aside to `pre-commit.bak` (refusing to overwrite an existing
/// backup); reinstalling over a managed hook just rewrites it.
pub fn install(repo: &Path, command: &str) -> Result<PathBuf, String> {
    let hooks = find_hooks_dir(repo)?;
    fs::create_dir_all(&hooks).map_err(|e| format!("cannot create {}: {e}", hooks.display()))?;
    let hook_path = hooks.join("pre-commit");
    if hook_path.exists() {
        let current =
            fs::read_to_string(&hook_path).map_err(|e| format!("cannot read hook: {e}"))?;
        if !current.contains(HOOK_MARKER) {
            let backup = hooks.join("pre-commit.bak");
            if backup.exists() {
                return Err(format!(
                    "existing pre-commit hook plus {} backup; move it aside first",
                    backup.display()
                ));
            }
            fs::rename(&hook_path, &backup)
                .map_err(|e| format!("cannot back up existing hook: {e}"))?;
        }
    }
    fs::write(&hook_path, render_hook(command)).map_err(|e| format!("cannot write hook: {e}"))?;
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&hook_path)
            .map_err(|e| format!("cannot stat hook: {e}"))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&hook_path, perms).map_err(|e| format!("cannot chmod hook: {e}"))?;
    }
    #[cfg(windows)]
    eprintln!("[runner] unsupported on Windows: hook chmod (POSIX permissions)");
    Ok(hook_path)
}

/// Uninstall the managed hook. Only a script containing the manager
/// marker is removed; a `.bak` backup is restored when present.
/// Foreign hooks are left untouched (error, not deletion).
pub fn uninstall(repo: &Path) -> Result<Option<PathBuf>, String> {
    let hooks = find_hooks_dir(repo)?;
    let hook_path = hooks.join("pre-commit");
    if !hook_path.exists() {
        return Err("no pre-commit hook installed".to_string());
    }
    let current = fs::read_to_string(&hook_path).map_err(|e| format!("cannot read hook: {e}"))?;
    if !current.contains(HOOK_MARKER) {
        return Err("pre-commit hook is not runner-managed; refusing to remove".to_string());
    }
    fs::remove_file(&hook_path).map_err(|e| format!("cannot remove hook: {e}"))?;
    let backup = hooks.join("pre-commit.bak");
    if backup.exists() {
        fs::rename(&backup, &hook_path).map_err(|e| format!("cannot restore backup: {e}"))?;
        return Ok(Some(hook_path));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("runner-hook-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".git").join("hooks")).unwrap();
        dir
    }

    #[test]
    fn detect_prefers_cargo_then_npm_then_pytest() {
        let dir = scratch("detect");
        assert_eq!(detect_command(&dir), None);
        fs::write(dir.join("pyproject.toml"), "[tool.pytest]").unwrap();
        assert_eq!(detect_command(&dir).as_deref(), Some("pytest"));
        fs::write(dir.join("package.json"), "{}").unwrap();
        assert_eq!(detect_command(&dir).as_deref(), Some("npm test"));
        fs::write(dir.join("Cargo.toml"), "[package]").unwrap();
        assert_eq!(detect_command(&dir).as_deref(), Some("cargo test"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rendered_hook_routes_through_exec_and_marks_managed() {
        let script = render_hook("cargo test --workspace");
        assert!(script.starts_with("#!/bin/sh"));
        assert!(script.contains(HOOK_MARKER));
        assert!(script.contains("exec \"$RUNNER_BIN\" exec --no-sandbox -- cargo test --workspace"));
    }

    #[cfg(unix)]
    #[test]
    fn install_write_executable_and_reinstall_idempotent() {
        let dir = scratch("install");
        let path = install(&dir, "cargo test").unwrap();
        assert!(path.is_file());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        // Reinstall over a managed hook rewrites without backup.
        let path2 = install(&dir, "npm test").unwrap();
        assert_eq!(path, path2);
        assert!(!dir
            .join(".git")
            .join("hooks")
            .join("pre-commit.bak")
            .exists());
        assert!(fs::read_to_string(&path).unwrap().contains("npm test"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_backs_up_foreign_hook_and_uninstall_restores_it() {
        let dir = scratch("backup");
        let hooks = dir.join(".git").join("hooks");
        fs::write(hooks.join("pre-commit"), "#!/bin/sh\necho foreign\n").unwrap();
        install(&dir, "pytest").unwrap();
        assert!(hooks.join("pre-commit.bak").is_file());
        let restored = uninstall(&dir).unwrap();
        assert_eq!(restored, Some(hooks.join("pre-commit")));
        assert_eq!(
            fs::read_to_string(hooks.join("pre-commit")).unwrap(),
            "#!/bin/sh\necho foreign\n"
        );
        assert!(!hooks.join("pre-commit.bak").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn uninstall_refuses_foreign_hook_and_missing_hook() {
        let dir = scratch("refuse");
        assert!(uninstall(&dir).is_err());
        fs::write(
            dir.join(".git").join("hooks").join("pre-commit"),
            "#!/bin/sh\n",
        )
        .unwrap();
        let err = uninstall(&dir).unwrap_err();
        assert!(err.contains("not runner-managed"));
        assert!(dir.join(".git").join("hooks").join("pre-commit").is_file());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn find_hooks_dir_walks_up_and_fails_outside_repo() {
        let dir = scratch("walk");
        let nested = dir.join("a").join("b");
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            find_hooks_dir(&nested).unwrap(),
            dir.join(".git").join("hooks")
        );
        let outside =
            std::env::temp_dir().join(format!("runner-hook-no-repo-{}", std::process::id()));
        // Guard: temp dir itself could sit inside a repo on some hosts.
        if find_hooks_dir(&outside).is_err() {
            assert!(find_hooks_dir(&outside)
                .unwrap_err()
                .contains("not inside a git"));
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
