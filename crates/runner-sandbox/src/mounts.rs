//! Mount namespace and filesystem isolation.
//!
//! Jobs run in an unprivileged user namespace
//! (`unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID)`) with a clean
//! `tmpfs` workspace. Personal directories (`/home/*`) are never mounted.
//! On worker exit the workspace is cryptographically scrubbed and removed.
//!
//! Hosts that block unprivileged user namespaces (e.g. Ubuntu 24.04+
//! AppArmor defaults) cannot use Tier-2 container sandboxing; those jobs
//! require Tier-1 microVMs (roadmap) or run unsandboxed with an explicit
//! operator override. [`probe_userns`] detects support at runtime.

use std::io;
use std::path::{Path, PathBuf};

/// Root for ephemeral per-job workspaces (wiped on completion).
pub const JOB_ROOT: &str = "/tmp/runner-jobs";
/// In-sandbox workspace mount point.
pub const WORKSPACE_MOUNT: &str = "/workspace";
/// Env override for the job root (tests).
pub const JOB_ROOT_ENV: &str = "RUNNER_JOB_ROOT";

/// Resolve the job workspace root.
pub fn job_root() -> PathBuf {
    std::env::var(JOB_ROOT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(JOB_ROOT))
}

/// Workspace directory for one job id.
pub fn job_workspace(job_id: &str) -> PathBuf {
    job_root().join(job_id)
}

/// Namespace flags for the unprivileged sandbox (Linux-only; other
/// platforms have no user namespaces and always degrade).
#[cfg(target_os = "linux")]
pub fn unshare_flags() -> nix::sched::CloneFlags {
    use nix::sched::CloneFlags;
    CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID
}

/// Reject any mount source under `/home` (invariant: never mount `/home/*`).
pub fn validate_no_home_mount(sources: &[&Path]) -> Result<(), String> {
    for source in sources {
        if source.starts_with("/home") {
            return Err(format!(
                "refusing to mount {}: /home/* is never mounted into job sandboxes",
                source.display()
            ));
        }
    }
    Ok(())
}

/// Sandbox setup applied in the worker child before exec.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Host workspace path (tmpfs-mounted over in the child).
    pub workspace: PathBuf,
}

impl SandboxSpec {
    pub fn new(workspace: PathBuf) -> Result<Self, String> {
        validate_no_home_mount(&[&workspace])?;
        Ok(Self { workspace })
    }
}

/// Child-side setup for `Command::pre_exec`: enter unprivileged namespaces,
/// map our own UID/GID 1:1, mount tmpfs over the workspace, chdir into it.
///
/// Returns `Err` (aborting the spawn) when any step fails. On macOS this
/// applies the Seatbelt profile instead (soft-fail: a failed apply logs
/// and continues unsandboxed). Elsewhere a no-op (callers gate on
/// [`probe_userns`], always false there), kept so `pre_exec` closures
/// compile on every Unix.
pub fn sandbox_pre_exec(spec: &SandboxSpec) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::mount::{mount, MsFlags};
        use nix::sched::unshare;
        use nix::unistd::{Gid, Uid};

        validate_no_home_mount(&[&spec.workspace])
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        unshare(unshare_flags())?;

        // 1:1 UID/GID mapping (unprivileged single-map write).
        std::fs::write("/proc/self/setgroups", "deny").ok();
        let uid = Uid::current();
        let gid = Gid::current();
        std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;
        std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;

        std::fs::create_dir_all(&spec.workspace)?;
        mount(
            Some("tmpfs"),
            &spec.workspace,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("size=80%,mode=755"),
        )?;
        std::env::set_current_dir(&spec.workspace)?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        // Mirror the Linux cwd contract (the parent skips
        // `current_dir` when a spec rides along).
        std::env::set_current_dir(&spec.workspace)?;
        // Seatbelt matches resolved paths; canonicalize so a
        // `/tmp`-style workspace matches kernel-side checks.
        let workspace =
            std::fs::canonicalize(&spec.workspace).unwrap_or_else(|_| spec.workspace.clone());
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        // Per-user temp (macOS: /var/folders/...) stays writable; an
        // unset or unresolvable TMPDIR simply omits the carve-out.
        let tmpdir = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .and_then(|tmp| std::fs::canonicalize(&tmp).ok());
        if crate::seatbelt::is_sandboxed() {
            eprintln!("[runner] seatbelt: already sandboxed, skipping nested profile");
            return Ok(());
        }
        let profile =
            crate::seatbelt::build_profile(&workspace, home.as_deref(), tmpdir.as_deref());
        match crate::seatbelt::apply_profile(&profile) {
            Ok(()) => eprintln!("[runner] seatbelt: Tier-2 sandbox active"),
            // Soft-fail (same posture as the Linux userns probe):
            // `--strict` will harden this in a future milestone.
            Err(e) => {
                eprintln!("[runner] seatbelt: sandbox_init failed ({e}); continuing unsandboxed")
            }
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = spec;
        Ok(())
    }
}

/// Probe unprivileged userns support by spawning `true` with the child
/// setup. Used once at startup to choose sandboxed vs plain spawning.
#[cfg(target_os = "linux")]
pub fn probe_userns() -> bool {
    let dir = std::env::temp_dir().join(format!("runner-userns-probe-{}", std::process::id()));
    let spec = match SandboxSpec::new(dir.clone()) {
        Ok(spec) => spec,
        Err(_) => return false,
    };
    std::fs::create_dir_all(&dir).ok();
    // SAFETY: pre_exec runs after fork in the child only.
    let mut cmd = std::process::Command::new("true");
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || sandbox_pre_exec(&spec));
    }
    let ok = cmd.status().map(|s| s.success()).unwrap_or(false);
    let _ = std::fs::remove_dir_all(&dir);
    ok
}

/// Non-Linux hosts have no user namespaces; Tier-2 always degrades to
/// governed direct spawning (plus platform QoS where available).
#[cfg(not(target_os = "linux"))]
pub fn probe_userns() -> bool {
    false
}

/// Overwrite a file's bytes with OS randomness (best-effort per file).
fn scrub_file(path: &Path) -> io::Result<()> {
    use rand::RngCore;
    let len = std::fs::metadata(path)?.len();
    if len == 0 {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let mut remaining = len;
    let mut chunk = [0u8; 65536];
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let n = remaining.min(chunk.len() as u64) as usize;
        rand::rngs::OsRng.fill_bytes(&mut chunk[..n]);
        file.write_all(&chunk[..n])?;
        remaining -= n as u64;
    }
    file.flush()?;
    Ok(())
}

/// Recursively scrub regular files under `root` (best-effort), then remove
/// the tree. Returns the count of scrubbed files.
pub fn scrub_workspace(root: &Path) -> usize {
    fn visit(dir: &Path, count: &mut usize) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                visit(&path, count);
            } else if path.is_file() && scrub_file(&path).is_ok() {
                *count += 1;
            }
        }
    }

    let mut count = 0;
    visit(root, &mut count);
    let _ = std::fs::remove_dir_all(root);
    count
}

/// Owned workspace: created on construction, scrubbed + removed on drop.
pub struct Workspace {
    path: PathBuf,
    scrubbed_files: usize,
}

impl Workspace {
    /// Create a fresh workspace directory for one job id.
    pub fn create(job_id: &str) -> io::Result<Self> {
        let path = job_workspace(&sanitize_job_id(job_id));
        validate_no_home_mount(&[&path])
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        std::fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            scrubbed_files: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sandbox spec mounting tmpfs over this workspace in the child.
    pub fn sandbox_spec(&self) -> Result<SandboxSpec, String> {
        SandboxSpec::new(self.path.clone())
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        self.scrubbed_files = scrub_workspace(&self.path);
    }
}

/// Strip path separators from job ids so workspaces cannot escape the root.
pub fn sanitize_job_id(job_id: &str) -> String {
    job_id
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == '.' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_mounts_are_rejected() {
        assert!(validate_no_home_mount(&[Path::new("/home/linux")]).is_err());
        assert!(validate_no_home_mount(&[Path::new("/home/linux/.ssh")]).is_err());
        assert!(validate_no_home_mount(&[Path::new("/workspace")]).is_ok());
    }

    #[test]
    fn job_ids_cannot_escape_root() {
        assert_eq!(sanitize_job_id("../../etc"), "______etc");
        // Single snapshot: a sibling test mutates RUNNER_JOB_ROOT, so the
        // root must be read once for both join and containment check.
        let root = job_root();
        let path = root.join(sanitize_job_id("../../etc"));
        assert!(path.starts_with(&root));
    }

    #[test]
    fn workspace_lifecycle_scrubs_on_drop() {
        let dir = runner_core::test_support::TempDir::new("ws").unwrap();
        std::env::set_var(JOB_ROOT_ENV, dir.path());
        let secret = {
            let ws = Workspace::create("job-1").unwrap();
            let secret = ws.path().join("secret.txt");
            std::fs::write(&secret, "s3cret").unwrap();
            assert!(secret.exists());
            secret
        };
        assert!(!secret.exists());
        std::env::remove_var(JOB_ROOT_ENV);
    }

    #[test]
    fn scrub_counts_files() {
        let dir = runner_core::test_support::TempDir::new("scrub").unwrap();
        std::fs::write(dir.path().join("a"), "x").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b"), "y").unwrap();
        assert_eq!(scrub_workspace(dir.path()), 2);
        assert!(!dir.path().exists());
    }
}
