//! Official `actions/runner` worker lifecycle.
//!
//! The supervisor caches versioned worker packages (verified against
//! `github.com/actions/runner` releases), then launches ephemeral workers
//! with `./run.sh --jitconfig "<blob>"` — no `config.sh` registration step
//! on the host. The worker accepts exactly one job, then unregisters/exits.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::process::Command as TokioCommand;

/// Privileged root for pre-cached official worker packages.
pub const WORKER_CACHE_ROOT: &str = "/var/cache/runner";
/// Launcher script inside the extracted worker package.
pub const RUN_SCRIPT: &str = "./run.sh";
/// Default worker version (verified `actions/runner` release tag).
pub const DEFAULT_WORKER_VERSION: &str = "2.338.2";

/// Unprivileged cache root (`~/.runner/cache/worker/`).
pub fn user_cache_root() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".runner").join("cache").join("worker"))
}

/// Pick the privileged cache root when writable, else the user cache.
pub fn resolve_cache_root() -> PathBuf {
    let probe = Path::new(WORKER_CACHE_ROOT).join(".runner-write-probe");
    if std::fs::create_dir_all(WORKER_CACHE_ROOT).is_ok()
        && std::fs::write(&probe, b"").is_ok()
    {
        let _ = std::fs::remove_file(&probe);
        return PathBuf::from(WORKER_CACHE_ROOT);
    }
    user_cache_root().unwrap_or_else(|| PathBuf::from(WORKER_CACHE_ROOT))
}

/// Cache directory for one pinned worker version.
pub fn cache_dir(version: &str) -> PathBuf {
    cache_dir_in(&resolve_cache_root(), version)
}

/// Cache directory under an explicit root (tests).
pub fn cache_dir_in(root: &Path, version: &str) -> PathBuf {
    root.join(format!("worker-{version}"))
}

/// Release tarball name, e.g. `actions-runner-linux-x64-2.338.2.tar.gz`.
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("actions-runner-linux-{arch}-{version}.tar.gz")
}

/// Download URL for a release tarball.
pub fn release_url(version: &str, arch: &str) -> String {
    format!(
        "https://github.com/actions/runner/releases/download/v{version}/{}",
        tarball_name(version, arch)
    )
}

/// Host architecture label matching release assets.
pub fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "arm" => "arm",
        other => {
            eprintln!("runner: unknown arch {other}, defaulting asset to x64");
            "x64"
        }
    }
}

/// Ensure a versioned worker package is cached and return its directory.
/// Reuses a previous extraction when `run.sh` is already present.
pub async fn ensure_cached(version: &str) -> Result<PathBuf, String> {
    ensure_cached_in(&resolve_cache_root(), version, host_arch()).await
}

/// Ensure-cached under an explicit root (tests pass a temp dir; download
/// still hits the network only on cache miss).
pub async fn ensure_cached_in(root: &Path, version: &str, arch: &str) -> Result<PathBuf, String> {
    let dir = cache_dir_in(root, version);
    if dir.join("run.sh").exists() {
        return Ok(dir);
    }
    let url = release_url(version, arch);
    eprintln!("runner: downloading worker {version} ({arch})");
    let bytes = reqwest::get(&url)
        .await
        .map_err(|e| format!("worker download failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("worker download: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("worker download body: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("worker cache: {e}"))?;
    let tar = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(&dir).map_err(|e| format!("worker extract: {e}"))?;
    if !dir.join("run.sh").exists() {
        return Err("worker package missing run.sh after extract".to_string());
    }
    Ok(dir)
}

/// Ephemeral single-job worker launch specification.
#[derive(Debug, Clone)]
pub struct WorkerLaunch {
    /// Working directory (extracted worker package).
    pub work_dir: PathBuf,
    /// Single-use JIT config blob from `generate-jitconfig`.
    pub jit_config: String,
    /// Sandbox workspace setup for the child (mount namespaces + tmpfs).
    /// `None` runs unsandboxed (hosts blocking unprivileged userns).
    pub sandbox: Option<crate::sandbox::mounts::SandboxSpec>,
}

impl WorkerLaunch {
    pub fn new(work_dir: PathBuf, jit_config: impl Into<String>) -> Self {
        Self { work_dir, jit_config: jit_config.into(), sandbox: None }
    }

    pub fn sandboxed(mut self, spec: crate::sandbox::mounts::SandboxSpec) -> Self {
        self.sandbox = Some(spec);
        self
    }

    /// Exact argv: `./run.sh --jitconfig <blob>`.
    pub fn argv(&self) -> Vec<String> {
        vec![
            RUN_SCRIPT.to_string(),
            "--jitconfig".to_string(),
            self.jit_config.clone(),
        ]
    }

    /// Build the spawn command with sandbox env clamps applied.
    pub fn command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(RUN_SCRIPT);
        cmd.current_dir(&self.work_dir)
            .arg("--jitconfig")
            .arg(&self.jit_config);
        for (key, value) in crate::governor::topology::sandbox_env_clamps() {
            cmd.env(key, value);
        }
        cmd
    }
}

/// Worker exit outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerOutcome {
    /// Exit code when the worker exited by itself.
    pub exit_code: Option<i32>,
    /// True when the supervisor killed the worker (timeout/shutdown).
    pub killed: bool,
}

/// Attach a pid to the supervisor slice (best-effort: logs, never fails).
fn attach_to_slice(slice: &crate::governor::cgroup::CgroupSlice, pid: u32) {
    let procs = slice.path().join("cgroup.procs");
    if let Err(e) = std::fs::write(&procs, pid.to_string()) {
        eprintln!("runner: cgroup attach of pid {pid} failed ({e}); unsliced");
    }
}

/// Spawn the worker, attach it to the cgroup slice, and supervise it to
/// completion. Kills the child on timeout. Never freezes: a stuck worker
/// is killed, never suspended mid-test.
pub async fn run_supervised(
    launch: &WorkerLaunch,
    slice: Option<&crate::governor::cgroup::CgroupSlice>,
    timeout: Duration,
) -> io::Result<WorkerOutcome> {
    let mut cmd = TokioCommand::new(RUN_SCRIPT);
    cmd.current_dir(&launch.work_dir)
        .arg("--jitconfig")
        .arg(&launch.jit_config)
        .kill_on_drop(true);
    for (key, value) in crate::governor::topology::sandbox_env_clamps() {
        cmd.env(key, value);
    }
    if let Some(spec) = launch.sandbox.clone() {
        // SAFETY: pre_exec runs after fork in the child only. The closure
        // performs only async-signal-safe syscalls plus synchronous file
        // writes before exec; on failure the child aborts the spawn.
        unsafe {
            cmd.pre_exec(move || crate::sandbox::mounts::sandbox_pre_exec(&spec));
        }
    }
    let mut child = cmd.spawn()?;
    if let (Some(pid), Some(slice)) = (child.id(), slice) {
        attach_to_slice(slice, pid);
    }
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => Ok(WorkerOutcome { exit_code: status.code(), killed: false }),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            child.kill().await.ok();
            Ok(WorkerOutcome { exit_code: None, killed: true })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jit_launch_argv_has_no_config_step() {
        let launch = WorkerLaunch::new("/tmp/w".into(), "BLOB");
        assert_eq!(launch.argv(), vec!["./run.sh", "--jitconfig", "BLOB"]);
    }

    #[test]
    fn release_asset_names_match_github() {
        assert_eq!(
            tarball_name("2.338.2", "x64"),
            "actions-runner-linux-x64-2.338.2.tar.gz"
        );
        assert_eq!(
            release_url("2.338.2", "x64"),
            "https://github.com/actions/runner/releases/download/\
             v2.338.2/actions-runner-linux-x64-2.338.2.tar.gz"
        );
    }

    #[test]
    fn cache_dir_is_versioned() {
        assert_eq!(
            cache_dir_in(Path::new("/cache"), "2.338.2"),
            PathBuf::from("/cache/worker-2.338.2")
        );
    }

    #[tokio::test]
    async fn supervises_fake_worker_exit_codes() {
        // Fake worker package: a run.sh honoring --jitconfig and exiting 0/3.
        let dir = crate::test_support::TempDir::new("worker").unwrap();
        let pkg = dir.path().join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("run.sh"), "#!/bin/sh\nexit ${FAKE_EXIT:-0}\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pkg.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let launch = WorkerLaunch::new(pkg, "BLOB");
        let outcome =
            run_supervised(&launch, None, Duration::from_secs(10)).await.unwrap();
        assert_eq!(outcome, WorkerOutcome { exit_code: Some(0), killed: false });
    }

    #[tokio::test]
    async fn kills_worker_on_timeout() {
        let dir = crate::test_support::TempDir::new("worker-timeout").unwrap();
        let pkg = dir.path().join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("run.sh"), "#!/bin/sh\nsleep 30\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pkg.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let launch = WorkerLaunch::new(pkg, "BLOB");
        let outcome =
            run_supervised(&launch, None, Duration::from_millis(300)).await.unwrap();
        assert!(outcome.killed);
    }
}
