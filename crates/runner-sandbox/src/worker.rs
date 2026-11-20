//! Official `actions/runner` worker lifecycle.
//!
//! The supervisor caches versioned worker packages (verified against
//! `github.com/actions/runner` releases), then launches ephemeral workers
//! with `./run.sh --jitconfig "<blob>"` — no `config.sh` registration step
//! on the host. The worker accepts exactly one job, then unregisters/exits.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::process::Command as TokioCommand;

use runner_core::governor::darwin::QosBackend;

/// Privileged root for pre-cached official worker packages.
pub const WORKER_CACHE_ROOT: &str = "/var/cache/runner";
/// Launcher script inside the extracted worker package.
#[cfg(unix)]
pub const RUN_SCRIPT: &str = "./run.sh";
/// Launcher script inside the extracted worker package.
#[cfg(windows)]
pub const RUN_SCRIPT: &str = "run.cmd";

/// Launcher file name for presence checks (`RUN_SCRIPT` without `./`).
#[cfg(unix)]
fn launcher_file_name() -> &'static str {
    "run.sh"
}
/// Launcher file name for presence checks.
#[cfg(windows)]
fn launcher_file_name() -> &'static str {
    "run.cmd"
}
/// Default worker version (verified `actions/runner` release tag).
pub const DEFAULT_WORKER_VERSION: &str = "2.338.2";

/// Unprivileged cache root (`~/.runner/cache/worker/`,
/// `%APPDATA%\runner\cache\worker` on Windows).
pub fn user_cache_root() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(|home| {
            PathBuf::from(home)
                .join(".runner")
                .join("cache")
                .join("worker")
        })
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|dir| {
            PathBuf::from(dir)
                .join("runner")
                .join("cache")
                .join("worker")
        })
    }
}

/// Pick the privileged cache root when writable, else the user cache.
pub fn resolve_cache_root() -> PathBuf {
    let probe = Path::new(WORKER_CACHE_ROOT).join(".runner-write-probe");
    if std::fs::create_dir_all(WORKER_CACHE_ROOT).is_ok() && std::fs::write(&probe, b"").is_ok() {
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

/// Release tarball name, e.g. `actions-runner-linux-x64-2.338.2.tar.gz`
/// (`actions-runner-win-x64-*.zip` on Windows, verified against the
/// `actions/runner` release assets).
#[cfg(unix)]
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("actions-runner-linux-{arch}-{version}.tar.gz")
}

/// Release archive name, e.g. `actions-runner-win-x64-2.338.2.zip`.
#[cfg(windows)]
pub fn tarball_name(version: &str, arch: &str) -> String {
    format!("actions-runner-win-{arch}-{version}.zip")
}

/// Download URL for a release tarball.
pub fn release_url(version: &str, arch: &str) -> String {
    format!(
        "https://github.com/actions/runner/releases/download/v{version}/{}",
        tarball_name(version, arch)
    )
}

/// Unpack a downloaded worker archive: gzip-tarball on unix, zip on
/// Windows (the `actions/runner` Windows assets ship as `.zip`).
#[cfg(unix)]
fn extract_archive(bytes: &[u8], dir: &Path) -> Result<(), String> {
    let tar = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(tar);
    archive
        .unpack(dir)
        .map_err(|e| format!("worker extract: {e}"))
}

/// Unpack a downloaded worker archive: gzip-tarball on unix, zip on
/// Windows (the `actions/runner` Windows assets ship as `.zip`).
#[cfg(windows)]
fn extract_archive(bytes: &[u8], dir: &Path) -> Result<(), String> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("worker extract: {e}"))?;
    archive
        .extract(dir)
        .map_err(|e| format!("worker extract: {e}"))
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
    if dir.join(launcher_file_name()).exists() {
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
    extract_archive(&bytes[..], &dir)?;
    let launcher = launcher_file_name();
    if !dir.join(launcher).exists() {
        return Err(format!("worker package missing {launcher} after extract"));
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
    pub sandbox: Option<crate::mounts::SandboxSpec>,
    /// Extra environment for the child (e.g. cache endpoint injection).
    pub env: Vec<(String, String)>,
}

impl WorkerLaunch {
    pub fn new(work_dir: PathBuf, jit_config: impl Into<String>) -> Self {
        Self {
            work_dir,
            jit_config: jit_config.into(),
            sandbox: None,
            env: Vec::new(),
        }
    }

    pub fn sandboxed(mut self, spec: crate::mounts::SandboxSpec) -> Self {
        self.sandbox = Some(spec);
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
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
        for (key, value) in runner_core::governor::topology::sandbox_env_clamps() {
            cmd.env(key, value);
        }
        for (key, value) in &self.env {
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
#[cfg(unix)]
fn attach_to_slice(slice: &runner_core::governor::cgroup::CgroupSlice, pid: u32) {
    let procs = slice.path().join("cgroup.procs");
    if let Err(e) = std::fs::write(&procs, pid.to_string()) {
        eprintln!("runner: cgroup attach of pid {pid} failed ({e}); unsliced");
    }
}

/// No cgroup slices on Windows; silently skipped (the governor-disabled
/// notice is emitted once by the dispatch path, not per spawn).
#[cfg(windows)]
fn attach_to_slice(_slice: &runner_core::governor::cgroup::CgroupSlice, _pid: u32) {}

/// Spawn the worker, attach it to the cgroup slice, and supervise it to
/// Spawn with `ETXTBSY` tolerance: under parallel load the kernel may
/// report the just-written worker script busy (errno 26). Back off 10ms
/// and retry up to 5 times; every other error returns immediately so
/// genuine spawn failures stay loud and fast.
async fn spawn_with_busy_retry(cmd: &mut TokioCommand) -> io::Result<tokio::process::Child> {
    const RETRIES: u32 = 5;
    let mut attempt = 0;
    loop {
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && attempt < RETRIES => {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// completion. Kills the child on timeout. Never freezes: a stuck worker
/// is killed, never suspended mid-test.
pub async fn run_supervised(
    launch: &WorkerLaunch,
    slice: Option<&runner_core::governor::cgroup::CgroupSlice>,
    timeout: Duration,
    qos: Arc<dyn QosBackend>,
) -> io::Result<WorkerOutcome> {
    let mut cmd = TokioCommand::new(RUN_SCRIPT);
    cmd.current_dir(&launch.work_dir)
        .arg("--jitconfig")
        .arg(&launch.jit_config)
        .kill_on_drop(true);
    for (key, value) in runner_core::governor::topology::sandbox_env_clamps() {
        cmd.env(key, value);
    }
    for (key, value) in &launch.env {
        cmd.env(key, value);
    }
    // QoS hook always installed (no-op off macOS); sandbox setup rides
    // along only when the launch carries a spec.
    runner_core::governor::darwin::install_child_hook(
        &mut cmd,
        qos,
        launch
            .sandbox
            .clone()
            .map(|spec| move || crate::mounts::sandbox_pre_exec(&spec)),
    );
    let mut child = spawn_with_busy_retry(&mut cmd).await?;
    if let (Some(pid), Some(slice)) = (child.id(), slice) {
        attach_to_slice(slice, pid);
    }
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => Ok(WorkerOutcome {
            exit_code: status.code(),
            killed: false,
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            child.kill().await.ok();
            Ok(WorkerOutcome {
                exit_code: None,
                killed: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_core::governor::darwin::{DarwinQos, MockQos};

    /// Write a test script and force it to stable storage before launch,
    /// closing the ETXTBSY race on the writer side.
    fn write_script(path: &Path, contents: &str) {
        use std::io::Write;
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }

    #[tokio::test]
    async fn busy_retry_ignores_other_errors_fast() {
        // Nonexistent binary: NotFound must propagate immediately with no
        // retry backoff (well under the 5x10ms busy budget).
        let start = std::time::Instant::now();
        let mut cmd = TokioCommand::new("/no/such/binary-xyz");
        let err = spawn_with_busy_retry(&mut cmd).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

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
        let dir = runner_core::test_support::TempDir::new("worker").unwrap();
        let pkg = dir.path().join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        write_script(&pkg.join("run.sh"), "#!/bin/sh\nexit ${FAKE_EXIT:-0}\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pkg.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let launch = WorkerLaunch::new(pkg, "BLOB");
        let outcome = run_supervised(&launch, None, Duration::from_secs(10), Arc::new(DarwinQos))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            WorkerOutcome {
                exit_code: Some(0),
                killed: false
            }
        );
    }

    #[tokio::test]
    async fn kills_worker_on_timeout() {
        let dir = runner_core::test_support::TempDir::new("worker-timeout").unwrap();
        let pkg = dir.path().join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        write_script(&pkg.join("run.sh"), "#!/bin/sh\nsleep 30\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pkg.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let launch = WorkerLaunch::new(pkg, "BLOB");
        let outcome = run_supervised(
            &launch,
            None,
            Duration::from_millis(300),
            Arc::new(DarwinQos),
        )
        .await
        .unwrap();
        assert!(outcome.killed);
    }

    #[tokio::test]
    async fn supervised_spawn_applies_qos_best_effort() {
        let dir = runner_core::test_support::TempDir::new("worker-qos").unwrap();
        let pkg = dir.path().join("pkg");
        std::fs::create_dir_all(&pkg).unwrap();
        write_script(&pkg.join("run.sh"), "#!/bin/sh\nexit 0\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pkg.join("run.sh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        // File-backed mock: the hook runs post-fork, so only the log
        // file proves placement.
        let log = dir.path().join("qos.log");
        let mock = Arc::new(MockQos::with_log(log.clone()));
        let launch = WorkerLaunch::new(pkg.clone(), "BLOB");
        let outcome = run_supervised(&launch, None, Duration::from_secs(10), mock)
            .await
            .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        // The hook applies once per spawn attempt, and the deliberate
        // ETXTBSY retry (spawn_with_busy_retry) may legitimately apply
        // it twice under parallel CI load — so assert placement
        // (nonempty, all lines valid), not an exact count.
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            !logged.is_empty() && logged.lines().all(|line| line == "process"),
            "QoS hook must apply at least once per spawn; got: {logged:?}"
        );
        // A failing backend never fails the spawn.
        let failing = Arc::new(MockQos::new());
        failing.set_failing();
        let launch = WorkerLaunch::new(pkg, "BLOB");
        let outcome = run_supervised(&launch, None, Duration::from_secs(10), failing)
            .await
            .unwrap();
        assert_eq!(outcome.exit_code, Some(0));
    }
}
