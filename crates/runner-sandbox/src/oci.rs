//! OCI container tier: host runtime probing and v1.0.2 bundle
//! generation. Phase 1 ships discovery + spec emission; execution
//! binds a probed runtime in a later phase.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::mounts::validate_no_home_mount;

/// OCI runtimes in probe order: standalone rootless runtimes first
/// (fast C, reference, Rust-native), then engine CLIs, daemon last.
pub const OCI_RUNTIME_CANDIDATES: [&str; 5] = ["crun", "runc", "youki", "podman", "docker"];

/// True when `path` names a runnable binary: a regular file, on unix
/// with at least one execute bit set.
fn is_runnable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn find_in_dirs(name: &str, dirs: impl Iterator<Item = PathBuf>) -> Option<PathBuf> {
    dirs.map(|dir| dir.join(name))
        .find(|path| is_runnable(path))
}

/// `which` over an explicit PATH value (pure; unit-tested without
/// touching the process environment).
pub fn find_on_path_with(name: &str, path_var: &str) -> Option<PathBuf> {
    find_in_dirs(name, std::env::split_paths(path_var))
}

/// `which` over the process PATH.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| find_in_dirs(name, std::env::split_paths(&path)))
}

/// Discover the OCI runtime binary: an explicit config override wins
/// (a missing override fails closed naming the path); otherwise the
/// first runnable candidate on PATH in [`OCI_RUNTIME_CANDIDATES`]
/// order. Absence reports every name searched so `--strict` callers
/// (and humans) get an actionable diagnostic; strict enforcement
/// itself binds at execution time.
pub fn probe_oci_runtime(explicit: Option<&Path>) -> Result<PathBuf, String> {
    probe_oci_runtime_with(explicit, &|name| find_on_path(name))
}

fn probe_oci_runtime_with(
    explicit: Option<&Path>,
    lookup: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(path) = explicit {
        return if is_runnable(path) {
            Ok(path.to_path_buf())
        } else {
            Err(format!(
                "configured OCI runtime '{}' is not a runnable binary",
                path.display()
            ))
        };
    }
    for candidate in OCI_RUNTIME_CANDIDATES {
        if let Some(path) = lookup(candidate) {
            return Ok(path);
        }
    }
    Err(format!(
        "no OCI runtime found on PATH (looked for {}); install one or set [sandbox.container] runtime_path",
        OCI_RUNTIME_CANDIDATES.join(", ")
    ))
}

/// OCI runtime-spec version this generator targets.
pub const OCI_SPEC_VERSION: &str = "1.0.2";
/// Job working directory inside the container.
pub const OCI_WORKDIR: &str = "/workspace";

/// Invoker UID/GID for the rootless 1:1 user-namespace mapping.
fn invoker_ids() -> (u32, u32) {
    #[cfg(unix)]
    {
        (
            nix::unistd::Uid::current().as_raw(),
            nix::unistd::Gid::current().as_raw(),
        )
    }
    #[cfg(not(unix))]
    {
        (0, 0)
    }
}

/// OCI `config.json` bundle specification (runtime-spec subset).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciBundleSpec {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub process: OciProcess,
    pub root: OciRoot,
    pub hostname: String,
    pub mounts: Vec<OciMount>,
    pub linux: OciLinux,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciProcess {
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub terminal: bool,
    #[serde(rename = "noNewPrivileges")]
    pub no_new_privileges: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciRoot {
    pub path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciMount {
    pub destination: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub mount_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub ns_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciIdMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinuxCpu {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinuxMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinuxResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<OciLinuxCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<OciLinuxMemory>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciLinux {
    pub namespaces: Vec<OciNamespace>,
    #[serde(rename = "uidMappings", default, skip_serializing_if = "Vec::is_empty")]
    pub uid_mappings: Vec<OciIdMapping>,
    #[serde(rename = "gidMappings", default, skip_serializing_if = "Vec::is_empty")]
    pub gid_mappings: Vec<OciIdMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<OciLinuxResources>,
}

/// Default mounts for a runnable bundle: `/proc`, `/dev`, read-only
/// `/sys`, and the tmpfs job workspace.
fn default_mounts() -> Vec<OciMount> {
    vec![
        OciMount {
            destination: "/proc".to_string(),
            mount_type: Some("proc".to_string()),
            source: Some("proc".to_string()),
            options: vec![],
        },
        OciMount {
            destination: "/dev".to_string(),
            mount_type: Some("tmpfs".to_string()),
            source: Some("tmpfs".to_string()),
            options: ["nosuid", "strictatime", "mode=755"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
        OciMount {
            destination: "/sys".to_string(),
            mount_type: Some("sysfs".to_string()),
            source: Some("sysfs".to_string()),
            options: ["nosuid", "noexec", "nodev", "ro"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
        OciMount {
            destination: OCI_WORKDIR.to_string(),
            mount_type: Some("tmpfs".to_string()),
            source: Some("tmpfs".to_string()),
            options: ["nosuid", "nodev", "mode=755"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        },
    ]
}

impl OciBundleSpec {
    /// Minimal runnable bundle: entrypoint argv + env, cwd `/workspace`,
    /// rootless userns mapped 1:1 to the invoker, default mounts,
    /// read-only rootfs, no resource limits (see [`with_limits`](Self::with_limits)).
    pub fn new(args: Vec<String>, env: Vec<String>) -> Self {
        let (uid, gid) = invoker_ids();
        Self {
            oci_version: OCI_SPEC_VERSION.to_string(),
            process: OciProcess {
                user: OciUser { uid: 0, gid: 0 },
                args,
                env,
                cwd: OCI_WORKDIR.to_string(),
                terminal: false,
                no_new_privileges: true,
            },
            root: OciRoot {
                path: "rootfs".to_string(),
                readonly: true,
            },
            hostname: "runner-job".to_string(),
            mounts: default_mounts(),
            linux: OciLinux {
                namespaces: ["pid", "network", "mount", "ipc", "uts", "user"]
                    .into_iter()
                    .map(|ns| OciNamespace {
                        ns_type: ns.to_string(),
                    })
                    .collect(),
                uid_mappings: vec![OciIdMapping {
                    container_id: 0,
                    host_id: uid,
                    size: 1,
                }],
                gid_mappings: vec![OciIdMapping {
                    container_id: 0,
                    host_id: gid,
                    size: 1,
                }],
                resources: None,
            },
        }
    }

    /// Extra bind mount (host `source` → container `destination`).
    /// Host sources under `/home` fail closed (existing invariant);
    /// the destination is container-namespaced and must be absolute.
    pub fn with_mount(
        mut self,
        source: &Path,
        destination: &str,
        readonly: bool,
    ) -> Result<Self, String> {
        validate_no_home_mount(&[source])?;
        if !destination.starts_with('/') {
            return Err(format!(
                "container mount destination must be absolute, got '{destination}'"
            ));
        }
        let mut options = vec!["rbind".to_string()];
        if readonly {
            options.push("ro".to_string());
        }
        self.mounts.push(OciMount {
            destination: destination.to_string(),
            mount_type: Some("bind".to_string()),
            source: Some(source.display().to_string()),
            options,
        });
        Ok(self)
    }

    /// cgroup v2 limits: CPU weight (1–10000) + memory max in bytes.
    /// Out-of-range values fail closed rather than emitting an
    /// invalid bundle.
    pub fn with_limits(mut self, cpu_weight: u64, memory_max_bytes: u64) -> Result<Self, String> {
        if !(1..=10000).contains(&cpu_weight) {
            return Err(format!(
                "container cpu weight must be 1-10000, got {cpu_weight}"
            ));
        }
        if memory_max_bytes == 0 || memory_max_bytes > i64::MAX as u64 {
            return Err(format!(
                "container memory max must be 1-{} bytes, got {memory_max_bytes}",
                i64::MAX as u64
            ));
        }
        self.linux.resources = Some(OciLinuxResources {
            cpu: Some(OciLinuxCpu {
                weight: Some(cpu_weight),
            }),
            memory: Some(OciLinuxMemory {
                limit: Some(memory_max_bytes as i64),
            }),
        });
        Ok(self)
    }

    /// Serialize to the bundle `config.json` value.
    pub fn to_json(&self) -> Result<serde_json::Value, String> {
        serde_json::to_value(self).map_err(|e| format!("cannot encode bundle spec: {e}"))
    }
}

/// Ring capacity for container stdio capture (tail only; the live
/// streams always go to our own stdout/stderr).
const RING_CAP_BYTES: usize = 32 * 1024;
/// Grace drain between SIGTERM and SIGKILL on timeout.
const TIMEOUT_GRACE: std::time::Duration = std::time::Duration::from_secs(4);
/// Bound on the force-delete step so a wedged runtime cannot hang teardown.
const TEARDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

type OutputRing = std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>;

/// Unique container id (`oci-<pid>-<n>`: runc-safe charset).
fn next_container_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "oci-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

/// Host environment as `K=V` pairs (lossy: containers take bytes).
fn host_env() -> Vec<String> {
    std::env::vars_os()
        .map(|(key, value)| format!("{}={}", key.to_string_lossy(), value.to_string_lossy()))
        .collect()
}

/// Runtime CLI argv for one bundle: standalone runtimes share the
/// `run --bundle <dir> <id>` shape (unknown override binaries are
/// assumed compatible); engine CLIs (`podman`/`docker`) manage their
/// own storage and fail closed with a deferral diagnostic.
fn runtime_argv(runtime: &Path, bundle: &Path, id: &str) -> Result<Vec<String>, String> {
    if let Some(stem) = runtime.file_stem().and_then(|stem| stem.to_str()) {
        if stem == "podman" || stem == "docker" {
            return Err(format!(
                "OCI runtime '{stem}' is a container engine: engine-backed execution needs image flows (later phase); override [sandbox.container] runtime_path with crun/runc/youki"
            ));
        }
    }
    Ok(vec![
        runtime.display().to_string(),
        "run".to_string(),
        "--bundle".to_string(),
        bundle.display().to_string(),
        id.to_string(),
    ])
}

/// Assemble one ephemeral bundle: `<parent>/<id>/` with `config.json`
/// plus a minimal `rootfs/` directory (image population lands with
/// the engine flows; Phase 2 verifies lifecycle, not payloads).
fn assemble_bundle_at(parent: &Path, id: &str, spec: &OciBundleSpec) -> Result<PathBuf, String> {
    let dir = parent.join(id);
    validate_no_home_mount(&[&dir])?;
    std::fs::create_dir_all(dir.join("rootfs"))
        .map_err(|e| format!("cannot stage container bundle {}: {e}", dir.display()))?;
    let config = spec
        .to_json()
        .and_then(|json| serde_json::to_string_pretty(&json).map_err(|e| e.to_string()))
        .map_err(|e| format!("cannot encode bundle spec: {e}"))?;
    std::fs::write(dir.join("config.json"), config)
        .map_err(|e| format!("cannot write bundle config {}: {e}", dir.display()))?;
    Ok(dir)
}

/// RAII bundle guard: explicit async teardown runs on every normal
/// exit path; `Drop` is the panic/early-return backstop (sync,
/// fire-and-forget — never waits, never panics).
struct OciBundleGuard {
    runtime: PathBuf,
    id: String,
    dir: Option<PathBuf>,
}

impl OciBundleGuard {
    fn new(runtime: PathBuf, id: String, dir: PathBuf) -> Self {
        Self {
            runtime,
            id,
            dir: Some(dir),
        }
    }

    /// Force-delete the container (bounded) and scrub the bundle.
    /// Idempotent: safe to call on every exit path.
    async fn teardown(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };
        let delete = tokio::process::Command::new(&self.runtime)
            .args(["delete", "--force", self.id.as_str()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status();
        let _ = tokio::time::timeout(TEARDOWN_TIMEOUT, delete).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}

impl Drop for OciBundleGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = std::process::Command::new(&self.runtime)
                .args(["delete", "--force", self.id.as_str()])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// Pump one pipe to our own stdio plus the shared tail ring.
async fn pump_pipe<R, W>(mut reader: R, mut sink: W, ring: OutputRing)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let _ = sink.write_all(&buf[..n]).await;
                if let Ok(mut ring) = ring.lock() {
                    ring.extend(buf[..n].iter().copied());
                    while ring.len() > RING_CAP_BYTES {
                        ring.pop_front();
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// Timeout escalation: polite SIGTERM + grace drain, then a
/// runtime-level `kill KILL` plus group SIGKILL and a direct child
/// kill (best-effort at every step; Windows has no SIGTERM so it
/// kills directly). Unix signals target the child's process group
/// (fresh per spawn, so only our tree): orphaned grandchildren die
/// with it instead of wedging the stdio pumps on held pipes.
async fn escalate_timeout(child: &mut tokio::process::Child, runtime: &Path, id: &str) {
    #[cfg(unix)]
    {
        if let Some(pid) = child.id() {
            // Recheck liveness first: never signal a possibly
            // recycled pid when the child already reaped.
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            // Negative pid = process group (fresh group per spawn).
            let group = nix::unistd::Pid::from_raw(-(pid as i32));
            let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGTERM);
            if tokio::time::timeout(TIMEOUT_GRACE, child.wait())
                .await
                .is_ok()
            {
                return;
            }
            let kill = tokio::process::Command::new(runtime)
                .args(["kill", id, "KILL"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .status();
            let _ = tokio::time::timeout(TIMEOUT_GRACE, kill).await;
            let _ = nix::sys::signal::kill(group, nix::sys::signal::Signal::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (runtime, id);
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

/// Supervise one running container: stream stdio, enforce the
/// timeout, propagate the exit code. Pumps always join before
/// returning so no output or task is orphaned.
async fn supervise_container(
    child: &mut tokio::process::Child,
    runtime: &Path,
    id: &str,
    timeout: std::time::Duration,
) -> Result<i32, String> {
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err("container stdio pipes unavailable".to_string());
    };
    let ring: OutputRing = std::sync::Arc::new(std::sync::Mutex::new(Default::default()));
    let out_pump = tokio::spawn(pump_pipe(out, tokio::io::stdout(), ring.clone()));
    let err_pump = tokio::spawn(pump_pipe(err, tokio::io::stderr(), ring.clone()));
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            let _ = tokio::join!(out_pump, err_pump);
            return Err(format!("container wait failed: {e}"));
        }
        Err(_) => {
            escalate_timeout(child, runtime, id).await;
            let _ = tokio::join!(out_pump, err_pump);
            return Err(format!("container timed out after {}s", timeout.as_secs()));
        }
    };
    let _ = tokio::join!(out_pump, err_pump);
    let code = status.code().unwrap_or(1);
    if code != 0 {
        if let Ok(ring) = ring.lock() {
            if !ring.is_empty() {
                let tail: Vec<u8> = ring.iter().copied().collect();
                eprintln!(
                    "runner: container exited {code}; last output:\n{}",
                    String::from_utf8_lossy(&tail)
                );
            }
        }
    }
    Ok(code)
}

/// Execute one command in an ephemeral OCI container: probe, bundle,
/// spawn, supervise, tear down. The probe runs first so a missing
/// runtime fails closed before touching disk or spawn — in every
/// mode (there is no tier fallback to gate, so `--strict` needs no
/// separate branch).
pub async fn execute_container(
    runtime_override: Option<&Path>,
    command: &[String],
    timeout: std::time::Duration,
) -> Result<i32, String> {
    execute_container_in(
        &crate::mounts::job_root(),
        runtime_override,
        command,
        timeout,
    )
    .await
}

/// [`execute_container`] with an explicit bundle parent (tests pin a
/// temp dir; production always passes [`job_root`](crate::mounts::job_root)).
async fn execute_container_in(
    bundle_parent: &Path,
    runtime_override: Option<&Path>,
    command: &[String],
    timeout: std::time::Duration,
) -> Result<i32, String> {
    if command.is_empty() {
        return Err("no command to execute".to_string());
    }
    let runtime = probe_oci_runtime(runtime_override)?;
    let id = next_container_id();
    let spec = OciBundleSpec::new(command.to_vec(), host_env());
    let dir = assemble_bundle_at(bundle_parent, &id, &spec)?;
    let mut guard = OciBundleGuard::new(runtime.clone(), id.clone(), dir.clone());
    let argv = match runtime_argv(&runtime, &dir, &id) {
        Ok(argv) => argv,
        Err(e) => {
            guard.teardown().await;
            return Err(e);
        }
    };
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // Fresh process group per spawn: timeout escalation signals the
    // whole tree (unix; no-op elsewhere).
    #[cfg(unix)]
    cmd.process_group(0);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            guard.teardown().await;
            return Err(format!("failed to spawn OCI runtime: {e}"));
        }
    };
    let outcome = supervise_container(&mut child, &runtime, &id, timeout).await;
    guard.teardown().await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake runnable binary (executable bit where the platform has one).
    fn fake_runtime(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn path_var(dirs: &[PathBuf]) -> String {
        std::env::join_paths(dirs).unwrap().into_string().unwrap()
    }

    #[test]
    fn find_on_path_resolves_runnable_files() {
        let dir = runner_core::test_support::TempDir::new("oci-path").unwrap();
        let runc = fake_runtime(dir.path(), "runc");
        let path_var = path_var(&[dir.path().to_path_buf()]);
        assert_eq!(find_on_path_with("runc", &path_var), Some(runc));
        assert_eq!(find_on_path_with("crun", &path_var), None);
        assert_eq!(find_on_path_with("runc", ""), None);
    }

    #[test]
    fn probe_prefers_candidate_order_over_path_order() {
        let dir = runner_core::test_support::TempDir::new("oci-order").unwrap();
        let early = dir.path().join("early");
        let late = dir.path().join("late");
        std::fs::create_dir_all(&early).unwrap();
        std::fs::create_dir_all(&late).unwrap();
        // docker sits earlier on PATH, but runc outranks it.
        fake_runtime(&early, "docker");
        let runc = fake_runtime(&late, "runc");
        let path_var = path_var(&[early, late]);
        let found =
            probe_oci_runtime_with(None, &|name| find_on_path_with(name, &path_var)).unwrap();
        assert_eq!(found, runc);
    }

    #[test]
    fn probe_honors_explicit_override_or_fails_closed() {
        let dir = runner_core::test_support::TempDir::new("oci-explicit").unwrap();
        let custom = fake_runtime(dir.path(), "my-runtime");
        assert_eq!(
            probe_oci_runtime_with(Some(&custom), &|_| None).unwrap(),
            custom
        );
        let missing = dir.path().join("nope");
        let err = probe_oci_runtime_with(Some(&missing), &|_| None).unwrap_err();
        assert!(err.contains("nope"), "{err}");
        // Non-runnable override (plain data file) fails closed too.
        let data = dir.path().join("data.txt");
        std::fs::write(&data, b"not a binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(unix)]
        assert!(probe_oci_runtime_with(Some(&data), &|_| None).is_err());
    }

    #[test]
    fn probe_missing_runtime_names_every_candidate() {
        let err = probe_oci_runtime_with(None, &|_| None).unwrap_err();
        for candidate in OCI_RUNTIME_CANDIDATES {
            assert!(err.contains(candidate), "{err}");
        }
        assert!(err.contains("runtime_path"), "{err}");
    }

    fn spec() -> OciBundleSpec {
        OciBundleSpec::new(
            vec!["/bin/sh".to_string(), "-c".to_string(), "make".to_string()],
            vec!["CI=true".to_string(), "PATH=/usr/bin".to_string()],
        )
        .with_limits(500, 512 * 1024 * 1024)
        .unwrap()
    }

    #[test]
    fn bundle_json_roundtrips_losslessly() {
        let spec = spec();
        let json = spec.to_json().unwrap();
        let back: OciBundleSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn bundle_carries_spec_invariants() {
        let json = spec().to_json().unwrap();
        assert_eq!(json["ociVersion"], "1.0.2");
        assert_eq!(json["process"]["args"][2], "make");
        assert_eq!(json["process"]["env"][0], "CI=true");
        assert_eq!(json["process"]["cwd"], "/workspace");
        assert_eq!(json["root"]["readonly"], true);
        let namespaces: Vec<&str> = json["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ns| ns["type"].as_str().unwrap())
            .collect();
        assert_eq!(
            namespaces,
            vec!["pid", "network", "mount", "ipc", "uts", "user"]
        );
        // Workspace tmpfs mount present.
        let workspace = json["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/workspace")
            .unwrap();
        assert_eq!(workspace["type"], "tmpfs");
        // cgroup v2 limits.
        assert_eq!(json["linux"]["resources"]["cpu"]["weight"], 500);
        assert_eq!(
            json["linux"]["resources"]["memory"]["limit"],
            512 * 1024 * 1024
        );
        // Rootless 1:1 identity mapping anchored at container 0.
        assert_eq!(json["linux"]["uidMappings"][0]["containerID"], 0);
        assert_eq!(json["linux"]["uidMappings"][0]["size"], 1);
    }

    #[test]
    fn bundle_limits_reject_garbage() {
        let base = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        assert!(base.clone().with_limits(0, 1024).is_err());
        assert!(base.clone().with_limits(10001, 1024).is_err());
        assert!(base.clone().with_limits(100, 0).is_err());
        assert!(base.with_limits(100, 1024).is_ok());
    }

    #[test]
    fn runtime_argv_dispatches_standalone_and_defers_engines() {
        let bundle = PathBuf::from("/tmp/b");
        // Standalone runtimes share the run --bundle shape.
        for name in ["crun", "runc", "youki"] {
            let argv = runtime_argv(Path::new(name), &bundle, "oci-1").unwrap();
            assert_eq!(argv[1..4], ["run", "--bundle", "/tmp/b"]);
            assert_eq!(argv[4], "oci-1");
        }
        // Unknown overrides are assumed runc-compatible.
        let argv = runtime_argv(Path::new("/opt/my-runtime"), &bundle, "oci-1").unwrap();
        assert_eq!(argv[0], "/opt/my-runtime");
        // Engines manage their own storage: clean deferral.
        for name in ["podman", "docker"] {
            let err = runtime_argv(Path::new(name), &bundle, "oci-1").unwrap_err();
            assert!(err.contains("engine"), "{err}");
        }
    }

    /// Fake runtime shim script (unix: real shell execution).
    #[cfg(unix)]
    fn shim_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn bundle_parent(dir: &Path) -> PathBuf {
        let parent = dir.join("bundles");
        std::fs::create_dir_all(&parent).unwrap();
        parent
    }

    fn assert_parent_empty(parent: &Path) {
        let leftovers: Vec<_> = std::fs::read_dir(parent).unwrap().collect();
        assert!(leftovers.is_empty(), "orphaned bundles: {leftovers:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_propagates_shim_exit_codes() {
        let dir = runner_core::test_support::TempDir::new("oci-exit").unwrap();
        let parent = bundle_parent(dir.path());
        for (code, body) in [(0, "exit 0"), (42, "exit 42"), (1, "exit 1")] {
            let shim = shim_script(dir.path(), &format!("rt-{code}"), body);
            let got = execute_container_in(
                &parent,
                Some(&shim),
                &["true".to_string()],
                std::time::Duration::from_secs(10),
            )
            .await
            .unwrap();
            assert_eq!(got, code);
        }
        assert_parent_empty(&parent);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_timeout_escalates_and_cleans() {
        let dir = runner_core::test_support::TempDir::new("oci-timeout").unwrap();
        let parent = bundle_parent(dir.path());
        // Ignores SIGTERM: forces the full ladder (TERM → grace →
        // runtime kill → direct SIGKILL). Management subcommands
        // succeed instantly like a real runtime.
        let shim = shim_script(
            dir.path(),
            "slow-rt",
            "if [ \"$1\" = kill ] || [ \"$1\" = delete ]; then exit 0; fi\ntrap '' TERM; sleep 30",
        );
        let start = std::time::Instant::now();
        let err = execute_container_in(
            &parent,
            Some(&shim),
            &["true".to_string()],
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.contains("timed out"), "{err}");
        // Waited the full timeout (never instant-failed), escalated
        // well before the shim's 30s sleep could elapse (~5s typical).
        assert!(
            elapsed >= std::time::Duration::from_millis(900),
            "{elapsed:?}"
        );
        assert!(elapsed < std::time::Duration::from_secs(15), "{elapsed:?}");
        assert_parent_empty(&parent);
    }

    #[tokio::test]
    async fn execute_missing_runtime_spawns_nothing() {
        let dir = runner_core::test_support::TempDir::new("oci-nospawn").unwrap();
        let marker = dir.path().join("RAN");
        // If any child spawned, this command would create the marker.
        let err = execute_container(
            Some(&dir.path().join("no-such-runtime")),
            &["touch".to_string(), marker.display().to_string()],
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.contains("not a runnable binary"), "{err}");
        assert!(!marker.exists(), "a child process ran on the host");
    }

    #[tokio::test]
    async fn execute_engine_runtime_defers_and_cleans() {
        let dir = runner_core::test_support::TempDir::new("oci-engine").unwrap();
        let parent = bundle_parent(dir.path());
        let docker = fake_runtime(dir.path(), "docker");
        let err = execute_container_in(
            &parent,
            Some(&docker),
            &["true".to_string()],
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.contains("engine"), "{err}");
        assert_parent_empty(&parent);
    }

    #[tokio::test]
    async fn execute_spawn_failure_cleans_bundle() {
        let dir = runner_core::test_support::TempDir::new("oci-spawnfail").unwrap();
        let parent = bundle_parent(dir.path());
        // Runnable bit, unexecutable bytes: passes the probe, fails spawn.
        let garbage = dir.path().join("garbage-rt");
        std::fs::write(&garbage, b"\xff\xfe not a program \x00\x01").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&garbage, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let err = execute_container_in(
            &parent,
            Some(&garbage),
            &["true".to_string()],
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.contains("failed to spawn"), "{err}");
        assert_parent_empty(&parent);
    }

    #[tokio::test]
    async fn guard_teardown_is_idempotent_and_drop_backstops() {
        // Explicit teardown twice: second is a no-op.
        let dir = runner_core::test_support::TempDir::new("oci-guard").unwrap();
        let bundle = dir.path().join("oci-x");
        std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
        let mut guard = OciBundleGuard::new(
            PathBuf::from("/nonexistent/rt"),
            "oci-x".to_string(),
            bundle.clone(),
        );
        guard.teardown().await;
        assert!(!bundle.exists());
        guard.teardown().await;
        // Drop without teardown still scrubs (panic backstop).
        let bundle = dir.path().join("oci-y");
        std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
        drop(OciBundleGuard::new(
            PathBuf::from("/nonexistent/rt"),
            "oci-y".to_string(),
            bundle.clone(),
        ));
        assert!(!bundle.exists());
    }

    #[tokio::test]
    async fn pump_pipe_roundtrips_and_caps_ring() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Small payload: exact roundtrip + exact ring.
        let (mut in_client, in_server) = tokio::io::duplex(4096);
        let (out_server, mut out_client) = tokio::io::duplex(4096);
        let ring: OutputRing = std::sync::Arc::new(std::sync::Mutex::new(Default::default()));
        let pump = tokio::spawn(pump_pipe(in_server, out_server, ring.clone()));
        in_client.write_all(b"hello").await.unwrap();
        drop(in_client);
        pump.await.unwrap();
        let mut got = Vec::new();
        out_client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
        let ring_bytes: Vec<u8> = ring.lock().unwrap().iter().copied().collect();
        assert_eq!(ring_bytes, b"hello");
        // 40KB through a 32KB ring: capped tail only.
        let (mut in_client, in_server) = tokio::io::duplex(65536);
        let (out_server, mut out_client) = tokio::io::duplex(65536);
        let ring: OutputRing = std::sync::Arc::new(std::sync::Mutex::new(Default::default()));
        let pump = tokio::spawn(pump_pipe(in_server, out_server, ring.clone()));
        let big = vec![7u8; 40 * 1024];
        in_client.write_all(&big).await.unwrap();
        drop(in_client);
        pump.await.unwrap();
        let mut got = Vec::new();
        out_client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, big);
        assert_eq!(ring.lock().unwrap().len(), 32 * 1024);
    }

    #[test]
    fn bundle_mounts_reject_home_and_relative() {
        let base = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        // Host paths under /home fail closed.
        assert!(base
            .clone()
            .with_mount(Path::new("/home/dev/data"), "/data", true)
            .is_err());
        assert!(base
            .clone()
            .with_mount(Path::new("/home/dev/.ssh"), "/secrets", true)
            .is_err());
        // Container-relative destinations fail closed.
        assert!(base
            .clone()
            .with_mount(Path::new("/opt/data"), "data", true)
            .is_err());
        // Sane bind mounts pass through with options.
        let spec = base
            .with_mount(Path::new("/opt/data"), "/data", true)
            .unwrap();
        let mount = spec
            .mounts
            .iter()
            .find(|m| m.destination == "/data")
            .unwrap();
        assert_eq!(mount.mount_type.as_deref(), Some("bind"));
        assert!(mount.options.contains(&"ro".to_string()));
    }
}
