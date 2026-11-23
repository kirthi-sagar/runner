//! OCI container tier: host runtime probing and v1.0.2 bundle
//! generation. Phase 1 ships discovery + spec emission; execution
//! binds a probed runtime in a later phase.

use std::collections::HashMap;
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
    /// Free-form annotations (records the requested image; the
    /// rootfs itself stays minimal until the engine flows land).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
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

/// Caller-specified container volume (host bind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciVolume {
    pub source: PathBuf,
    pub destination: String,
    pub readonly: bool,
}

impl OciBundleSpec {
    /// Minimal runnable bundle: entrypoint argv + env, cwd `/workspace`,
    /// rootless userns mapped 1:1 to the invoker, default mounts,
    /// read-only rootfs, no resource limits (see [`with_limits`](Self::with_limits)).
    /// Networking defaults to the host namespace (docker parity for
    /// CI workloads; the [`EgressGuard`](crate::egress::EgressGuard)
    /// filters host egress) — see
    /// [`with_offline_network`](Self::with_offline_network) for
    /// loopback-only isolation.
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
            annotations: HashMap::new(),
            linux: OciLinux {
                namespaces: ["pid", "mount", "ipc", "uts", "user"]
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

    /// Loopback-only isolation: `true` confines the container to
    /// a fresh network namespace holding only the `lo` interface (no
    /// veth is ever provisioned, so nothing leaves the box);
    /// `false` shares the host namespace (the default). Idempotent
    /// in both directions; the canonical namespace order is kept.
    /// Note: a fresh netns starts with `lo` down — workloads needing
    /// loopback must bring it up (a prestart hook lands with the
    /// runtime integration that needs it).
    pub fn with_offline_network(mut self, offline: bool) -> Self {
        self.linux.namespaces.retain(|ns| ns.ns_type != "network");
        if offline {
            // Canonical position: pid, network, mount, ...
            let at = self
                .linux
                .namespaces
                .iter()
                .position(|ns| ns.ns_type == "pid")
                .map(|i| i + 1)
                .unwrap_or(0);
            self.linux.namespaces.insert(
                at,
                OciNamespace {
                    ns_type: "network".to_string(),
                },
            );
        }
        self
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

    /// Attach caller-specified volumes (each validated like
    /// [`with_mount`](Self::with_mount): `/home` host sources fail
    /// closed before anything is written or spawned).
    pub fn with_volumes(mut self, volumes: &[OciVolume]) -> Result<Self, String> {
        for volume in volumes {
            self = self.with_mount(&volume.source, &volume.destination, volume.readonly)?;
        }
        Ok(self)
    }
}

/// Parse one `-v/--volume` spec (`host:container[:ro|rw]`) into
/// a bind volume. Syntax-only: `/home` policy enforces later at
/// [`OciBundleSpec::with_mount`]. Windows drive letters (`C:\…`)
/// are honored; anything else with a stray `:` fails closed (same
/// quirk as docker `-v`).
pub fn parse_volume_spec(spec: &str) -> Result<OciVolume, String> {
    let invalid = || format!("invalid volume spec '{spec}' (want host:container[:ro|rw])");
    // Peel a Windows drive prefix so its colon never splits.
    let bytes = spec.as_bytes();
    let (drive, rest) = if bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        spec.split_at(2)
    } else {
        ("", spec)
    };
    let mut parts = rest.split(':');
    let host = parts.next().ok_or_else(&invalid)?;
    let container = parts.next().ok_or_else(&invalid)?;
    let opts = parts.next().unwrap_or("rw");
    if parts.next().is_some() {
        return Err(invalid());
    }
    if host.is_empty() || container.is_empty() {
        return Err(invalid());
    }
    if !container.starts_with('/') {
        return Err(format!(
            "invalid volume spec '{spec}': container path must be absolute"
        ));
    }
    let readonly = match opts {
        "ro" => true,
        "rw" => false,
        _ => {
            return Err(format!(
                "invalid volume spec '{spec}': options must be ro|rw, got '{opts}'"
            ));
        }
    };
    Ok(OciVolume {
        source: PathBuf::from(format!("{drive}{host}")),
        destination: container.to_string(),
        readonly,
    })
}

/// Resolve the container image: explicit flag first, config default
/// second, fail closed when both are missing or blank.
pub fn resolve_container_image(
    flag: Option<&str>,
    config: &runner_core::config::SandboxContainerConfig,
) -> Result<String, String> {
    flag.map(str::trim)
        .filter(|flag| !flag.is_empty())
        .map(str::to_string)
        .or_else(|| config.default_image.clone())
        .filter(|image| !image.trim().is_empty())
        .ok_or_else(|| {
            "container execution requires an image (--image or [sandbox.container] default_image)"
                .to_string()
        })
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

    /// Force-delete the container (bounded), then cryptographically
    /// scrub the workspace and remove the bundle (same guarantee as
    /// process-tier workspaces). Idempotent: safe on every exit path.
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
        crate::mounts::scrub_workspace(&dir);
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
            crate::mounts::scrub_workspace(&dir);
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

/// Launch parameters for one container execution, assembled by
/// the CLI (`--image`, `--volume`, `--no-network`) or the MCP agent
/// from tool args plus config fallbacks.
#[derive(Debug, Clone)]
pub struct ContainerLaunch {
    pub runtime_override: Option<PathBuf>,
    pub command: Vec<String>,
    pub timeout: std::time::Duration,
    pub volumes: Vec<OciVolume>,
    pub network_egress_filtering: bool,
    /// Resolved image reference (flag over config default); empty
    /// fails closed at launch.
    pub image: String,
    pub no_network: bool,
    /// Container environment (`None` inherits the host).
    pub env: Option<Vec<String>>,
}

impl Default for ContainerLaunch {
    fn default() -> Self {
        Self {
            runtime_override: None,
            command: Vec::new(),
            timeout: std::time::Duration::from_secs(60),
            volumes: Vec::new(),
            network_egress_filtering: false,
            image: String::new(),
            no_network: false,
            env: None,
        }
    }
}

/// Captured container result (MCP path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Per-stream capture cap (agents get bounded payloads).
const CAPTURE_CAP_BYTES: usize = 1024 * 1024;

/// Collect a pipe to bytes, capped: past the cap the reader keeps
/// draining (a capped stream must never backpressure the pump into
/// a false timeout).
async fn collect_capped<R>(mut reader: R, cap: usize) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < cap {
                    out.extend_from_slice(&buf[..n.min(cap - out.len())]);
                }
            }
            Err(_) => break,
        }
    }
    out
}

/// Wait with timeout escalation; returns the exit status (never hangs
/// past timeout+grace+kill). Shared by both supervision modes.
async fn wait_supervised(
    child: &mut tokio::process::Child,
    runtime: &Path,
    id: &str,
    timeout: std::time::Duration,
) -> Result<std::process::ExitStatus, String> {
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => Err(format!("container wait failed: {e}")),
        Err(_) => {
            escalate_timeout(child, runtime, id).await;
            Err(format!("container timed out after {}s", timeout.as_secs()))
        }
    }
}

/// Supervise one running container: stream stdio live, enforce the
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
    let status = match wait_supervised(child, runtime, id, timeout).await {
        Ok(status) => status,
        Err(e) => {
            let _ = tokio::join!(out_pump, err_pump);
            return Err(e);
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

/// Supervise one running container with captured (not inherited)
/// stdio for the MCP path. Collectors drain concurrently with the
/// pumps so a chatty container can never deadlock the capture.
async fn supervise_container_captured(
    child: &mut tokio::process::Child,
    runtime: &Path,
    id: &str,
    timeout: std::time::Duration,
) -> Result<ContainerOutput, String> {
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err("container stdio pipes unavailable".to_string());
    };
    // Ring unused here (full output returns); the pumps require one.
    let ring: OutputRing = std::sync::Arc::new(std::sync::Mutex::new(Default::default()));
    let (out_sink, out_source) = tokio::io::duplex(65536);
    let (err_sink, err_source) = tokio::io::duplex(65536);
    let out_pump = tokio::spawn(pump_pipe(out, out_sink, ring.clone()));
    let err_pump = tokio::spawn(pump_pipe(err, err_sink, ring.clone()));
    let out_collect = tokio::spawn(collect_capped(out_source, CAPTURE_CAP_BYTES));
    let err_collect = tokio::spawn(collect_capped(err_source, CAPTURE_CAP_BYTES));
    let status = match wait_supervised(child, runtime, id, timeout).await {
        Ok(status) => status,
        Err(e) => {
            let _ = tokio::join!(out_pump, err_pump, out_collect, err_collect);
            return Err(e);
        }
    };
    let _ = tokio::join!(out_pump, err_pump);
    let (stdout, stderr) = tokio::join!(out_collect, err_collect);
    Ok(ContainerOutput {
        code: status.code().unwrap_or(1),
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
    })
}

/// Spawned container plus its teardown guard and identity.
struct LaunchedContainer {
    child: tokio::process::Child,
    guard: OciBundleGuard,
    runtime: PathBuf,
    id: String,
}

/// Validate, probe, assemble, and spawn one container (shared by the
/// streaming and captured paths). Pure validations run before any
/// side effect; each fallible setup step tears down on failure.
async fn launch_container(
    bundle_parent: &Path,
    launch: &ContainerLaunch,
) -> Result<LaunchedContainer, String> {
    if launch.command.is_empty() {
        return Err("no command to execute".to_string());
    }
    if launch.image.trim().is_empty() {
        return Err(
            "container execution requires an image (--image or [sandbox.container] default_image)"
                .to_string(),
        );
    }
    let runtime = probe_oci_runtime(launch.runtime_override.as_deref())?;
    let id = next_container_id();
    let env = launch.env.clone().unwrap_or_else(host_env);
    // Volumes validate before anything is written: a /home source
    // fails closed with no bundle and no spawn.
    let mut spec = OciBundleSpec::new(launch.command.clone(), env)
        .with_volumes(&launch.volumes)?
        .with_offline_network(launch.no_network);
    spec.annotations
        .insert("org.runner.image".to_string(), launch.image.clone());
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
    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            guard.teardown().await;
            return Err(format!("failed to spawn OCI runtime: {e}"));
        }
    };
    Ok(LaunchedContainer {
        child,
        guard,
        runtime,
        id,
    })
}

/// Execute one command in an ephemeral OCI container: guard, launch,
/// supervise (live stdio), tear down. The egress guard runs before
/// any setup so failures abort before touching disk or spawn — in
/// every mode (there is no tier fallback to gate, so `--strict`
/// needs no separate branch).
pub async fn execute_container(launch: ContainerLaunch) -> Result<i32, String> {
    execute_container_in(&crate::mounts::job_root(), launch).await
}

/// [`execute_container`] with an explicit bundle parent (tests pin a
/// temp dir; production always passes [`job_root`](crate::mounts::job_root)).
async fn execute_container_in(
    bundle_parent: &Path,
    launch: ContainerLaunch,
) -> Result<i32, String> {
    // Egress boundary first (mirrors the process tier): held across
    // the whole lifecycle; acquisition failure aborts unfiltered-never.
    let _egress_guard = crate::egress::EgressGuard::acquire(launch.network_egress_filtering)?;
    let mut launched = launch_container(bundle_parent, &launch).await?;
    let outcome = supervise_container(
        &mut launched.child,
        &launched.runtime,
        &launched.id,
        launch.timeout,
    )
    .await;
    launched.guard.teardown().await;
    outcome
}

/// [`execute_container`] with captured (not inherited) stdio for the
/// MCP agent path.
pub async fn execute_container_captured(
    launch: ContainerLaunch,
) -> Result<ContainerOutput, String> {
    execute_container_captured_in(&crate::mounts::job_root(), launch).await
}

/// Captured [`execute_container_in`] (tests pin a temp dir).
async fn execute_container_captured_in(
    bundle_parent: &Path,
    launch: ContainerLaunch,
) -> Result<ContainerOutput, String> {
    let _egress_guard = crate::egress::EgressGuard::acquire(launch.network_egress_filtering)?;
    let mut launched = launch_container(bundle_parent, &launch).await?;
    let outcome = supervise_container_captured(
        &mut launched.child,
        &launched.runtime,
        &launched.id,
        launch.timeout,
    )
    .await;
    launched.guard.teardown().await;
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
        // Host-networked by default (docker parity); offline mode
        // adds the isolated namespace (see below).
        assert_eq!(namespaces, vec!["pid", "mount", "ipc", "uts", "user"]);
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

    fn namespace_types(spec: &OciBundleSpec) -> Vec<String> {
        spec.linux
            .namespaces
            .iter()
            .map(|ns| ns.ns_type.clone())
            .collect()
    }

    #[test]
    fn offline_mode_emits_loopback_only_namespace() {
        let base = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        // Default shares the host network namespace...
        assert!(!namespace_types(&base).contains(&"network".to_string()));
        // ...offline confines to a fresh netns (lo-only: no veth is
        // ever provisioned), in canonical position, idempotently...
        let offline = base.clone().with_offline_network(true);
        assert_eq!(
            namespace_types(&offline),
            vec!["pid", "network", "mount", "ipc", "uts", "user"]
        );
        let json = offline.to_json().unwrap();
        let types: Vec<&str> = json["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ns| ns["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"network"));
        // ...and back off restores the default.
        let online = offline.with_offline_network(false);
        assert_eq!(
            namespace_types(&online),
            vec!["pid", "mount", "ipc", "uts", "user"]
        );
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

    /// Launch builder for tests (image pre-resolved; tweak per test).
    fn test_launch(
        runtime: Option<PathBuf>,
        command: Vec<String>,
        timeout: std::time::Duration,
    ) -> ContainerLaunch {
        ContainerLaunch {
            runtime_override: runtime,
            command,
            timeout,
            image: "test:latest".to_string(),
            ..Default::default()
        }
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
                test_launch(
                    Some(shim),
                    vec!["true".to_string()],
                    std::time::Duration::from_secs(10),
                ),
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
            test_launch(
                Some(shim),
                vec!["true".to_string()],
                std::time::Duration::from_secs(1),
            ),
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
        let err = execute_container(test_launch(
            Some(dir.path().join("no-such-runtime")),
            vec!["touch".to_string(), marker.display().to_string()],
            std::time::Duration::from_secs(5),
        ))
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
            test_launch(
                Some(docker),
                vec!["true".to_string()],
                std::time::Duration::from_secs(5),
            ),
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
            test_launch(
                Some(garbage),
                vec!["true".to_string()],
                std::time::Duration::from_secs(5),
            ),
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

    #[tokio::test]
    async fn execute_rejects_home_volume_before_setup() {
        let dir = runner_core::test_support::TempDir::new("oci-homevol").unwrap();
        let parent = bundle_parent(dir.path());
        // A /home host source fails closed: no bundle, no spawn. The
        // override passes the probe but is never spawned (portable:
        // no shell needed).
        let volumes = vec![OciVolume {
            source: PathBuf::from("/home/dev/data"),
            destination: "/data".to_string(),
            readonly: true,
        }];
        let runtime = fake_runtime(dir.path(), "vol-rt");
        let launch = ContainerLaunch {
            volumes,
            ..test_launch(
                Some(runtime),
                vec!["true".to_string()],
                std::time::Duration::from_secs(5),
            )
        };
        let err = execute_container_in(&parent, launch).await.unwrap_err();
        assert!(err.contains("/home"), "{err}");
        assert_parent_empty(&parent);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_with_egress_boundary_completes_lifecycle() {
        // Filtering enabled: the guard acquires (canary on CI),
        // rides the lifecycle, and releases — the run succeeds and
        // everything tears down.
        let dir = runner_core::test_support::TempDir::new("oci-egress").unwrap();
        let parent = bundle_parent(dir.path());
        let shim = shim_script(dir.path(), "guard-rt", "exit 0");
        let launch = ContainerLaunch {
            network_egress_filtering: true,
            ..test_launch(
                Some(shim),
                vec!["true".to_string()],
                std::time::Duration::from_secs(10),
            )
        };
        let code = execute_container_in(&parent, launch).await.unwrap();
        assert_eq!(code, 0);
        assert_parent_empty(&parent);
    }

    #[test]
    fn volume_specs_parse_and_reject() {
        // Happy paths.
        let volume = parse_volume_spec("/opt/data:/data").unwrap();
        assert_eq!(volume.source, PathBuf::from("/opt/data"));
        assert_eq!(volume.destination, "/data");
        assert!(!volume.readonly);
        let volume = parse_volume_spec("/opt/data:/data:ro").unwrap();
        assert!(volume.readonly);
        let volume = parse_volume_spec("/opt/data:/data:rw").unwrap();
        assert!(!volume.readonly);
        // Windows drive hosts (pure string logic: runs everywhere).
        let volume = parse_volume_spec("C:\\data:/data:ro").unwrap();
        assert_eq!(volume.source, PathBuf::from("C:\\data"));
        assert_eq!(volume.destination, "/data");
        assert!(volume.readonly);
        // Malformed specs fail closed.
        for bad in [
            "",
            "justahost",
            "/data",
            ":/data",
            "/host:",
            "/host:relative",
            "/host:/data:z",
            "/a:/b:ro:extra",
        ] {
            assert!(parse_volume_spec(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn image_resolves_flag_over_config_or_fails_closed() {
        use runner_core::config::SandboxContainerConfig;
        let blank = SandboxContainerConfig::default();
        // Neither: fail closed naming both sources.
        let err = resolve_container_image(None, &blank).unwrap_err();
        assert!(err.contains("--image"), "{err}");
        assert!(err.contains("default_image"), "{err}");
        // Blank flag falls through to the default.
        let configured = SandboxContainerConfig {
            default_image: Some("ubuntu:24.04".to_string()),
            ..SandboxContainerConfig::default()
        };
        assert_eq!(
            resolve_container_image(None, &configured).unwrap(),
            "ubuntu:24.04"
        );
        assert_eq!(
            resolve_container_image(Some("  "), &configured).unwrap(),
            "ubuntu:24.04"
        );
        // Explicit flag wins.
        assert_eq!(
            resolve_container_image(Some("alpine:3"), &configured).unwrap(),
            "alpine:3"
        );
    }

    #[tokio::test]
    async fn execute_missing_image_fails_before_setup() {
        let dir = runner_core::test_support::TempDir::new("oci-noimage").unwrap();
        let parent = bundle_parent(dir.path());
        let runtime = fake_runtime(dir.path(), "img-rt");
        let launch = ContainerLaunch {
            image: String::new(),
            ..test_launch(
                Some(runtime),
                vec!["true".to_string()],
                std::time::Duration::from_secs(5),
            )
        };
        let err = execute_container_in(&parent, launch).await.unwrap_err();
        assert!(err.contains("--image"), "{err}");
        assert_parent_empty(&parent);
    }

    #[test]
    fn annotations_roundtrip_with_spec() {
        let mut spec = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        spec.annotations
            .insert("org.runner.image".to_string(), "ubuntu:24.04".to_string());
        let json = spec.to_json().unwrap();
        assert_eq!(json["annotations"]["org.runner.image"], "ubuntu:24.04");
        let back: OciBundleSpec = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.annotations.get("org.runner.image").unwrap(),
            "ubuntu:24.04"
        );
        // Absent annotations default empty (old bundles parse).
        let mut spec = OciBundleSpec::new(vec!["x".to_string()], vec![]);
        spec.annotations.clear();
        let json = spec.to_json().unwrap();
        assert!(json.get("annotations").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_captured_returns_separate_streams() {
        let dir = runner_core::test_support::TempDir::new("oci-capture").unwrap();
        let parent = bundle_parent(dir.path());
        let shim = shim_script(dir.path(), "echo-rt", "echo OUT; echo ERR >&2; exit 3");
        let launch = test_launch(
            Some(shim),
            vec!["true".to_string()],
            std::time::Duration::from_secs(10),
        );
        let out = execute_container_captured_in(&parent, launch)
            .await
            .unwrap();
        assert_eq!(out.code, 3);
        assert_eq!(out.stdout, b"OUT\n");
        assert_eq!(out.stderr, b"ERR\n");
        assert_parent_empty(&parent);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_captured_timeout_reports_without_streams() {
        let dir = runner_core::test_support::TempDir::new("oci-captimeout").unwrap();
        let parent = bundle_parent(dir.path());
        let shim = shim_script(dir.path(), "slow-rt", "sleep 30");
        let launch = test_launch(
            Some(shim),
            vec!["true".to_string()],
            std::time::Duration::from_secs(1),
        );
        let err = execute_container_captured_in(&parent, launch)
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert_parent_empty(&parent);
    }

    #[test]
    fn egress_guard_disabled_bypasses() {
        use crate::egress::EgressGuard;
        assert!(EgressGuard::acquire(false).unwrap().is_none());
    }

    // Live acquisition needs no privileges off Windows (canary
    // validation); on Windows it opens a real WFP session.
    #[cfg(not(windows))]
    #[test]
    fn egress_guard_acquire_smoke() {
        use crate::egress::EgressGuard;
        let guard = EgressGuard::acquire(true).unwrap();
        assert!(guard.is_some());
        drop(guard);
    }
}
