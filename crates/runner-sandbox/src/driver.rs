//! Dual-tier sandbox engine: instant switching between lightweight
//! process isolation (community) and hardware-isolated microVMs
//! (enterprise) behind one [`SandboxEngine`] interface.
//!
//! * [`SandboxDriver::Process`] — unprivileged user + mount namespaces with
//!   an ephemeral tmpfs workspace (falls back to a plain governed spawn
//!   where user namespaces are unavailable).
//! * [`SandboxDriver::MicroVm`] — Firecracker microVM with vsock guest
//!   dispatch: the engine boots the guest, runs the command via the
//!   in-guest agent, streams its stdio, and tears the VM down. It fails
//!   closed (clean errors, never silent host execution) without KVM,
//!   the Firecracker binary, or kernel/rootfs images.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::process::Command as TokioCommand;

use crate::microvm::{probe_kvm, MicroVmConfig, MicroVmSupervisor};
use crate::mounts::{probe_userns, sanitize_job_id, Workspace};
use runner_core::governor::darwin::QosBackend;

/// Isolation tier selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxDriver {
    /// Community tier: process namespaces + tmpfs workspace.
    #[default]
    Process,
    /// Enterprise tier: Firecracker microVM.
    MicroVm,
}

impl SandboxDriver {
    /// Parse a driver name (`process` / `microvm`, case-insensitive).
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "process" => Ok(Self::Process),
            "microvm" | "micro-vm" | "firecracker" => Ok(Self::MicroVm),
            other => Err(format!(
                "unknown sandbox driver: '{other}' (want process|microvm)"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::MicroVm => "microvm",
        }
    }
}

/// Unified entrypoint for tier-selected isolated execution.
#[derive(Debug)]
pub struct SandboxEngine {
    driver: SandboxDriver,
    microvm: Option<MicroVmConfig>,
    firecracker_bin: PathBuf,
}

impl SandboxEngine {
    pub fn new(driver: SandboxDriver) -> Self {
        Self {
            driver,
            microvm: None,
            firecracker_bin: PathBuf::from("firecracker"),
        }
    }

    /// Attach the microVM configuration used by the [`SandboxDriver::MicroVm`] tier.
    pub fn with_microvm(mut self, config: MicroVmConfig, firecracker_bin: PathBuf) -> Self {
        self.microvm = Some(config);
        self.firecracker_bin = firecracker_bin;
        self
    }

    pub fn driver(&self) -> SandboxDriver {
        self.driver
    }

    /// Execute a command under the selected tier, returning its exit code.
    ///
    /// Process tier: tmpfs user-namespace sandbox (or governed direct
    /// spawn where namespaces are unavailable), stdio inherited, timeout
    /// kills the child. MicroVM tier: boots the guest, dispatches the
    /// command over vsock to the in-guest agent, streams its stdio, and
    /// tears the VM down.
    pub async fn execute(&self, command: &[String], timeout: Duration) -> Result<i32, String> {
        match self.driver {
            SandboxDriver::Process => {
                execute_process(
                    command,
                    timeout,
                    Arc::new(runner_core::governor::darwin::DarwinQos),
                )
                .await
            }
            SandboxDriver::MicroVm => self.execute_microvm(command, timeout).await,
        }
    }

    async fn execute_microvm(&self, command: &[String], timeout: Duration) -> Result<i32, String> {
        if command.is_empty() {
            return Err("no command to execute".to_string());
        }
        if !probe_kvm() {
            return Err("/dev/kvm unavailable: Tier-1 microVMs need KVM".to_string());
        }
        let config = self.microvm.clone().ok_or_else(|| {
            "microvm tier needs kernel/rootfs images (see sandbox config)".to_string()
        })?;
        let mut supervisor = MicroVmSupervisor::new(config.clone());
        supervisor.launch(&self.firecracker_bin).await?;
        let request = runner_guest_agent::ExecRequest {
            argv: command.to_vec(),
            cwd: "/".to_string(),
            env: std::env::vars().collect(),
            timeout_secs: timeout.as_secs().max(1),
        };
        let outcome = crate::vsock::dispatch(
            &config.vsock_path,
            &request,
            timeout,
            &mut tokio::io::stdout(),
            &mut tokio::io::stderr(),
        )
        .await;
        supervisor.shutdown().await;
        outcome
    }
}

fn next_engine_job_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "engine-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

/// Spawn errors worth one retry: the observed `pre_exec` unshare-race
/// ENOENT (flakes spawning on-PATH binaries under test concurrency)
/// plus the classic transient spawn errnos. Genuine failures surface
/// unchanged after the single backoff. Deliberately broader than
/// worker.rs's busy-only policy, which stays pinned by its own test.
fn is_transient_spawn_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        NotFound | ExecutableFileBusy | ResourceBusy | OutOfMemory | WouldBlock
    )
}

/// Spawn with one retry on transient errors (10ms backoff); every other
/// error — and the second transient failure — returns immediately.
async fn spawn_with_transient_retry(
    cmd: &mut TokioCommand,
) -> std::io::Result<tokio::process::Child> {
    match cmd.spawn() {
        Ok(child) => Ok(child),
        Err(e) if is_transient_spawn_error(&e) => {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cmd.spawn()
        }
        Err(e) => Err(e),
    }
}

async fn execute_process(
    command: &[String],
    timeout: Duration,
    qos: Arc<dyn QosBackend>,
) -> Result<i32, String> {
    if command.is_empty() {
        return Err("no command to execute".to_string());
    }
    #[cfg(windows)]
    eprintln!("governor disabled: Windows Tier-3 mode");
    let workspace = Workspace::create(&sanitize_job_id(&next_engine_job_id()))
        .map_err(|e| format!("workspace setup failed: {e}"))?;
    // macOS Tier-2 is Seatbelt, applied in `sandbox_pre_exec`; the
    // userns probe is Linux-only.
    #[cfg(target_os = "macos")]
    let sandboxed = true;
    #[cfg(not(target_os = "macos"))]
    let sandboxed = probe_userns();

    let mut cmd = TokioCommand::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    // QoS hook always installed (no-op off macOS); the sandbox setup
    // rides along when Tier-2 is available (userns on Linux, Seatbelt
    // on macOS). The job cwd is the workspace either way (child-side
    // chdir when sandboxed, parent-side otherwise).
    let spec = if sandboxed {
        Some(workspace.sandbox_spec()?)
    } else {
        cmd.current_dir(workspace.path());
        None
    };
    runner_core::governor::darwin::install_child_hook(
        &mut cmd,
        qos,
        spec.map(|spec| move || crate::mounts::sandbox_pre_exec(&spec)),
    );

    let mut child = spawn_with_transient_retry(&mut cmd)
        .await
        .map_err(|e| format!("failed to spawn command: {e}"))?;
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return Err(format!("command wait failed: {e}")),
        Err(_) => {
            child.kill().await.ok();
            return Err(format!("command timed out after {}s", timeout.as_secs()));
        }
    };
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_names_parse_and_round_trip() {
        assert_eq!(
            SandboxDriver::from_name("process").unwrap(),
            SandboxDriver::Process
        );
        assert_eq!(
            SandboxDriver::from_name("MicroVM").unwrap(),
            SandboxDriver::MicroVm
        );
        assert_eq!(
            SandboxDriver::from_name("firecracker").unwrap(),
            SandboxDriver::MicroVm
        );
        assert!(SandboxDriver::from_name("gvisor").is_err());
        assert_eq!(SandboxDriver::default(), SandboxDriver::Process);
        assert_eq!(SandboxDriver::MicroVm.name(), "microvm");
    }

    /// Exit-0 / exit-nonzero argv per platform (`true`/`false` don't
    /// exist on Windows; `cmd /c exit N` propagates N).
    fn exit_zero_argv() -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".to_string(), "/c".to_string(), "exit 0".to_string()]
        } else {
            vec!["true".to_string()]
        }
    }

    fn exit_nonzero_argv() -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".to_string(), "/c".to_string(), "exit 3".to_string()]
        } else {
            vec!["false".to_string()]
        }
    }

    #[tokio::test]
    async fn process_tier_runs_and_propagates_exit_codes() {
        let engine = SandboxEngine::new(SandboxDriver::Process);
        let ok = engine
            .execute(&exit_zero_argv(), Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(ok, 0);
        let fail = engine
            .execute(&exit_nonzero_argv(), Duration::from_secs(30))
            .await
            .unwrap();
        assert_ne!(fail, 0);
        assert!(engine.execute(&[], Duration::from_secs(5)).await.is_err());
    }

    #[test]
    fn transient_spawn_errors_cover_flake_kinds() {
        use std::io::{Error, ErrorKind::*};
        // Retried: observed pre_exec-race ENOENT plus the classic
        // transient spawn errnos.
        for kind in [
            NotFound,
            ExecutableFileBusy,
            ResourceBusy,
            OutOfMemory,
            WouldBlock,
        ] {
            assert!(
                is_transient_spawn_error(&Error::new(kind, "x")),
                "{kind:?} should retry"
            );
        }
        // Never retried: genuine failures stay loud and fast.
        for kind in [
            PermissionDenied,
            InvalidInput,
            TimedOut,
            BrokenPipe,
            AlreadyExists,
            InvalidData,
            UnexpectedEof,
            AddrInUse,
            ConnectionRefused,
        ] {
            assert!(
                !is_transient_spawn_error(&Error::new(kind, "x")),
                "{kind:?} should not retry"
            );
        }
    }

    #[tokio::test]
    async fn transient_retry_surfaces_persistent_errors_fast() {
        // A genuinely missing binary still errors (after one bounded
        // retry), with no long backoff loop.
        let engine = SandboxEngine::new(SandboxDriver::Process);
        let start = std::time::Instant::now();
        let err = engine
            .execute(&["/no/such/binary-xyz".to_string()], Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.contains("failed to spawn"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "retry took too long: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn process_spawns_apply_qos_best_effort() {
        use runner_core::governor::darwin::MockQos;
        let dir = runner_core::test_support::TempDir::new("driver-qos").unwrap();
        let log = dir.path().join("qos.log");
        let mock = Arc::new(MockQos::with_log(log.clone()));
        let code = execute_process(&exit_zero_argv(), Duration::from_secs(30), mock)
            .await
            .unwrap();
        assert_eq!(code, 0);
        // The QoS log is written by the pre_exec child hook, which has
        // no Windows counterpart (no fork); spawns proceed unhooked.
        if cfg!(unix) {
            assert_eq!(std::fs::read_to_string(&log).unwrap(), "process\n");
        }
        // A failing backend never fails the spawn.
        let failing = Arc::new(MockQos::new());
        failing.set_failing();
        let code = execute_process(&exit_zero_argv(), Duration::from_secs(30), failing)
            .await
            .unwrap();
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn microvm_tier_fails_closed_without_kvm_or_config() {
        // No config at all: KVM probe fires first on hosts without /dev/kvm,
        // config error fires on KVM hosts. Either way: clean Err, no panic,
        // and definitely no host execution.
        let engine = SandboxEngine::new(SandboxDriver::MicroVm);
        let err = engine
            .execute(&["id".to_string()], Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            err.contains("KVM") || err.contains("kernel/rootfs"),
            "unexpected error: {err}"
        );
    }
}
