//! Dual-tier sandbox engine: instant switching between lightweight
//! process isolation (community) and hardware-isolated microVMs
//! (enterprise) behind one [`SandboxEngine`] interface.
//!
//! * [`SandboxDriver::Process`] — unprivileged user + mount namespaces with
//!   an ephemeral tmpfs workspace (falls back to a plain governed spawn
//!   where user namespaces are unavailable).
//! * [`SandboxDriver::MicroVm`] — Firecracker microVM boot/shutdown
//!   lifecycle. Guest workload dispatch over vsock is operator-integrated;
//!   the engine guarantees the hardware isolation boundary and fails
//!   closed (clean errors, never silent host execution) without KVM,
//!   the Firecracker binary, or kernel/rootfs images.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command as TokioCommand;

use crate::microvm::{probe_kvm, MicroVmConfig, MicroVmSupervisor};
use crate::mounts::{probe_userns, sanitize_job_id, Workspace};

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
    /// kills the child. MicroVM tier: verifies the hardware isolation
    /// lifecycle (boot + teardown); guest workload dispatch is a clean
    /// error until a vsock guest agent is integrated.
    pub async fn execute(&self, command: &[String], timeout: Duration) -> Result<i32, String> {
        match self.driver {
            SandboxDriver::Process => execute_process(command, timeout).await,
            SandboxDriver::MicroVm => self.execute_microvm().await,
        }
    }

    async fn execute_microvm(&self) -> Result<i32, String> {
        if !probe_kvm() {
            return Err("/dev/kvm unavailable: Tier-1 microVMs need KVM".to_string());
        }
        let config = self.microvm.clone().ok_or_else(|| {
            "microvm tier needs kernel/rootfs images (see sandbox config)".to_string()
        })?;
        let mut supervisor = MicroVmSupervisor::new(config);
        supervisor.launch(&self.firecracker_bin).await?;
        supervisor.shutdown().await;
        Err(
            "microvm guest dispatch needs a vsock guest agent; boot/shutdown lifecycle verified"
                .to_string(),
        )
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

async fn execute_process(command: &[String], timeout: Duration) -> Result<i32, String> {
    if command.is_empty() {
        return Err("no command to execute".to_string());
    }
    let workspace = Workspace::create(&sanitize_job_id(&next_engine_job_id()))
        .map_err(|e| format!("workspace setup failed: {e}"))?;
    let sandboxed = probe_userns();

    let mut cmd = TokioCommand::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if sandboxed {
        let spec = workspace.sandbox_spec()?;
        // SAFETY: pre_exec runs after fork in the child only.
        unsafe {
            cmd.pre_exec(move || crate::mounts::sandbox_pre_exec(&spec));
        }
    } else {
        cmd.current_dir(workspace.path());
    }

    let mut child = cmd
        .spawn()
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

    #[tokio::test]
    async fn process_tier_runs_and_propagates_exit_codes() {
        let engine = SandboxEngine::new(SandboxDriver::Process);
        let ok = engine
            .execute(&["true".to_string()], Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(ok, 0);
        let fail = engine
            .execute(&["false".to_string()], Duration::from_secs(30))
            .await
            .unwrap();
        assert_ne!(fail, 0);
        assert!(engine.execute(&[], Duration::from_secs(5)).await.is_err());
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
