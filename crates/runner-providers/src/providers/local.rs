//! Local provider: direct sandboxed command execution (`runner exec`).
//!
//! Runs any command under the zero-freeze governor: unprivileged user +
//! mount + PID namespaces with a tmpfs workspace when the kernel allows
//! it (plain spawn with cgroup governance otherwise), slice attachment,
//! live PSI weight control, and real-time output streaming.

use std::net::IpAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command as TokioCommand;

use super::{JobPayload, ProviderAdapter, ProviderJob};
use runner_core::governor::cgroup::CgroupSlice;
use runner_core::governor::psi::PsiPoller;
use runner_sandbox::mounts::{probe_userns, sanitize_job_id, Workspace};

/// Refuse commands carrying a literal blocked egress IP in any argument.
/// (Full packet-level enforcement is the nftables ruleset in
/// `src/sandbox/network.rs`, applied by privileged hosts.)
fn reject_blocked_ip_literals(command: &[String]) -> Result<()> {
    for arg in command {
        if let Ok(ip) = IpAddr::from_str(arg) {
            if runner_sandbox::network::is_blocked_egress(ip) {
                anyhow::bail!("refusing to run with blocked egress IP literal: {arg}");
            }
        }
    }
    Ok(())
}

/// Unique job id per execution: concurrent calls must never share a
/// workspace directory (one call's scrub-on-drop would remove another's
/// child working directory mid-spawn).
fn next_job_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "exec-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

/// Drive slice weights from live PSI until cancelled (250ms cadence).
async fn govern_slice_while_running(slice: CgroupSlice) {
    let poller = PsiPoller::spawn();
    let mut rx = poller.subscribe();
    loop {
        tokio::select! {
            _ = rx.changed() => {
                let snapshot = *rx.borrow_and_update();
                let weight = runner_core::governor::cgroup::weight_for_cpu_psi(
                    snapshot.cpu_some_avg10(),
                );
                // Best-effort: unprivileged runs simply cannot write the slice.
                let _ = slice.set_weight(weight);
            }
        }
    }
}

/// Execute a command under zero-freeze governance, returning its exit code.
///
/// Sandboxing: tmpfs user namespace when available (unless `no_sandbox`);
/// otherwise direct spawn still governed by the cgroup slice + PSI loop.
/// Stdout/stderr stream to the terminal in real time. Timeout kills the
/// child and returns an error (never a freeze).
pub async fn execute_local_sandboxed(
    command: &[String],
    no_sandbox: bool,
    timeout: Duration,
) -> Result<i32> {
    if command.is_empty() {
        anyhow::bail!("no command to execute");
    }
    reject_blocked_ip_literals(command)?;

    // Workspace lifetime spans the run so Drop scrubs it after exit.
    let workspace =
        Workspace::create(&sanitize_job_id(&next_job_id())).context("workspace setup failed")?;
    let sandboxed = !no_sandbox && probe_userns();

    let mut cmd = TokioCommand::new(&command[0]);
    cmd.args(&command[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    // Sandboxed runs chdir into the scratch workspace via pre_exec;
    // governed-direct runs inherit the caller's cwd so repo-relative
    // commands (`cargo test`, pre-commit hooks) resolve correctly.
    let spec = if sandboxed {
        Some(workspace.sandbox_spec().map_err(|e| anyhow::anyhow!(e))?)
    } else {
        None
    };
    runner_core::governor::darwin::install_child_hook(
        &mut cmd,
        std::sync::Arc::new(runner_core::governor::darwin::DarwinQos),
        spec.map(|spec| move || runner_sandbox::mounts::sandbox_pre_exec(&spec)),
    );

    let slice = CgroupSlice::system_default();
    let _ = slice.ensure();
    let governor = tokio::spawn(govern_slice_while_running(slice.clone()));

    let mut child = cmd.spawn().context("failed to spawn command")?;
    if let Some(pid) = child.id() {
        let _ = std::fs::write(slice.path().join("cgroup.procs"), pid.to_string());
    }
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            governor.abort();
            return Err(e.into());
        }
        Err(_) => {
            child.kill().await.ok();
            governor.abort();
            anyhow::bail!("command timed out after {}s", timeout.as_secs());
        }
    };
    governor.abort();
    Ok(status.code().unwrap_or(1))
}

/// Captured command output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Execute with piped stdio + extra env, capturing output (used by
/// provider adapters that stream logs back, e.g. GitLab trace upload).
/// Same sandboxing, governance, and timeout-kill contract as
/// [`execute_local_sandboxed`].
pub async fn execute_captured(
    command: &[String],
    env: &[(String, String)],
    no_sandbox: bool,
    timeout: Duration,
) -> Result<ExecOutput> {
    if command.is_empty() {
        anyhow::bail!("no command to execute");
    }
    reject_blocked_ip_literals(command)?;

    let workspace =
        Workspace::create(&sanitize_job_id(&next_job_id())).context("workspace setup failed")?;
    let sandboxed = !no_sandbox && probe_userns();

    let mut cmd = TokioCommand::new(&command[0]);
    cmd.args(&command[1..])
        .envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let spec = if sandboxed {
        Some(workspace.sandbox_spec().map_err(|e| anyhow::anyhow!(e))?)
    } else {
        cmd.current_dir(workspace.path());
        None
    };
    runner_core::governor::darwin::install_child_hook(
        &mut cmd,
        std::sync::Arc::new(runner_core::governor::darwin::DarwinQos),
        spec.map(|spec| move || runner_sandbox::mounts::sandbox_pre_exec(&spec)),
    );

    let slice = CgroupSlice::system_default();
    let _ = slice.ensure();
    let governor = tokio::spawn(govern_slice_while_running(slice.clone()));

    let mut child = cmd.spawn().context("failed to spawn command")?;
    if let Some(pid) = child.id() {
        let _ = std::fs::write(slice.path().join("cgroup.procs"), pid.to_string());
    }
    // Drain pipes on background tasks so output larger than the pipe buffer
    // never deadlocks the child; `child` stays owned here for timeout kill.
    // Each stream is capped: runaway output evicts the oldest bytes instead
    // of growing daemon RAM without bound.
    let mut stdout_pipe = child.stdout.take().context("stdout pipe missing")?;
    let mut stderr_pipe = child.stderr.take().context("stderr pipe missing")?;
    let out_task = tokio::spawn(async move { drain_reader(&mut stdout_pipe).await });
    let err_task = tokio::spawn(async move { drain_reader(&mut stderr_pipe).await });
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            governor.abort();
            out_task.abort();
            err_task.abort();
            return Err(e.into());
        }
        Err(_) => {
            child.kill().await.ok();
            governor.abort();
            out_task.abort();
            err_task.abort();
            anyhow::bail!("command timed out after {}s", timeout.as_secs());
        }
    };
    governor.abort();
    let stdout = out_task
        .await
        .context("stdout drain failed")?
        .context("stdout read failed")?;
    let stderr = err_task
        .await
        .context("stderr drain failed")?
        .context("stderr read failed")?;
    Ok(ExecOutput {
        code: status.code().unwrap_or(1),
        stdout,
        stderr,
    })
}

/// Per-stream capture cap: 10 MiB retained, oldest bytes evicted first.
pub const CAPTURE_CAP_BYTES: usize = 10 * 1024 * 1024;

/// Drain a reader to EOF into a bounded ring (tail wins on overflow).
async fn drain_reader<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use runner_telemetry::RingBuffer;
    use tokio::io::AsyncReadExt;

    let mut ring = RingBuffer::new(CAPTURE_CAP_BYTES);
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        ring.push_bytes(&chunk[..n]);
    }
    Ok(ring.contents())
}

/// Direct-execution provider (drives `runner exec`; no remote queue).
pub struct LocalProvider {
    enabled: bool,
}

impl LocalProvider {
    pub fn new() -> Self {
        Self { enabled: true }
    }
}

impl Default for LocalProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ProviderAdapter for LocalProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    async fn poll_pending_jobs(&self) -> Result<Vec<ProviderJob>> {
        // Local execution is push-based (`runner exec`); nothing to poll.
        Ok(Vec::new())
    }

    async fn claim_job(&self, _job_id: &str) -> Result<JobPayload> {
        anyhow::bail!("local jobs execute directly via `runner exec`; nothing to claim")
    }

    async fn complete_job(&self, _job_id: &str, _success: bool) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_private_ip_literals() {
        let err = execute_local_sandboxed(
            &["ping".to_string(), "10.0.0.5".to_string()],
            true,
            Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("blocked egress"), "{err:#}");
    }

    #[test]
    fn literal_scan_ignores_hostnames() {
        assert!(reject_blocked_ip_literals(&[
            "curl".to_string(),
            "https://example.com".to_string()
        ])
        .is_ok());
    }
}
