//! Tier-1 Firecracker microVM sandboxing over the REST socket API.
//!
//! Hardware-isolated execution for database/nested-container workloads:
//! the supervisor spawns Firecracker, configures boot/rootfs/vsock over
//! its Unix domain socket API, and starts the instance — all with
//! graceful degradation when `/dev/kvm` is unavailable (no panics).

use std::path::{Path, PathBuf};

/// MicroVM instance configuration.
#[derive(Debug, Clone)]
pub struct MicroVmConfig {
    /// Firecracker API Unix socket path.
    pub socket_path: PathBuf,
    /// Uncompressed `vmlinux` guest kernel.
    pub kernel_path: PathBuf,
    /// ext4 rootfs image.
    pub rootfs_path: PathBuf,
    /// Guest vCPUs.
    pub vcpu_count: u8,
    /// Guest RAM in MiB.
    pub mem_size_mib: usize,
    /// vsock context id for host/guest calls.
    pub vsock_cid: u32,
    /// Host UDS path backing vsock.
    pub vsock_path: PathBuf,
}

impl MicroVmConfig {
    pub fn new(
        socket_path: PathBuf,
        kernel_path: PathBuf,
        rootfs_path: PathBuf,
        vsock_path: PathBuf,
    ) -> Self {
        Self {
            socket_path,
            kernel_path,
            rootfs_path,
            vcpu_count: 2,
            mem_size_mib: 1024,
            vsock_cid: 3,
            vsock_path,
        }
    }
}

/// `PUT /boot-source` payload (pure; unit-tested).
pub fn boot_source_payload(kernel_path: &Path, boot_args: &str) -> serde_json::Value {
    serde_json::json!({
        "kernel_image_path": kernel_path.to_string_lossy(),
        "boot_args": boot_args,
    })
}

/// `PUT /drives/rootfs` payload (pure; unit-tested).
pub fn drive_payload(rootfs_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "drive_id": "rootfs",
        "path_on_host": rootfs_path.to_string_lossy(),
        "is_root_device": true,
        "is_read_only": false,
    })
}

/// `PUT /vsock` payload (pure; unit-tested).
pub fn vsock_payload(cid: u32, uds_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "guest_cid": cid,
        "uds_path": uds_path.to_string_lossy(),
    })
}

/// `PUT /actions` payload (pure; unit-tested).
pub fn action_payload(action_type: &str) -> serde_json::Value {
    serde_json::json!({ "action_type": action_type })
}

/// Default guest kernel cmdline.
pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

/// Minimal HTTP/1.1 client over a Unix socket for the Firecracker API.
pub struct FirecrackerClient {
    // Unread on Windows (`put` fails before dialing); kept so the
    // public shape stays identical across platforms.
    #[cfg_attr(windows, allow(dead_code))]
    socket_path: PathBuf,
}

impl FirecrackerClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Raw `PUT <path>` with a JSON body; Ok on 2xx, Err otherwise.
    #[cfg(unix)]
    pub async fn put(&self, path: &str, body: &serde_json::Value) -> Result<(), String> {
        self.put_inner(path, body).await
    }

    /// Windows has no Firecracker/KVM; Tier-1 calls fail loudly at the
    /// single choke point every setter delegates through.
    #[cfg(windows)]
    pub async fn put(&self, _path: &str, _body: &serde_json::Value) -> Result<(), String> {
        eprintln!("[runner] unsupported on Windows: Tier-1 microVM (Firecracker)");
        Err("unsupported on Windows: Tier-1 microVM (Firecracker)".to_string())
    }

    #[cfg(unix)]
    async fn put_inner(&self, path: &str, body: &serde_json::Value) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = serde_json::to_vec(body).map_err(|e| format!("encode: {e}"))?;
        let request = format!(
            "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| format!("firecracker socket: {e}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        stream
            .write_all(&body)
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|e| format!("read: {e}"))?;
        let status_line = response
            .split(|b| *b == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .unwrap_or("");
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(format!("firecracker {path}: HTTP {code}"))
        }
    }

    pub async fn set_boot_source(&self, kernel_path: &Path, boot_args: &str) -> Result<(), String> {
        self.put("/boot-source", &boot_source_payload(kernel_path, boot_args))
            .await
    }

    pub async fn set_rootfs(&self, drive_path: &Path) -> Result<(), String> {
        self.put("/drives/rootfs", &drive_payload(drive_path)).await
    }

    pub async fn set_vsock(&self, cid: u32, uds_path: &Path) -> Result<(), String> {
        self.put("/vsock", &vsock_payload(cid, uds_path)).await
    }

    pub async fn start_instance(&self) -> Result<(), String> {
        self.put("/actions", &action_payload("InstanceStart")).await
    }

    pub async fn send_ctrl_alt_del(&self) -> Result<(), String> {
        self.put("/actions", &action_payload("SendCtrlAltDel"))
            .await
    }
}

/// True when KVM is present and this process can open it read/write.
pub fn probe_kvm() -> bool {
    let path = Path::new("/dev/kvm");
    if !path.exists() {
        return false;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .is_ok()
}

/// Wait for a UDS path to accept connections (readiness polling).
#[cfg(unix)]
pub async fn wait_for_socket(path: &Path, timeout: std::time::Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for {}", path.display()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Windows has no Unix domain sockets; readiness polling fails loudly.
#[cfg(windows)]
pub async fn wait_for_socket(_path: &Path, _timeout: std::time::Duration) -> Result<(), String> {
    eprintln!("[runner] unsupported on Windows: Tier-1 microVM (Firecracker)");
    Err("unsupported on Windows: Tier-1 microVM (Firecracker)".to_string())
}

/// MicroVM lifecycle supervisor: spawn, configure, start, stop, clean.
pub struct MicroVmSupervisor {
    config: MicroVmConfig,
    child: Option<tokio::process::Child>,
}

impl MicroVmSupervisor {
    pub fn new(config: MicroVmConfig) -> Self {
        Self {
            config,
            child: None,
        }
    }

    pub fn client(&self) -> FirecrackerClient {
        FirecrackerClient::new(self.config.socket_path.clone())
    }

    /// Launch Firecracker, wait for the API socket, and configure
    /// boot/rootfs/vsock. Fails gracefully (Err, never panic) without KVM
    /// or when the binary is missing.
    pub async fn launch(&mut self, firecracker_bin: &Path) -> Result<(), String> {
        if !probe_kvm() {
            return Err("/dev/kvm unavailable: Tier-1 microVMs need KVM".to_string());
        }
        let _ = std::fs::remove_file(&self.config.socket_path);
        let mut child = tokio::process::Command::new(firecracker_bin)
            .arg("--api-sock")
            .arg(&self.config.socket_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("firecracker spawn: {e}"))?;
        // Fail fast if the process exits during socket wait.
        let socket_path = self.config.socket_path.clone();
        let ready =
            async { wait_for_socket(&socket_path, std::time::Duration::from_secs(10)).await };
        tokio::select! {
            result = ready => result?,
            status = child.wait() => {
                return Err(format!("firecracker exited during boot: {:?}", status.map(|s| s.code())));
            }
        }
        let client = self.client();
        client
            .set_boot_source(&self.config.kernel_path, DEFAULT_BOOT_ARGS)
            .await?;
        client.set_rootfs(&self.config.rootfs_path).await?;
        client
            .set_vsock(self.config.vsock_cid, &self.config.vsock_path)
            .await?;
        client.start_instance().await?;
        self.child = Some(child);
        Ok(())
    }

    /// Graceful stop (CtrlAltDel + SIGKILL fallback) and socket cleanup.
    pub async fn shutdown(&mut self) {
        let _ = self.client().send_ctrl_alt_del().await;
        if let Some(mut child) = self.child.take() {
            tokio::select! {
                _ = child.wait() => {},
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    child.kill().await.ok();
                }
            }
        }
        let _ = std::fs::remove_file(&self.config.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shapes_match_firecracker_api() {
        let boot = boot_source_payload(Path::new("/k/vmlinux"), "console=ttyS0");
        assert_eq!(boot["kernel_image_path"], "/k/vmlinux");
        let drive = drive_payload(Path::new("/r/rootfs.ext4"));
        assert_eq!(drive["drive_id"], "rootfs");
        assert_eq!(drive["is_root_device"], true);
        let vsock = vsock_payload(3, Path::new("/tmp/v.sock"));
        assert_eq!(vsock["guest_cid"], 3);
        assert_eq!(
            action_payload("InstanceStart")["action_type"],
            "InstanceStart"
        );
    }

    #[test]
    fn config_defaults_match_spec() {
        let config = MicroVmConfig::new("a".into(), "k".into(), "r".into(), "v".into());
        assert_eq!(config.vcpu_count, 2);
        assert_eq!(config.mem_size_mib, 1024);
        assert_eq!(config.vsock_cid, 3);
    }

    #[tokio::test]
    async fn socket_wait_times_out_cleanly() {
        let missing = PathBuf::from("/tmp/runner-no-such-socket-12345.sock");
        let err = wait_for_socket(&missing, std::time::Duration::from_millis(120))
            .await
            .unwrap_err();
        assert!(err.contains("timed out"), "{err}");
    }
}
