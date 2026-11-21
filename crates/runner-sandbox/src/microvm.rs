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

/// Default guest kernel cmdline. `init=/init` is required: the kernel's
/// built-in init search does not include `/init`, where the injected
/// guest agent lives. (`root=/dev/vda` is appended by Firecracker.)
pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off init=/init";

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
        use tokio::io::AsyncWriteExt;
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
        let code = tokio::time::timeout(API_READ_TIMEOUT, read_response_code(&mut stream))
            .await
            .map_err(|_| format!("firecracker {path}: response timed out"))??;
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

/// Bound for one API response read (local UDS; milliseconds normally).
#[cfg(unix)]
const API_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Fail-closed caps: Firecracker answers tiny headers and small JSON
/// error bodies; anything larger is a runaway or hostile peer.
#[cfg(unix)]
const MAX_HEADER_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Read one framed HTTP/1.1 response and return its status code.
/// Firecracker answers `Connection: keep-alive` and never closes, so
/// EOF-framed reads hang forever — frame on headers + Content-Length
/// instead, and never wait past the caller's timeout.
#[cfg(unix)]
async fn read_response_code(stream: &mut tokio::net::UnixStream) -> Result<u16, String> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("firecracker closed connection mid-response".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEADER_BYTES {
            return Err("firecracker response headers too large".to_string());
        }
        if let Some(end) = find_headers_end(&buf) {
            break end;
        }
    };
    let code = parse_status_code(&buf[..head_end]);
    let mut body = buf[head_end..].to_vec();
    // A declared body is drained exactly; without Content-Length the
    // response is whatever already arrived (204s carry nothing) and
    // waiting longer would reintroduce the keep-alive hang.
    if let Some(len) = parse_content_length(&buf[..head_end])? {
        if len > MAX_BODY_BYTES {
            return Err("firecracker response body too large".to_string());
        }
        while body.len() < len {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("firecracker truncated response body".to_string());
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > MAX_BODY_BYTES {
                return Err("firecracker response body too large".to_string());
            }
        }
        body.truncate(len);
    }
    let _ = body;
    Ok(code)
}

/// Offset just past the `\r\n\r\n` headers delimiter, if present.
#[cfg(unix)]
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Status code from a response head; 0 when unparseable (fails the
/// caller's 2xx check loudly rather than panicking).
#[cfg(unix)]
fn parse_status_code(head: &[u8]) -> u16 {
    let line = head.split(|b| *b == b'\n').next().unwrap_or(b"");
    let line = std::str::from_utf8(line).unwrap_or("");
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// Declared body length, if any. A malformed value fails closed:
/// without a trustworthy length there is no safe way to frame.
#[cfg(unix)]
fn parse_content_length(head: &[u8]) -> Result<Option<usize>, String> {
    for raw in head.split(|b| *b == b'\n') {
        let line = std::str::from_utf8(raw).unwrap_or("").trim();
        let Some(value) = line
            .get(..15)
            .filter(|name| name.eq_ignore_ascii_case("content-length:"))
            .map(|_| &line[15..])
        else {
            continue;
        };
        let len: usize = value
            .trim()
            .parse()
            .map_err(|_| "firecracker sent malformed Content-Length".to_string())?;
        return Ok(Some(len));
    }
    Ok(None)
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

    #[cfg(unix)]
    #[test]
    fn response_framing_parses_firecracker_shapes() {
        // Observed live: 204, keep-alive, no Content-Length, no body.
        let keepalive =
            b"HTTP/1.1 204 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(find_headers_end(keepalive), Some(keepalive.len()));
        assert_eq!(parse_status_code(keepalive), 204);
        assert_eq!(parse_content_length(keepalive).unwrap(), None);

        // Error shape: status + declared JSON body.
        let err = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 31\r\nConnection: keep-alive\r\n\r\n{\"error\":\"bad drive config...\"}";
        let end = find_headers_end(err).unwrap();
        assert_eq!(parse_status_code(&err[..end]), 400);
        assert_eq!(parse_content_length(&err[..end]).unwrap(), Some(31));
        assert_eq!(&err[end..], b"{\"error\":\"bad drive config...\"}");

        // Header names are case-insensitive; values tolerate padding.
        let mixed = b"HTTP/1.1 200 OK\r\ncontent-length:   5  \r\n\r\nhello";
        let end = find_headers_end(mixed).unwrap();
        assert_eq!(parse_status_code(&mixed[..end]), 200);
        assert_eq!(parse_content_length(&mixed[..end]).unwrap(), Some(5));

        // Degenerate input fails closed, never panics.
        assert_eq!(find_headers_end(b"HTTP/1.1 204"), None);
        assert_eq!(parse_status_code(b""), 0);
        assert_eq!(parse_status_code(b"garbage"), 0);
        assert_eq!(parse_content_length(b"HTTP/1.1 204\r\n\r\n").unwrap(), None);
        assert!(parse_content_length(b"Content-Length: many\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn socket_wait_times_out_cleanly() {
        let missing = PathBuf::from("/tmp/runner-no-such-socket-12345.sock");
        let err = wait_for_socket(&missing, std::time::Duration::from_millis(120))
            .await
            .unwrap_err();
        // No Unix domain sockets on Windows: the loud stub fires
        // instead of the timeout.
        if cfg!(windows) {
            assert!(err.contains("unsupported on Windows"), "{err}");
        } else {
            assert!(err.contains("timed out"), "{err}");
        }
    }
}
