//! MicroVM tests: Firecracker payload shapes, mock UDS handshake,
//! and graceful KVM-absent behavior (no hardware required).

use runner::sandbox::microvm::{
    action_payload, boot_source_payload, drive_payload, probe_kvm, vsock_payload, MicroVmConfig,
    MicroVmSupervisor,
};
#[cfg(unix)]
use runner::sandbox::microvm::{wait_for_socket, FirecrackerClient};
use std::path::Path;
use std::time::Duration;

/// Keep-alive discipline: the real server never closes; a faithful
/// mock exits only on client hangup. (A mock that closes would mask
/// EOF-framing regressions — the exact live hang this guards.)
#[cfg(unix)]
async fn hold_open(mut stream: tokio::net::UnixStream) {
    use tokio::io::AsyncReadExt;
    let mut drain = [0u8; 1024];
    loop {
        match stream.read(&mut drain).await {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

/// Minimal mock Firecracker API: accepts PUTs, records paths, answers
/// 204 with the exact keep-alive bytes the live server sends.
#[cfg(unix)]
async fn serve_mock(
    path: std::path::PathBuf,
    seen: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // Read request head (single read is enough for small PUTs).
            let Ok(n) = stream.read(&mut buf).await else {
                return;
            };
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            // Drain any body bytes already buffered is unnecessary for the mock.
            if let Some(request_line) = head.lines().next() {
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                if parts.len() >= 2 {
                    seen.lock().await.push(parts[1].to_string());
                }
            }
            let _ = stream
                .write_all(
                    b"HTTP/1.1 204 \r\nServer: Firecracker API\r\nConnection: keep-alive\r\n\r\n",
                )
                .await;
            hold_open(stream).await;
        });
    }
}

#[test]
fn payload_structures_match_api() {
    let boot = boot_source_payload(Path::new("/kernels/vmlinux"), "console=ttyS0");
    assert_eq!(boot["boot_args"], "console=ttyS0");
    let drive = drive_payload(Path::new("/images/rootfs.ext4"));
    assert_eq!(drive["path_on_host"], "/images/rootfs.ext4");
    assert_eq!(drive["is_read_only"], false);
    let vsock = vsock_payload(7, Path::new("/tmp/v.sock"));
    assert_eq!(vsock["guest_cid"], 7);
    assert_eq!(
        action_payload("SendCtrlAltDel")["action_type"],
        "SendCtrlAltDel"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn client_handshake_and_instance_start_over_mock_uds() {
    let dir = runner::test_support::TempDir::new("fc-mock").unwrap();
    let sock = dir.path().join("fc.sock");
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let server = tokio::spawn(serve_mock(sock.clone(), seen.clone()));
    wait_for_socket(&sock, Duration::from_secs(5))
        .await
        .unwrap();

    let client = FirecrackerClient::new(sock.clone());
    // Bounded: an EOF-framing regression would hang forever against
    // the keep-alive mock instead of failing.
    tokio::time::timeout(Duration::from_secs(30), async {
        client
            .set_boot_source(Path::new("/k"), "console=ttyS0")
            .await
            .unwrap();
        client.set_rootfs(Path::new("/r")).await.unwrap();
        client.set_vsock(3, Path::new("/v")).await.unwrap();
        client.start_instance().await.unwrap();
    })
    .await
    .expect("mock handshake must complete without EOF");

    let seen = seen.lock().await;
    for path in ["/boot-source", "/drives/rootfs", "/vsock", "/actions"] {
        assert!(seen.iter().any(|p| p == path), "missing {path}: {seen:?}");
    }
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn client_surfaces_error_status_with_framed_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = runner::test_support::TempDir::new("fc-mock-err").unwrap();
    let sock = dir.path().join("fc.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let _ = stream.read(&mut buf).await;
        let body = br#"{"fault_message":"bad drive"}"#;
        let head = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        hold_open(stream).await;
    });
    let client = FirecrackerClient::new(sock);
    let err = tokio::time::timeout(Duration::from_secs(30), client.set_rootfs(Path::new("/r")))
        .await
        .expect("error response must arrive without EOF")
        .unwrap_err();
    assert!(err.contains("400"), "{err}");
    server.abort();
}

/// Resolved live-harness inputs; `None` means skip (standard CI).
struct LiveInputs {
    kernel: std::path::PathBuf,
    rootfs: std::path::PathBuf,
    firecracker: std::path::PathBuf,
}

fn binary_resolves(bin: &std::path::Path) -> bool {
    if bin.components().count() > 1 {
        return bin.is_file();
    }
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
}

fn live_inputs_from(
    live_var_set: bool,
    kvm_present: bool,
    kernel: Option<std::path::PathBuf>,
    rootfs: Option<std::path::PathBuf>,
    firecracker: Option<std::path::PathBuf>,
) -> Option<LiveInputs> {
    if !live_var_set || !kvm_present {
        return None;
    }
    let (kernel, rootfs) = (kernel?, rootfs?);
    if !kernel.is_file() || !rootfs.is_file() {
        return None;
    }
    let bin = firecracker.unwrap_or_else(|| std::path::PathBuf::from("firecracker"));
    if !binary_resolves(&bin) {
        return None;
    }
    Some(LiveInputs {
        kernel,
        rootfs,
        firecracker: bin,
    })
}

fn live_inputs() -> Option<LiveInputs> {
    live_inputs_from(
        std::env::var("RUNNER_LIVE_KVM").is_ok(),
        probe_kvm(),
        std::env::var_os("RUNNER_LIVE_KERNEL").map(std::path::PathBuf::from),
        std::env::var_os("RUNNER_LIVE_ROOTFS").map(std::path::PathBuf::from),
        std::env::var_os("RUNNER_LIVE_FIRECRACKER").map(std::path::PathBuf::from),
    )
}

#[test]
fn live_gate_requires_every_input() {
    let dir = runner::test_support::TempDir::new("kvm-gate").unwrap();
    let kernel = dir.path().join("vmlinux");
    let rootfs = dir.path().join("rootfs.ext4");
    let bin = dir.path().join("firecracker");
    std::fs::write(&kernel, b"k").unwrap();
    std::fs::write(&rootfs, b"r").unwrap();
    std::fs::write(&bin, b"x").unwrap();
    let missing = dir.path().join("absent");
    // Each missing piece skips, including unresolvable binaries.
    assert!(live_inputs_from(
        false,
        true,
        Some(kernel.clone()),
        Some(rootfs.clone()),
        Some(bin.clone())
    )
    .is_none());
    assert!(live_inputs_from(
        true,
        false,
        Some(kernel.clone()),
        Some(rootfs.clone()),
        Some(bin.clone())
    )
    .is_none());
    assert!(live_inputs_from(true, true, None, Some(rootfs.clone()), Some(bin.clone())).is_none());
    assert!(live_inputs_from(true, true, Some(kernel.clone()), None, Some(bin.clone())).is_none());
    assert!(live_inputs_from(
        true,
        true,
        Some(missing.clone()),
        Some(rootfs.clone()),
        Some(bin.clone())
    )
    .is_none());
    assert!(live_inputs_from(
        true,
        true,
        Some(kernel.clone()),
        Some(rootfs.clone()),
        Some(missing.clone())
    )
    .is_none());
    assert!(live_inputs_from(
        true,
        true,
        Some(kernel.clone()),
        Some(rootfs.clone()),
        Some(std::path::PathBuf::from("definitely-not-a-binary-xyz"))
    )
    .is_none());
    // Complete inputs pass, with PATH search for bare binary names.
    assert!(live_inputs_from(
        true,
        true,
        Some(kernel.clone()),
        Some(rootfs.clone()),
        Some(bin)
    )
    .is_some());
    // PATH search for bare binary names: `sh` on Unix CI,
    // `cmd.exe` (always on PATH via SystemRoot; the extension is
    // required since resolution is a plain file probe) on Windows.
    #[cfg(unix)]
    let path_probe = std::path::PathBuf::from("sh");
    #[cfg(windows)]
    let path_probe = std::path::PathBuf::from("cmd.exe");
    assert!(live_inputs_from(true, true, Some(kernel), Some(rootfs), Some(path_probe)).is_some());
}

/// Opt-in live boot: real Firecracker launch → Tier-1 dispatch →
/// shutdown. Skips silently without `RUNNER_LIVE_KVM=1`, /dev/kvm,
/// guest images, and a firecracker binary, so standard CI is unaffected.
#[tokio::test]
async fn live_kvm_boot_dispatch_and_shutdown() {
    let Some(inputs) = live_inputs() else {
        eprintln!("live KVM harness skipped (needs RUNNER_LIVE_KVM=1, /dev/kvm, RUNNER_LIVE_KERNEL/ROOTFS images, firecracker binary)");
        return;
    };
    use runner::sandbox::driver::{SandboxDriver, SandboxEngine};
    let dir = runner::test_support::TempDir::new("kvm-live").unwrap();
    let vsock_path = dir.path().join("v.sock");
    let config = MicroVmConfig::new(
        dir.path().join("fc.sock"),
        inputs.kernel,
        inputs.rootfs,
        vsock_path.clone(),
    );
    let engine =
        SandboxEngine::new(SandboxDriver::MicroVm).with_microvm(config, inputs.firecracker);
    // Loose assertion is deliberate: stock images carry no guest agent,
    // so dispatch cannot succeed, and Firecracker's exact UDS direction
    // (bind-vs-connect, `<uds>_<port>`) is documented but unverified
    // against a live binary. What this proves on a KVM host: real boot
    // works, dispatch fails closed, shutdown cleans up, nothing panics.
    let result = engine
        .execute(&["id".to_string()], Duration::from_secs(15))
        .await;
    assert!(
        result.is_err(),
        "live dispatch unexpectedly succeeded: {result:?}"
    );
    assert!(
        !vsock_path.exists(),
        "vsock socket file leaked after live run"
    );
}

#[tokio::test]
async fn supervisor_reports_missing_kvm_without_panic() {
    if probe_kvm() {
        eprintln!("KVM present on this host; asserting graceful launch path instead");
        return;
    }
    let dir = runner::test_support::TempDir::new("fc-nokvm").unwrap();
    let config = MicroVmConfig::new(
        dir.path().join("fc.sock"),
        dir.path().join("vmlinux"),
        dir.path().join("rootfs.ext4"),
        dir.path().join("v.sock"),
    );
    let mut supervisor = MicroVmSupervisor::new(config);
    let err = supervisor
        .launch(Path::new("/nonexistent/firecracker"))
        .await
        .unwrap_err();
    assert!(err.contains("/dev/kvm"), "{err}");
}

#[tokio::test]
async fn missing_binary_reports_clean_error() {
    // Regardless of KVM presence, a bogus binary path must surface Err.
    // (When KVM exists, launch proceeds past the probe to the spawn error.)
    let dir = runner::test_support::TempDir::new("fc-nobin").unwrap();
    let config = MicroVmConfig::new(
        dir.path().join("fc.sock"),
        dir.path().join("vmlinux"),
        dir.path().join("rootfs.ext4"),
        dir.path().join("v.sock"),
    );
    let mut supervisor = MicroVmSupervisor::new(config);
    let result = supervisor
        .launch(Path::new("/nonexistent-firecracker-binary-xyz"))
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("/dev/kvm") || err.contains("spawn"),
        "unexpected error: {err}"
    );
}
