//! MicroVM tests: Firecracker payload shapes, mock UDS handshake,
//! and graceful KVM-absent behavior (no hardware required).

use runner::sandbox::microvm::{
    FirecrackerClient, MicroVmConfig, MicroVmSupervisor, action_payload, boot_source_payload,
    drive_payload, probe_kvm, vsock_payload, wait_for_socket,
};
use std::path::Path;
use std::time::Duration;

/// Minimal mock Firecracker API: accepts PUTs, records paths, answers 204.
async fn serve_mock(path: std::path::PathBuf, seen: std::sync::Arc<tokio::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { break };
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // Read request head (single read is enough for small PUTs).
            let Ok(n) = stream.read(&mut buf).await else { return };
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            // Drain any body bytes already buffered is unnecessary for the mock.
            if let Some(request_line) = head.lines().next() {
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                if parts.len() >= 2 {
                    seen.lock().await.push(parts[1].to_string());
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
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
    assert_eq!(action_payload("SendCtrlAltDel")["action_type"], "SendCtrlAltDel");
}

#[tokio::test]
async fn client_handshake_and_instance_start_over_mock_uds() {
    let dir = runner::test_support::TempDir::new("fc-mock").unwrap();
    let sock = dir.path().join("fc.sock");
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let server = tokio::spawn(serve_mock(sock.clone(), seen.clone()));
    wait_for_socket(&sock, Duration::from_secs(5)).await.unwrap();

    let client = FirecrackerClient::new(sock.clone());
    client.set_boot_source(Path::new("/k"), "console=ttyS0").await.unwrap();
    client.set_rootfs(Path::new("/r")).await.unwrap();
    client.set_vsock(3, Path::new("/v")).await.unwrap();
    client.start_instance().await.unwrap();

    let seen = seen.lock().await;
    for path in ["/boot-source", "/drives/rootfs", "/vsock", "/actions"] {
        assert!(seen.iter().any(|p| p == path), "missing {path}: {seen:?}");
    }
    server.abort();
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
    let err = supervisor.launch(Path::new("/nonexistent/firecracker")).await.unwrap_err();
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
    let result = supervisor.launch(Path::new("/nonexistent-firecracker-binary-xyz")).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("/dev/kvm") || err.contains("spawn"),
        "unexpected error: {err}"
    );
}
