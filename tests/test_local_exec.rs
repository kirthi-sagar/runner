//! Local execution tests: exit codes and timeout enforcement.
//!
//! Commands run through the real `execute_local_sandboxed` path
//! (sandboxed where the kernel allows it, governed otherwise).

use runner::providers::local::{execute_captured, execute_local_sandboxed, CAPTURE_CAP_BYTES};
use std::time::Duration;

fn cmd(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn echo_succeeds_with_zero() {
    let code = execute_local_sandboxed(&cmd(&["echo", "hello"]), false, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(code, 0);
}

#[tokio::test]
async fn python_computation_succeeds() {
    let code = execute_local_sandboxed(
        &cmd(&["python3", "-c", "print(2+2)"]),
        false,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
}

#[tokio::test]
async fn exit_code_propagates_on_failure() {
    let code = execute_local_sandboxed(
        &cmd(&["python3", "-c", "import sys; sys.exit(7)"]),
        true,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(code, 7);
}

#[tokio::test]
async fn timeout_kills_and_errors() {
    let err = execute_local_sandboxed(&cmd(&["sleep", "30"]), true, Duration::from_millis(300))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("timed out"), "{err:#}");
}

#[tokio::test]
async fn empty_command_is_rejected() {
    assert!(execute_local_sandboxed(&[], true, Duration::from_secs(5))
        .await
        .is_err());
}

#[tokio::test]
async fn direct_mode_inherits_caller_cwd() {
    // Governed-direct runs must resolve relative paths against the
    // invoking directory (repo checks, hooks) — not scratch space.
    // `no_sandbox = true` pins the direct path on every host.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let marker = format!(
        "cwd-probe-{}-{}.txt",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    );
    let code = execute_local_sandboxed(
        &cmd(&["sh", "-c", &format!("pwd > {marker}")]),
        true,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    let expected = std::env::current_dir().unwrap();
    let observed = std::fs::read_to_string(expected.join(&marker)).unwrap();
    std::fs::remove_file(expected.join(&marker)).unwrap();
    assert_eq!(observed.trim(), expected.to_string_lossy());
}

#[tokio::test]
async fn capture_caps_runaway_output_at_ten_mib() {
    // 12 MiB of output; only the trailing 10 MiB may be retained.
    let out = execute_captured(
        &cmd(&["head", "-c", "12582912", "/dev/zero"]),
        &[],
        true,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.len(), CAPTURE_CAP_BYTES);
    assert!(out.stdout.iter().all(|&b| b == 0));
    assert!(out.stderr.is_empty());
}

#[tokio::test]
async fn capture_keeps_small_output_intact() {
    let out = execute_captured(
        &cmd(&["sh", "-c", "echo out; echo err >&2"]),
        &[],
        true,
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, b"err\n");
}
