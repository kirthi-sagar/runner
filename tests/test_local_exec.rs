//! Local execution tests: exit codes and timeout enforcement.
//!
//! Commands run through the real `execute_local_sandboxed` path
//! (sandboxed where the kernel allows it, governed otherwise).

use runner::providers::local::execute_local_sandboxed;
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
    assert!(execute_local_sandboxed(&[], true, Duration::from_secs(5)).await.is_err());
}
