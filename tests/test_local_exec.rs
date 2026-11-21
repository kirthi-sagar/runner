//! Local execution tests: exit codes and timeout enforcement.
//!
//! Commands run through the real `execute_local_sandboxed` path
//! (sandboxed where the kernel allows it, governed otherwise).

use runner::providers::local::{execute_captured, execute_local_sandboxed, CAPTURE_CAP_BYTES};
use std::time::Duration;

fn cmd(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Shell line ending: `cmd.exe` emits CRLF where POSIX shells emit LF.
fn sh_line(text: &str) -> Vec<u8> {
    #[cfg(windows)]
    return format!("{text}\r\n").into_bytes();
    #[cfg(unix)]
    return format!("{text}\n").into_bytes();
}

#[tokio::test]
async fn echo_succeeds_with_zero() {
    // Unix ships /bin/echo; on Windows `echo` is cmd-internal only.
    #[cfg(unix)]
    let argv = cmd(&["echo", "hello"]);
    #[cfg(windows)]
    let argv = cmd(&["cmd", "/c", "echo", "hello"]);
    let code = execute_local_sandboxed(&argv, false, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(code, 0);
}

#[tokio::test]
async fn python_computation_succeeds() {
    // windows-latest ships CPython as `python` (no `python3` alias).
    #[cfg(unix)]
    let argv = cmd(&["python3", "-c", "print(2+2)"]);
    #[cfg(windows)]
    let argv = cmd(&["python", "-c", "print(2+2)"]);
    let code = execute_local_sandboxed(&argv, false, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(code, 0);
}

#[tokio::test]
async fn exit_code_propagates_on_failure() {
    #[cfg(unix)]
    let argv = cmd(&["python3", "-c", "import sys; sys.exit(7)"]);
    #[cfg(windows)]
    let argv = cmd(&["python", "-c", "import sys; sys.exit(7)"]);
    let code = execute_local_sandboxed(&argv, true, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(code, 7);
}

#[tokio::test]
async fn timeout_kills_and_errors() {
    // No `sleep(1)` on Windows; PowerShell Start-Sleep sleeps the
    // full duration (unlike `timeout /t`, which errors without a
    // console on stdin).
    #[cfg(unix)]
    let argv = cmd(&["sleep", "30"]);
    #[cfg(windows)]
    let argv = cmd(&[
        "powershell",
        "-NoProfile",
        "-Command",
        "Start-Sleep -Seconds 30",
    ]);
    let err = execute_local_sandboxed(&argv, true, Duration::from_millis(300))
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
    // `cmd /c cd` prints the working directory like `pwd`.
    #[cfg(unix)]
    let argv = cmd(&["sh", "-c", &format!("pwd > {marker}")]);
    #[cfg(windows)]
    let argv = cmd(&["cmd", "/c", &format!("cd > {marker}")]);
    let code = execute_local_sandboxed(&argv, true, Duration::from_secs(30))
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
    // No `head`/`/dev/zero` on Windows; PowerShell writes the bytes.
    #[cfg(unix)]
    let argv = cmd(&["head", "-c", "12582912", "/dev/zero"]);
    #[cfg(windows)]
    let argv = cmd(&[
        "powershell",
        "-NoProfile",
        "-Command",
        "$s=[Console]::OpenStandardOutput();$b=New-Object byte[] 12582912;$s.Write($b,0,$b.Length)",
    ]);
    let out = execute_captured(&argv, &[], true, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.len(), CAPTURE_CAP_BYTES);
    assert!(out.stdout.iter().all(|&b| b == 0));
    assert!(out.stderr.is_empty());
}

#[tokio::test]
async fn capture_keeps_small_output_intact() {
    #[cfg(unix)]
    let argv = cmd(&["sh", "-c", "echo out; echo err >&2"]);
    #[cfg(windows)]
    let argv = cmd(&["cmd", "/c", "echo out& echo err >&2"]);
    let out = execute_captured(&argv, &[], true, Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout, sh_line("out"));
    assert_eq!(out.stderr, sh_line("err"));
}
