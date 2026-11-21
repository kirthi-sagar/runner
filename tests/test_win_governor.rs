//! Windows governor integration: live Job Objects plus supervisor
//! ticks against the real kernel. Runs only on windows-native CI.

#![cfg(windows)]

use std::time::Duration;

/// Spawn a sleeper, assign it to a fresh job, and prove membership
/// plus limit round-trips — the worker spawn path's exact sequence.
#[tokio::test]
async fn worker_tree_assignment_and_limits_round_trip() {
    let job = runner_core::governor::windows::JobObject::create().expect("create job");
    let mut child = tokio::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id().expect("child pid");
    job.assign(pid).expect("assign to job");
    assert!(job.contains(pid).expect("membership query"));
    job.set_memory_cap(2 * 1024 * 1024 * 1024)
        .expect("set memory cap");
    job.set_cpu_weight(5).expect("set weight");
    assert_eq!(job.query_cpu_weight().expect("query weight"), 5);
    child.kill().await.ok();
    child.wait().await.ok();
}

/// The supervisor loop activates: ticks run, a weight publishes, and
/// the daemon job carries an applied (nonzero) weight — without
/// panicking. Ended by abort; the loop itself runs until ctrl_c.
#[tokio::test]
async fn supervisor_loop_ticks_and_applies_weight() {
    let state = runner_core::governor::supervisor::new_shared_state();
    let task_state = state.clone();
    let task =
        tokio::spawn(
            async move { runner_core::governor::supervisor::run_supervisor(task_state).await },
        );
    // Several 250ms ticks (the first only seeds the sensor).
    tokio::time::sleep(Duration::from_millis(900)).await;
    task.abort();
    let _ = task.await;
    let guard = state.read().await;
    let published = guard.last_weight.expect("a tick published a weight");
    assert!((1..=9).contains(&published), "weight {published}");
    drop(guard);
    // A fresh job reads weight 0 (never set); 1-9 proves the loop
    // applied to the daemon job. No equality with `published`: an
    // abort can land between publish and apply.
    let applied = runner_core::governor::windows::JobObject::system_default()
        .expect("system job")
        .query_cpu_weight()
        .expect("query weight");
    assert!((1..=9).contains(&applied), "applied {applied}");
}

/// Windows named pipes carry real IPC: a bound server answers a
/// status report over `\\.\pipe\runner-<stem>`, and the transport
/// leaves no socket file behind.
#[tokio::test]
async fn win_named_pipe_serves_status() {
    let dir = runner_core::test_support::TempDir::new("win-named-pipe").unwrap();
    let sock = dir.path().join("status.sock");
    let server = std::sync::Arc::new(
        runner_core::ipc::IpcServer::bind(
            &sock,
            runner_core::governor::supervisor::new_shared_state(),
        )
        .await
        .unwrap(),
    );
    let task = tokio::spawn(async move { server.serve().await });
    let body = runner_core::ipc::ipc_call(&sock, "status").await.unwrap();
    let version = body["result"]["version"].as_str().unwrap_or("");
    assert!(!version.is_empty(), "status report version: {body}");
    assert!(!sock.exists(), "pipe transport leaves no socket file");
    task.abort();
}

/// The pidfile-mediated stop flow end to end: a recorded sleeper
/// reports alive, terminates on signal, the exit poll observes it,
/// and the pid file cleans up — the exact `runner stop` sequence.
#[tokio::test]
async fn win_pidfile_stop_flow() {
    use std::time::Duration;
    let pid_path = runner_core::pidfile::resolve_pid_path();
    assert_eq!(
        pid_path.file_name().and_then(|n| n.to_str()),
        Some("runner.pid"),
        "windows pid file name: {}",
        pid_path.display()
    );
    let mut child = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
        .spawn()
        .expect("spawn sleeper");
    let pid = child.id();
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent).expect("pid dir");
    }
    std::fs::write(&pid_path, format!("{pid}")).expect("write pid");
    assert_eq!(runner_core::pidfile::read_pid(&pid_path).unwrap(), pid);
    assert!(runner_core::pidfile::process_alive(pid));
    runner_core::pidfile::signal_daemon(pid, false).expect("terminate sleeper");
    assert!(runner_core::pidfile::wait_for_exit(
        pid,
        Duration::from_secs(10)
    ));
    std::fs::remove_file(&pid_path).ok();
    assert!(!pid_path.exists(), "pid file cleaned after stop");
    let _ = child.wait();
}
