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
