//! IPC socket tests: bind, ping round-trip, and status telemetry.

use runner::governor::supervisor::new_shared_state;
use runner::ipc::{ipc_call, IpcServer};
use std::sync::Arc;

#[tokio::test]
async fn ipc_ping_roundtrip() {
    let dir = runner::test_support::TempDir::new("ipc-it").unwrap();
    let path = dir.path().join("runner.sock");
    let server = Arc::new(IpcServer::bind(&path, new_shared_state()).await.unwrap());
    let task = tokio::spawn(async move { server.serve().await });

    let res = ipc_call(&path, "ping").await.unwrap();
    assert_eq!(res["result"], "pong");

    let res = ipc_call(&path, "status").await.unwrap();
    assert_eq!(res["result"]["status"], "healthy");
    assert!(res["result"]["host"]["total_cores"].as_u64().unwrap() >= 1);

    let res = ipc_call(&path, "bogus").await.unwrap();
    assert_eq!(res["error"]["code"], -32601);

    task.abort();
}

#[tokio::test]
async fn ipc_snapshot_and_poll_now() {
    let dir = runner::test_support::TempDir::new("ipc-snap").unwrap();
    let path = dir.path().join("runner.sock");
    let state = new_shared_state();
    {
        let mut guard = state.write().await;
        guard.job_started("github", "7", "ci / test");
        guard.set_queue_depth(3);
    }
    let server = Arc::new(IpcServer::bind(&path, state.clone()).await.unwrap());
    let task = tokio::spawn(async move { server.serve().await });

    let res = ipc_call(&path, "snapshot").await.unwrap();
    let snap = &res["result"];
    assert_eq!(snap["jobs"][0]["id"], "7");
    assert_eq!(snap["jobs"][0]["provider"], "github");
    assert_eq!(snap["queue_depth"], 3);
    assert!(snap.get("psi_warn").and_then(|v| v.as_f64()).unwrap() > 0.0);

    // poll_now broadcasts: every waiting forge loop wakes, not just one.
    // (notify_waiters only reaches current waiters, so wait first.)
    let wakeup = state.read().await.wakeup();
    let mut waiters = Vec::new();
    for _ in 0..3 {
        let wakeup = wakeup.clone();
        waiters.push(tokio::spawn(async move { wakeup.notified().await }));
    }
    // Let all three waiters park before notifying.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let res = ipc_call(&path, "poll_now").await.unwrap();
    assert_eq!(res["result"]["notified"], true);
    for waiter in waiters {
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("wakeup must fire")
            .unwrap();
    }

    task.abort();
}

#[tokio::test]
async fn ipc_job_cancel_drops_records() {
    use runner::ipc::ipc_call_with;
    let dir = runner::test_support::TempDir::new("ipc-cancel").unwrap();
    let path = dir.path().join("runner.sock");
    let state = new_shared_state();
    {
        let mut guard = state.write().await;
        guard.job_started("github", "7", "ci / test");
        guard.job_started("gitlab", "7", "ci / test");
    }
    let server = Arc::new(IpcServer::bind(&path, state.clone()).await.unwrap());
    let task = tokio::spawn(async move { server.serve().await });

    let params = |job_id: &str| Some(serde_json::json!({ "job_id": job_id }));
    let res = ipc_call_with(&path, "job_cancel", params("7"))
        .await
        .unwrap();
    assert_eq!(res["result"]["cancelled"], true);
    assert_eq!(
        res["result"]["providers"],
        serde_json::json!(["github", "gitlab"])
    );
    // Second cancel finds nothing; empty ids are rejected.
    let res = ipc_call_with(&path, "job_cancel", params("7"))
        .await
        .unwrap();
    assert_eq!(res["result"]["cancelled"], false);
    let res = ipc_call_with(&path, "job_cancel", params("  "))
        .await
        .unwrap();
    assert_eq!(res["error"]["code"], -32602);

    task.abort();
}
