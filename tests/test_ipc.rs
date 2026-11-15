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
