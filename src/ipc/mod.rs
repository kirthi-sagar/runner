//! Local Unix domain socket API.
//!
//! Listens on [`SOCK_PATH`] (`/run/runner.sock`), falling back to
//! `~/.runner/runner.sock` when unprivileged. Sockets are created with
//! `0600` owner-only permissions. Requests are newline-delimited JSON-RPC:
//! `ping` (liveness) and `status` (host telemetry).

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::governor::supervisor::SharedState;

/// Privileged supervisor socket path.
pub const SOCK_PATH: &str = "/run/runner.sock";

/// Unprivileged fallback socket path.
pub fn fallback_sock_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".runner").join("runner.sock"))
}

/// Pick the privileged path when its parent is writable, else the fallback.
pub fn resolve_sock_path() -> PathBuf {
    let primary = PathBuf::from(SOCK_PATH);
    if let Some(parent) = primary.parent() {
        // Writable probe: the daemon must be able to create the socket file.
        let probe = parent.join(".runner-write-probe");
        if std::fs::create_dir_all(parent).is_ok() && std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            return primary;
        }
    }
    fallback_sock_path().unwrap_or(primary)
}

/// Handle one IPC request value.
pub async fn handle_ipc_request(value: Value, state: &SharedState) -> Value {
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    match method {
        "ping" => serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": "pong" }),
        "status" => serde_json::json!({
            "jsonrpc": "2.0", "id": id, "result": crate::status::status_report(),
        }),
        "peers" => {
            let guard = state.read().await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "wan_peers": guard.peers(),
                "cloud_nodes": guard.cloud_nodes(),
                "drained_nodes": guard.drained_nodes(),
            } })
        }
        "join" => {
            let record_value = value
                .get("params")
                .and_then(|p| p.get("record"))
                .cloned()
                .unwrap_or(Value::Null);
            let record: Result<crate::config::PeerRecord, _> =
                serde_json::from_value(record_value);
            match record {
                Ok(record) => {
                    state.write().await.add_peer(record.clone());
                    serde_json::json!({ "jsonrpc": "2.0", "id": id,
                        "result": { "joined": record.node_id } })
                }
                Err(e) => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": format!("bad peer record: {e}") } }),
            }
        }
        _ => serde_json::json!({ "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") } }),
    }
}

async fn serve_conn(stream: UnixStream, state: SharedState) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(value) => handle_ipc_request(value, &state).await,
            Err(e) => serde_json::json!({ "jsonrpc": "2.0", "id": Value::Null,
                "error": { "code": -32700, "message": format!("parse error: {e}") } }),
        };
        writer.write_all(serde_json::to_string(&response)?.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
    Ok(())
}

/// Bound IPC server.
pub struct IpcServer {
    path: PathBuf,
    listener: UnixListener,
    state: SharedState,
}

impl IpcServer {
    /// Bind `path` (removing a stale socket first) with `0600` permissions.
    pub async fn bind(path: &Path, state: SharedState) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { path: path.to_path_buf(), listener, state })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop; runs until the listener errors fatally.
    pub async fn serve(&self) -> io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_conn(stream, state).await {
                    eprintln!("runner: ipc connection error: {e}");
                }
            });
        }
    }
}

/// Client: send one method call and wait for the response object.
pub async fn ipc_call(path: &Path, method: &str) -> io::Result<Value> {
    ipc_call_with(path, method, None).await
}

/// Client: method call with optional params.
pub async fn ipc_call_with(path: &Path, method: &str, params: Option<Value>) -> io::Result<Value> {
    let stream = UnixStream::connect(path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut req = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method });
    if let Some(params) = params {
        req["params"] = params;
    }
    writer.write_all(serde_json::to_string(&req)?.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "ipc: no response"))?;
    serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::supervisor::new_shared_state;

    #[tokio::test]
    async fn ping_roundtrip_over_socket() {
        let dir = crate::test_support::TempDir::new("ipc").unwrap();
        let path = dir.path().join("runner.sock");
        let server = std::sync::Arc::new(IpcServer::bind(&path, new_shared_state()).await.unwrap());
        let task = tokio::spawn(async move { server.serve().await });
        let res = ipc_call(&path, "ping").await.unwrap();
        assert_eq!(res["result"], "pong");
        task.abort();
    }

    #[tokio::test]
    async fn socket_has_owner_only_permissions() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_support::TempDir::new("ipc-perm").unwrap();
        let path = dir.path().join("runner.sock");
        let server = IpcServer::bind(&path, new_shared_state()).await.unwrap();
        let mode = std::fs::metadata(server.path()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
