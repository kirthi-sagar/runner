//! Local Unix domain socket API.
//!
//! Listens on [`SOCK_PATH`] (`/run/runner.sock`), falling back to
//! `~/.runner/runner.sock` when unprivileged. Sockets are created with
//! `0600` owner-only permissions. Requests are newline-delimited JSON-RPC:
//! `ping` (liveness), `status` (host telemetry), `peers`, `join`,
//! `snapshot` (daemon state for `runner top`), and `poll_now` (wake the
//! coordinator for instant dispatch).

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
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".runner").join("runner.sock"))
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
        "status" => {
            let guard = state.read().await;
            serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": crate::status::status_report_with_state(&guard),
            })
        }
        "peers" => {
            let guard = state.read().await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "wan_peers": guard.peers(),
                "cloud_nodes": guard.cloud_nodes(),
                "drained_nodes": guard.drained_nodes(),
            } })
        }
        "snapshot" => {
            let guard = state.read().await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "weight": guard.last_weight,
                "slots": guard.last_slots,
                "in_flight": guard.in_flight(),
                "jobs": guard.in_flight_jobs(),
                "queue_depth": guard.queue_depth(),
                "wan_peers": guard.peers(),
                "cloud_nodes": guard.cloud_nodes(),
                "drained_nodes": guard.drained_nodes(),
                "afk_boosted": guard.afk.boosted(),
                "afk_mode": guard.afk_mode.name(),
                "psi_warn": guard.psi_warn,
                "psi_crit": guard.psi_crit,
            } })
        }
        "poll_now" => {
            state.read().await.wakeup().notify_waiters();
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": { "notified": true } })
        }
        "cloud_list" => {
            let guard = state.read().await;
            let pool = guard.cloud_pool();
            let tracked = pool.as_ref().is_some_and(|p| p.spend_tracked());
            let (spend_usd, spend_error) = match pool.as_ref().map(|p| p.month_spend()) {
                Some(Ok(usd)) => (usd, None),
                Some(Err(e)) => {
                    eprintln!("runner: spend ledger unreadable ({e})");
                    (0.0, Some(e))
                }
                None => (0.0, None),
            };
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "nodes": guard.cloud_nodes(),
                "providers": {
                    "digitalocean": pool.as_ref().is_some_and(|p| p.has_provider("digitalocean")),
                    "render": pool.as_ref().is_some_and(|p| p.has_provider("render")),
                },
                "max_monthly_spend_usd": guard.cloud_spend_cap(),
                "spend_usd": spend_usd,
                "spend_tracked": tracked,
                "spend_error": spend_error,
            } })
        }
        "cache_stats" => {
            let guard = state.read().await;
            match guard.cache_store() {
                Some(store) => {
                    let stats = store.stats();
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "entries": stats.entries,
                        "size_bytes": stats.size_bytes,
                        "hits": stats.hits,
                        "misses": stats.misses,
                        "hit_ratio": stats.hit_ratio,
                        "bytes_served": stats.bytes_served,
                        "bytes_uploaded": stats.bytes_uploaded,
                        "remote_hits": stats.remote_hits,
                        "remote_bytes_imported": stats.remote_bytes_imported,
                        "remote_bytes_served": stats.remote_bytes_served,
                    } })
                }
                None => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": "cache proxy not running" } }),
            }
        }
        "cache_clear" => {
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            let all = params.get("all").and_then(Value::as_bool).unwrap_or(false);
            let older_than_days = params.get("older_than_days").and_then(Value::as_u64);
            if !all && older_than_days.is_none() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "all or older_than_days is required" } });
            }
            let guard = state.read().await;
            match guard.cache_store() {
                Some(store) => {
                    let days = if all { None } else { older_than_days };
                    let (removed, freed_bytes) = store.clear(days);
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "removed": removed,
                        "freed_bytes": freed_bytes,
                    } })
                }
                None => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": "cache proxy not running" } }),
            }
        }
        "cloud_terminate" => {
            let instance_id = value
                .get("params")
                .and_then(|p| p.get("instance_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if instance_id.is_empty() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "instance_id must not be empty" } });
            }
            let (node, pool) = {
                let guard = state.read().await;
                (
                    guard
                        .cloud_nodes()
                        .into_iter()
                        .find(|n| n.id == instance_id),
                    guard.cloud_pool(),
                )
            };
            match (node, pool) {
                (None, _) => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": format!("unknown instance: {instance_id}") } }),
                (_, None) => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": "cloud bursting not configured" } }),
                (Some(node), Some(pool)) => match pool.terminate(&node).await {
                    Ok(cleanup) => {
                        state.write().await.remove_cloud_node(&instance_id);
                        serde_json::json!({ "jsonrpc": "2.0", "id": id,
                            "result": { "terminated": instance_id, "cleanup": cleanup } })
                    }
                    Err(e) => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32603, "message": format!("terminate failed: {e}") } }),
                },
            }
        }
        "cloud_purge" => {
            let (nodes, pool) = {
                let guard = state.read().await;
                (guard.cloud_nodes(), guard.cloud_pool())
            };
            if nodes.is_empty() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "result": { "purged": Vec::<String>::new(), "failed": Vec::<String>::new() } });
            }
            let Some(pool) = pool else {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": "cloud bursting not configured" } });
            };
            let mut purged = Vec::new();
            let mut failed = Vec::new();
            for node in &nodes {
                match pool.terminate(node).await {
                    Ok(_) => {
                        state.write().await.remove_cloud_node(&node.id);
                        purged.push(node.id.clone());
                    }
                    Err(e) => failed.push(format!("{}: {e}", node.id)),
                }
            }
            serde_json::json!({ "jsonrpc": "2.0", "id": id,
                "result": { "purged": purged, "failed": failed } })
        }
        "join" => {
            let record_value = value
                .get("params")
                .and_then(|p| p.get("record"))
                .cloned()
                .unwrap_or(Value::Null);
            let record: Result<crate::config::PeerRecord, _> = serde_json::from_value(record_value);
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
        "throttle_set" => {
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            let level = params
                .get("level")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let minutes = params
                .get("duration_minutes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let Some(weight) = throttle_weight_for_level(&level) else {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "level must be warning|critical|high" } });
            };
            if minutes == 0 {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "duration_minutes must be > 0" } });
            }
            state.write().await.set_throttle(
                weight,
                std::time::Duration::from_secs(minutes * 60),
                std::time::Instant::now(),
            );
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "level": level,
                "cpu_weight": weight,
                "duration_minutes": minutes,
            } })
        }
        "reserve" => {
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            let cores = params.get("cores").and_then(Value::as_f64).unwrap_or(0.0);
            let ram_gb = params.get("ram_gb").and_then(Value::as_f64).unwrap_or(0.0);
            let mins = params
                .get("duration_minutes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let reason = params
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let (cores, ram_mb, mins) =
                match crate::mcp::tools::validate_reserve(cores, ram_gb, mins) {
                    Ok(v) => v,
                    Err(e) => {
                        return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32602, "message": e } })
                    }
                };
            let r = crate::mcp::tools::reserve_on(state, cores, ram_mb, mins, reason).await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "reservation_id": r.id,
                "cores": r.cores,
                "ram_gb": ram_gb,
                "duration_minutes": mins,
            } })
        }
        "release" => {
            let id_param = value
                .get("params")
                .and_then(|p| p.get("reservation_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if id_param.trim().is_empty() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "reservation_id must not be empty" } });
            }
            let found = crate::mcp::tools::release_on(state, &id_param).await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "released": id_param,
                "found": found,
            } })
        }
        "drain" => {
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            let node_id = params
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let reason = params
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if node_id.trim().is_empty() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "node_id must not be empty" } });
            }
            crate::mcp::tools::drain_on(state, node_id.clone(), reason).await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "node_id": node_id,
                "drained": true,
            } })
        }
        "cloud_capacity" => {
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            let provider = params
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let max = params
                .get("max_instances")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u32;
            let hours = params
                .get("duration_hours")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if let Err(e) = crate::mcp::tools::validate_cloud_request(&provider, max, hours) {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": e } });
            }
            let (pool, cap) = {
                let guard = state.read().await;
                (guard.cloud_pool(), guard.cloud_spend_cap())
            };
            let Some(pool) = pool else {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                    "approved": false,
                    "reason": "cloud pool not initialized on the daemon",
                } });
            };
            match crate::mcp::tools::request_cloud_with(&pool, cap, state, &provider, max, hours)
                .await
            {
                Ok(v) => serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": v }),
                Err(e) => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": e } }),
            }
        }
        "ci_status" => {
            let v = crate::mcp::tools::ci_status_value(state).await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": v })
        }
        "fleet_topology" => {
            let v = crate::mcp::tools::fleet_topology_value(state).await;
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": v })
        }
        _ => serde_json::json!({ "jsonrpc": "2.0", "id": id,
            "error": { "code": -32601, "message": format!("method not found: {method}") } }),
    }
}

/// Map a throttle level name to its cgroup weight. `high` is the
/// README's word for maximum throttling (alias of `critical`).
pub fn throttle_weight_for_level(level: &str) -> Option<u32> {
    use crate::governor::cgroup::{WEIGHT_TRICKLE, WEIGHT_WARNING};
    match level.trim().to_ascii_lowercase().as_str() {
        "warning" => Some(WEIGHT_WARNING),
        "critical" | "high" => Some(WEIGHT_TRICKLE),
        _ => None,
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
        writer
            .write_all(serde_json::to_string(&response)?.as_bytes())
            .await?;
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
        Ok(Self {
            path: path.to_path_buf(),
            listener,
            state,
        })
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
    writer
        .write_all(serde_json::to_string(&req)?.as_bytes())
        .await?;
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

    fn cloud_req(method: &str, params: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    async fn seeded_state() -> crate::governor::supervisor::SharedState {
        let state = new_shared_state();
        {
            let mut guard = state.write().await;
            guard.add_cloud_node(crate::mesh::cloud::CloudNode {
                id: "i-1".to_string(),
                provider: "digitalocean".to_string(),
                status: "active".to_string(),
                launched_at: 0,
                name: String::new(),
            });
            guard.set_cloud_pool(crate::mesh::cloud::CloudPool::default(), 25.0);
        }
        state
    }

    #[tokio::test]
    async fn cloud_list_reports_nodes_providers_and_cap() {
        let state = seeded_state().await;
        let res = handle_ipc_request(cloud_req("cloud_list", serde_json::json!({})), &state).await;
        let result = &res["result"];
        assert_eq!(result["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(result["nodes"][0]["id"], "i-1");
        assert_eq!(result["providers"]["digitalocean"], false);
        assert_eq!(result["max_monthly_spend_usd"], 25.0);
        // Seeded pool carries no ledger: untracked, zero spend.
        assert_eq!(result["spend_usd"], 0.0);
        assert_eq!(result["spend_tracked"], false);
    }

    #[tokio::test]
    async fn cloud_list_reports_corrupt_ledger_as_error() {
        let dir = crate::test_support::TempDir::new("ipc-ledger").unwrap();
        let ledger_path = dir.path().join("spend_ledger.json");
        std::fs::write(&ledger_path, "{not json").unwrap();
        let pool = crate::mesh::cloud::CloudPool::from_clients(None, None)
            .with_ledger(crate::mesh::cloud::ledger::SpendLedger::new(ledger_path));
        let state = new_shared_state();
        state.write().await.set_cloud_pool(pool, 25.0);
        let res = handle_ipc_request(cloud_req("cloud_list", serde_json::json!({})), &state).await;
        let result = &res["result"];
        // Tracked pool, but the error — not $0.00 — is the signal.
        assert_eq!(result["spend_tracked"], true);
        assert!(result["spend_error"].as_str().unwrap().contains("parse"));
    }

    #[tokio::test]
    async fn cache_stats_and_clear_roundtrip() {
        let state = new_shared_state();
        // No cache attached: honest error, not zeros.
        let res = handle_ipc_request(cloud_req("cache_stats", serde_json::json!({})), &state).await;
        assert!(res.get("error").is_some());

        let dir = crate::test_support::TempDir::new("ipc-cache").unwrap();
        let store = crate::cache::store::CacheStore::open(&dir.path().join("c"), 1 << 30).unwrap();
        store
            .reserve(crate::cache::store::GLOBAL_SCOPE, "k", "v")
            .unwrap();
        state
            .write()
            .await
            .set_cache(crate::cache::server::CacheServerState::new(
                store,
                "http://127.0.0.1:8787".to_string(),
            ));
        assert_eq!(
            state.read().await.cache_base_url().as_deref(),
            Some("http://127.0.0.1:8787")
        );
        let res = handle_ipc_request(cloud_req("cache_stats", serde_json::json!({})), &state).await;
        assert_eq!(res["result"]["entries"], 0);
        assert_eq!(res["result"]["hit_ratio"], 0.0);

        // Clear requires explicit scope.
        let res = handle_ipc_request(cloud_req("cache_clear", serde_json::json!({})), &state).await;
        assert!(res.get("error").is_some());
        let res = handle_ipc_request(
            cloud_req("cache_clear", serde_json::json!({ "all": true })),
            &state,
        )
        .await;
        assert_eq!(res["result"]["removed"], 0);
    }

    #[tokio::test]
    async fn cloud_terminate_rejects_unknown_and_missing_id() {
        let state = seeded_state().await;
        let res = handle_ipc_request(
            cloud_req(
                "cloud_terminate",
                serde_json::json!({ "instance_id": "nope" }),
            ),
            &state,
        )
        .await;
        assert_eq!(res["error"]["code"], -32602);
        let res =
            handle_ipc_request(cloud_req("cloud_terminate", serde_json::json!({})), &state).await;
        assert_eq!(res["error"]["code"], -32602);
    }

    #[tokio::test]
    async fn cloud_mutations_require_a_pool() {
        let bare = new_shared_state();
        bare.write()
            .await
            .add_cloud_node(crate::mesh::cloud::CloudNode {
                id: "i-1".to_string(),
                provider: "digitalocean".to_string(),
                status: "active".to_string(),
                launched_at: 0,
                name: String::new(),
            });
        let res = handle_ipc_request(
            cloud_req(
                "cloud_terminate",
                serde_json::json!({ "instance_id": "i-1" }),
            ),
            &bare,
        )
        .await;
        assert_eq!(res["error"]["code"], -32603);
        let res = handle_ipc_request(cloud_req("cloud_purge", serde_json::json!({})), &bare).await;
        assert_eq!(res["error"]["code"], -32603);
    }

    #[tokio::test]
    async fn cloud_purge_empty_succeeds_without_pool() {
        let res = handle_ipc_request(
            cloud_req("cloud_purge", serde_json::json!({})),
            &new_shared_state(),
        )
        .await;
        assert!(res["result"]["purged"].as_array().unwrap().is_empty());
    }

    #[test]
    fn throttle_levels_map_to_ladder_weights() {
        use crate::governor::cgroup::{WEIGHT_TRICKLE, WEIGHT_WARNING};
        assert_eq!(throttle_weight_for_level("warning"), Some(WEIGHT_WARNING));
        assert_eq!(throttle_weight_for_level("critical"), Some(WEIGHT_TRICKLE));
        // `high` is the README alias for maximum throttling.
        assert_eq!(throttle_weight_for_level("high"), Some(WEIGHT_TRICKLE));
        assert_eq!(throttle_weight_for_level("HIGH"), Some(WEIGHT_TRICKLE));
        assert_eq!(throttle_weight_for_level("medium"), None);
        assert_eq!(throttle_weight_for_level(""), None);
    }

    #[tokio::test]
    async fn throttle_set_engages_and_validates() {
        let state = new_shared_state();
        let res = handle_ipc_request(
            cloud_req(
                "throttle_set",
                serde_json::json!({ "level": "high", "duration_minutes": 5 }),
            ),
            &state,
        )
        .await;
        assert_eq!(res["result"]["level"], "high");
        assert_eq!(res["result"]["cpu_weight"], 1);
        assert_eq!(res["result"]["duration_minutes"], 5);
        // Latch visible on shared state until expiry.
        let now = std::time::Instant::now();
        assert_eq!(state.read().await.throttle_weight(now), Some(1));

        // Invalid level and zero duration reject with -32602.
        let res = handle_ipc_request(
            cloud_req(
                "throttle_set",
                serde_json::json!({ "level": "medium", "duration_minutes": 5 }),
            ),
            &state,
        )
        .await;
        assert_eq!(res["error"]["code"], -32602);
        let res = handle_ipc_request(
            cloud_req(
                "throttle_set",
                serde_json::json!({ "level": "warning", "duration_minutes": 0 }),
            ),
            &state,
        )
        .await;
        assert_eq!(res["error"]["code"], -32602);
    }
}
