//! Local daemon API: Unix domain sockets on unix, named pipes on Windows.
//!
//! Listens on [`SOCK_PATH`] (`/run/runner.sock`), falling back to
//! `~/.runner/runner.sock` when unprivileged; on Windows it listens on
//! `PIPE_NAME`. Unix sockets are created with `0600` owner-only
//! permissions. Requests are newline-delimited JSON-RPC either way:
//! `ping` (liveness), `status` (host telemetry), `peers`, `join`,
//! `snapshot` (daemon state for `runner top`), and `poll_now` (wake the
//! coordinator for instant dispatch).

use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;
#[cfg(windows)]
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

use crate::governor::supervisor::SharedState;

/// Privileged supervisor socket path.
pub const SOCK_PATH: &str = "/run/runner.sock";

/// Unprivileged fallback socket path.
pub fn fallback_sock_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".runner").join("runner.sock"))
}

/// Pick the privileged path when its parent is writable, else the fallback.
/// `RUNNER_SOCK` overrides everything (tests pin a hermetic path so
/// they never dial a live production daemon).
#[cfg(not(windows))]
pub fn resolve_sock_path() -> PathBuf {
    if let Some(path) = sock_override() {
        return path;
    }
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

/// Well-known production pipe. Callers pass paths through
/// [`pipe_name_for`], so TempDir-based tests derive unique names.
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\runner-ipc";

/// Windows pipe endpoint: literal `\\.\pipe\` paths pass through;
/// anything else (test TempDirs) derives a unique name, so parallel
/// tests never collide on one pipe.
#[cfg(windows)]
pub fn resolve_sock_path() -> PathBuf {
    if let Some(path) = sock_override() {
        return path;
    }
    PathBuf::from(PIPE_NAME)
}

/// Explicit socket override from the environment (blank values
/// ignored, so empty exports can't strand the client).
fn sock_override() -> Option<PathBuf> {
    let path = std::env::var("RUNNER_SOCK").ok()?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

/// Map a socket path to its Windows pipe name (see [`resolve_sock_path`]).
#[cfg(windows)]
pub fn pipe_name_for(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text.starts_with(r"\\.\pipe\") {
        return text.into_owned();
    }
    let stem: String = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Suffix with an FNV-1a hash of the FULL path: parallel tests
    // routinely share the `runner.sock` stem from different TempDirs,
    // and a stem-only name would put two servers on one pipe (one
    // bind fails with access-denied, or clients land on the wrong
    // server). FNV is deterministic across processes (unlike
    // SipHash), so out-of-process daemon/CLI pairs keep agreeing.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in text.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!(r"\\.\pipe\runner-test-{stem}-{hash:016x}")
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
        "cache_peers" => {
            let guard = state.read().await;
            match guard.cache_peer_snapshot() {
                Some(peers) => {
                    let rows: Vec<Value> = peers
                        .iter()
                        .map(|p| {
                            serde_json::json!({
                                "node_id": p.node_id,
                                "base_url": p.base_url,
                                "port": p.port,
                                "cache_enabled": p.cache_enabled,
                                "last_seen_secs": p.last_seen_secs,
                            })
                        })
                        .collect();
                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                        "peers": rows,
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
            let args: crate::mcp::tools::ReserveHostResourcesArgs =
                match serde_json::from_value(params) {
                    Ok(args) => args,
                    Err(e) => {
                        return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32602, "message": e.to_string() } })
                    }
                };
            let request = match crate::mcp::reservation::ReservationRequest::try_from(&args) {
                Ok(request) => request,
                Err(e) => {
                    return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": e } })
                }
            };
            let outcome = match crate::mcp::tools::reserve_on(state, &request).await {
                Ok(outcome) => outcome,
                Err(crate::mcp::reservation::ReserveError::Invalid(message)) => {
                    return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": message } })
                }
                Err(
                    full @ (crate::mcp::reservation::ReserveError::Full { .. }
                    | crate::mcp::reservation::ReserveError::Budget(_)),
                ) => {
                    return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": full.to_string() } })
                }
            };
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "reservation_id": outcome.reservation.id,
                "cores": outcome.reservation.cores,
                "ram_mb": outcome.reservation.ram_mb,
                "priority": outcome.reservation.priority,
                "duration_secs": request.duration_secs,
                "preempted": outcome.preempted,
                "reason": outcome.reservation.reason,
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
        "swarm_list" => {
            let guard = state.read().await;
            let mut swarms: Vec<crate::mcp::swarm::SwarmSummary> =
                guard.swarms().values().map(|s| s.summarize()).collect();
            swarms.sort_by(|a, b| a.swarm_id.cmp(&b.swarm_id));
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "swarms": swarms,
            } })
        }
        "swarm_kill" => {
            let swarm_id = value
                .get("params")
                .and_then(|p| p.get("swarm_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if swarm_id.trim().is_empty() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "swarm_id must not be empty" } });
            }
            let mut guard = state.write().await;
            match crate::mcp::swarm::terminate_swarm(
                guard.swarms_mut(),
                &swarm_id,
                std::time::Instant::now(),
            ) {
                Ok(outcome) => serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "result": outcome }),
                Err(crate::mcp::swarm::SwarmError::Invalid(message))
                | Err(crate::mcp::swarm::SwarmError::BudgetExceeded(message)) => {
                    serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": message } })
                }
                Err(internal @ crate::mcp::swarm::SwarmError::Internal(_)) => {
                    serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32603, "message": internal.to_string() } })
                }
            }
        }
        "job_cancel" => {
            let job_id = value
                .get("params")
                .and_then(|p| p.get("job_id"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if job_id.trim().is_empty() {
                return serde_json::json!({ "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32602, "message": "job_id must not be empty" } });
            }
            let mut guard = state.write().await;
            let providers = guard.job_cancel(&job_id);
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
                "job_id": job_id,
                "cancelled": !providers.is_empty(),
                "providers": providers,
            } })
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

/// One accepted connection: newline-delimited JSON-RPC in, single
/// JSON line per request out. Generic over the byte stream so Unix
/// sockets and Windows named pipes share framing.
async fn serve_conn<S>(stream: S, state: SharedState) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, mut writer) = tokio::io::split(stream);
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
    #[cfg(unix)]
    listener: UnixListener,
    /// Named-pipe instances are created per accept (no persistent
    /// listener object), so the server only retains the name — plus
    /// the first instance, created synchronously at bind so the pipe
    /// exists before any client can dial (mirrors the unix socket
    /// file appearing at bind).
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    first: std::sync::Mutex<Option<NamedPipeServer>>,
    state: SharedState,
}

impl IpcServer {
    /// Bind `path` (removing a stale socket first) with `0600` permissions.
    #[cfg(unix)]
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

    /// Bind the named pipe for `path` (see [`pipe_name_for`]). The
    /// first instance is created (and held) here with first-pipe-
    /// instance exclusivity: a taken name fails the bind (pipes
    /// leave no stale files, so taken always means a live daemon),
    /// and holding it closes the dial-before-serve race. The pipe
    /// then gets an owner + SYSTEM DACL (the unix `0600`); a DACL
    /// failure fails the bind rather than serving world-dialable.
    #[cfg(windows)]
    pub async fn bind(path: &Path, state: SharedState) -> io::Result<Self> {
        let pipe_name = pipe_name_for(path);
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)?;
        // Synchronous with creation (no await between): the default
        // DACL window is microseconds at bind, and the pipe DACL
        // then covers every instance the accept loop creates.
        crate::winacl::restrict_pipe_dacl(&pipe_name)?;
        Ok(Self {
            path: path.to_path_buf(),
            pipe_name,
            first: std::sync::Mutex::new(Some(first)),
            state,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept loop; runs until the listener errors fatally.
    #[cfg(unix)]
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

    /// Accept loop; runs until instance creation fails fatally. The
    /// first iteration serves the instance held since bind, later
    /// ones create fresh instances — each waits for a client, then
    /// hands it to a task and loops for the next.
    #[cfg(windows)]
    pub async fn serve(&self) -> io::Result<()> {
        loop {
            let held = self.first.lock().unwrap_or_else(|e| e.into_inner()).take();
            let pipe = match held {
                Some(pipe) => pipe,
                None => ServerOptions::new().create(&self.pipe_name)?,
            };
            pipe.connect().await?;
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_conn(pipe, state).await {
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
#[cfg(unix)]
pub async fn ipc_call_with(path: &Path, method: &str, params: Option<Value>) -> io::Result<Value> {
    ipc_call_with_inner(path, method, params).await
}

/// Windows client: open the pipe for `path` (same name rule as
/// the server, so TempDir tests dial their own instance). A missing
/// pipe fails fast (no daemon); a busy pipe retries briefly while
/// the server recreates its accept instance.
#[cfg(windows)]
pub async fn ipc_call_with(path: &Path, method: &str, params: Option<Value>) -> io::Result<Value> {
    let name = pipe_name_for(path);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let stream: NamedPipeClient = loop {
        match ClientOptions::new().open(&name) {
            Ok(client) => break client,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => return Err(e),
        }
    };
    ipc_roundtrip(stream, method, params).await
}

#[cfg(unix)]
async fn ipc_call_with_inner(
    path: &Path,
    method: &str,
    params: Option<Value>,
) -> io::Result<Value> {
    let stream = UnixStream::connect(path).await?;
    ipc_roundtrip(stream, method, params).await
}

/// One JSON-RPC exchange over any byte stream; shared by the Unix
/// and Windows clients so framing can never drift apart.
async fn ipc_roundtrip<S>(stream: S, method: &str, params: Option<Value>) -> io::Result<Value>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
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

    // Pipe names: production marker passes through literally, test
    // paths derive unique names that never collide with it.
    #[cfg(windows)]
    #[test]
    fn pipe_name_for_routes_production_and_tests() {
        use std::path::Path;
        assert_eq!(
            pipe_name_for(Path::new(r"\\.\pipe\runner-ipc")),
            r"\\.\pipe\runner-ipc"
        );
        let derived = pipe_name_for(Path::new(r"C:\Temp\runner-test-1\runner.sock"));
        assert!(derived.starts_with(r"\\.\pipe\runner-test-"), "{derived}");
        assert!(derived.contains("runner.sock"), "{derived}");
        assert_ne!(derived, PIPE_NAME);
        // Same stem from different dirs must not share a pipe
        // (parallel tests bind simultaneously).
        let other = pipe_name_for(Path::new(r"C:\Temp\runner-test-2\runner.sock"));
        assert_ne!(derived, other);
        // Same path re-derives the same name (server/client agree,
        // rebinds land on the same pipe).
        assert_eq!(
            derived,
            pipe_name_for(Path::new(r"C:\Temp\runner-test-1\runner.sock"))
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_has_owner_only_permissions() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_support::TempDir::new("ipc-perm").unwrap();
        let path = dir.path().join("runner.sock");
        let server = IpcServer::bind(&path, new_shared_state()).await.unwrap();
        let mode = std::fs::metadata(server.path()).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Socket override: explicit paths win, blanks fall through
    // (previous value restored — env is process-global).
    #[test]
    fn sock_override_respects_explicit_paths_only() {
        let prior = std::env::var("RUNNER_SOCK").ok();
        std::env::set_var("RUNNER_SOCK", "  /tmp/hermetic.sock  ");
        assert_eq!(sock_override(), Some(PathBuf::from("/tmp/hermetic.sock")));
        assert_eq!(resolve_sock_path(), PathBuf::from("/tmp/hermetic.sock"));
        std::env::set_var("RUNNER_SOCK", "   ");
        assert_eq!(sock_override(), None);
        match prior {
            Some(value) => std::env::set_var("RUNNER_SOCK", value),
            None => std::env::remove_var("RUNNER_SOCK"),
        }
    }

    fn cloud_req(method: &str, params: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    #[tokio::test]
    async fn swarm_list_and_kill_roundtrip() {
        use crate::mcp::swarm;
        use std::time::Instant;

        let state = new_shared_state();
        // Empty table lists clean.
        let res = handle_ipc_request(cloud_req("swarm_list", serde_json::json!({})), &state).await;
        assert_eq!(res["result"]["swarms"].as_array().unwrap().len(), 0);
        // Seed two sessions through the protocol (one drained).
        {
            let mut guard = state.write().await;
            let now = Instant::now();
            swarm::register_agent(guard.swarms_mut(), "beta", "a", "builder", 0, now).unwrap();
            swarm::register_agent(guard.swarms_mut(), "alpha", "b", "tester", 0, now).unwrap();
            swarm::transition_swarm_status(
                guard.swarms_mut(),
                "beta",
                swarm::SwarmStatus::Draining,
                now,
            )
            .unwrap();
        }
        let res = handle_ipc_request(cloud_req("swarm_list", serde_json::json!({})), &state).await;
        let swarms = res["result"]["swarms"].as_array().unwrap();
        assert_eq!(swarms.len(), 2);
        assert_eq!(swarms[0]["swarm_id"], "alpha");
        assert_eq!(swarms[0]["status"], "active");
        assert_eq!(swarms[0]["member_count"], 1);
        assert_eq!(swarms[1]["status"], "draining");
        // Kill reclaims and reports; unknown ids fail closed.
        let res = handle_ipc_request(
            cloud_req("swarm_kill", serde_json::json!({ "swarm_id": "alpha" })),
            &state,
        )
        .await;
        assert_eq!(res["result"]["status"], "terminated");
        assert_eq!(res["result"]["slices_reclaimed"], 1);
        let res = handle_ipc_request(
            cloud_req("swarm_kill", serde_json::json!({ "swarm_id": "ghost" })),
            &state,
        )
        .await;
        assert_eq!(res["error"]["code"], -32602);
        let res = handle_ipc_request(
            cloud_req("swarm_kill", serde_json::json!({ "swarm_id": "  " })),
            &state,
        )
        .await;
        assert_eq!(res["error"]["code"], -32602);
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
    async fn cache_peers_reports_table_snapshot() {
        use crate::cache::server::{CacheServerState, MdnsPeerResolver};
        use crate::mesh::discovery::{DiscoveredNode, LanMetrics, MdnsCachePeerTable};
        use std::time::Instant;

        let state = new_shared_state();
        // No cache attached: honest error, not an empty list.
        let res = handle_ipc_request(cloud_req("cache_peers", serde_json::json!({})), &state).await;
        assert_eq!(res["error"]["code"], -32603);

        let dir = crate::test_support::TempDir::new("ipc-peers").unwrap();
        let store = crate::cache::store::CacheStore::open(&dir.path().join("c"), 1 << 30).unwrap();
        let table = MdnsCachePeerTable::new();
        table.register_heartbeat(
            DiscoveredNode {
                instance: "node-a._runner._tcp.local.".to_string(),
                host: "node-a.local".to_string(),
                port: 9535,
                addrs: vec!["10.0.0.2".parse().unwrap()],
                metrics: Some(LanMetrics {
                    cores: 8,
                    ram_mb: 16384,
                    slots: 4,
                    cache_port: Some(8787),
                    cache_enabled: true,
                    node_id: "node-a".to_string(),
                    cache_token: "tok".to_string(),
                }),
            },
            Instant::now(),
        );
        // Legacy row: listed with blanks, not dropped.
        table.register_heartbeat(
            DiscoveredNode {
                instance: "legacy._runner._tcp.local.".to_string(),
                host: "legacy.local".to_string(),
                port: 9535,
                addrs: vec![],
                metrics: None,
            },
            Instant::now(),
        );
        let mut server_state = CacheServerState::new(store, "http://127.0.0.1:8787".to_string());
        server_state.peers = std::sync::Arc::new(MdnsPeerResolver::with_table(table));
        state.write().await.set_cache(server_state);
        let res = handle_ipc_request(cloud_req("cache_peers", serde_json::json!({})), &state).await;
        let peers = res["result"]["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
        let active = peers.iter().find(|p| p["node_id"] == "node-a").unwrap();
        assert_eq!(active["base_url"], "http://10.0.0.2:8787");
        assert_eq!(active["port"], 8787);
        assert_eq!(active["cache_enabled"], true);
        assert!(active["last_seen_secs"].as_u64().unwrap() < 5);
        let legacy = peers
            .iter()
            .find(|p| p["node_id"] == "legacy._runner._tcp.local.")
            .unwrap();
        assert_eq!(legacy["base_url"], "");
        assert!(legacy["port"].is_null());
        assert_eq!(legacy["cache_enabled"], false);
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

    #[tokio::test]
    async fn reserve_arm_bills_and_denies_over_budget() {
        use crate::mcp::reservation::ScriptHooks;
        let state = new_shared_state();
        let hooks = std::sync::Arc::new(ScriptHooks::default());
        state.write().await.set_reservation_hooks(hooks.clone());
        let params = serde_json::json!({
            "cores": 2.0, "memory_mb": 1024, "duration_secs": 60,
        });
        let res = handle_ipc_request(cloud_req("reserve", params.clone()), &state).await;
        let id = res["result"]["reservation_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            hooks.calls.lock().unwrap().clone(),
            vec!["budget".to_string(), format!("grant:{id}")]
        );
        *hooks.deny_budget_with.lock().unwrap() = Some("cap hit".to_string());
        let res = handle_ipc_request(cloud_req("reserve", params), &state).await;
        assert_eq!(res["error"]["code"], -32603);
        assert!(
            res["error"]["message"]
                .as_str()
                .unwrap()
                .contains("cap hit"),
            "{res}"
        );
    }
}
