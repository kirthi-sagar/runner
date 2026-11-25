//! Embedded Axum control plane: fleet API + OIDC login.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};

use super::auth::{grant_expired, Grant, OidcManager, Role, SessionStore};
use super::fleet::{FleetRegistry, HeartbeatPayload, RunnerRegistration};

/// Shared server state (cloneable handle).
#[derive(Clone)]
pub struct AppState {
    pub fleet: Arc<FleetRegistry>,
    pub sessions: Arc<SessionStore>,
    pub oidc: Option<Arc<OidcManager>>,
    /// Pre-shared local-console bearer (grants Admin when matched).
    pub local_token: Option<String>,
}

impl AppState {
    pub fn new(
        fleet: FleetRegistry,
        sessions: SessionStore,
        oidc: Option<OidcManager>,
        local_token: Option<String>,
    ) -> Self {
        Self {
            fleet: Arc::new(fleet),
            sessions: Arc::new(sessions),
            oidc: oidc.map(Arc::new),
            local_token,
        }
    }
}

async fn health() -> impl IntoResponse {
    // PSI is best-effort: containers without /proc/pressure still
    // report healthy with null gauges.
    let snapshot = runner_core::governor::psi::read_snapshot().ok();
    let psi = snapshot.map(|s| {
        serde_json::json!({
            "cpu": s.cpu.some.avg10,
            "memory": s.memory.some.avg10,
            "io": s.io.full.avg10,
        })
    });
    let governor = snapshot.map(|s| match s.cpu_pressure() {
        runner_core::governor::psi::PressureLevel::Normal => "normal",
        runner_core::governor::psi::PressureLevel::Warning => "warning",
        runner_core::governor::psi::PressureLevel::Critical => "critical",
    });
    // Cloud stats are best-effort: the daemon owns cloud nodes, and
    // this server may run on a host without one (nulls, still healthy).
    let (cloud_nodes_active, cloud_spend_usd) = cloud_stats().await;
    let cache = cache_stats().await;
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "psi": psi,
        "governor": governor,
        "cloud_nodes_active": cloud_nodes_active,
        "cloud_spend_usd": cloud_spend_usd,
        "cache": cache,
    }))
}

/// Daemon LAN-cache stats over IPC (`None` when the daemon or the
/// cache proxy is unreachable).
async fn cache_stats() -> Option<serde_json::Value> {
    ipc_result("cache_stats").await
}

/// Daemon cloud stats over the local IPC socket: active node count +
/// ledgered month spend (both `None` when unreachable).
async fn cloud_stats() -> (Option<usize>, Option<f64>) {
    let Some(result) = ipc_result("cloud_list").await else {
        return (None, None);
    };
    let count = result
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| nodes.len());
    // A ledger error means spend is unknown, not zero.
    if result.get("spend_error").and_then(|e| e.as_str()).is_some() {
        return (count, None);
    }
    let spend = result.get("spend_usd").and_then(|s| s.as_f64());
    (count, spend)
}

/// Embedded fleet dashboard (single file, zero external assets).
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

async fn dashboard() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

async fn fleet_inventory(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({ "runners": state.fleet.active_runners().await }))
}

async fn register_runner(
    State(state): State<AppState>,
    Json(registration): Json<RunnerRegistration>,
) -> impl IntoResponse {
    if registration.runner_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "runner_id must not be empty" })),
        );
    }
    let token = state.fleet.register(registration.clone()).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({ "runner_id": registration.runner_id, "token": token })),
    )
}

async fn runner_heartbeat(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<HeartbeatPayload>,
) -> impl IntoResponse {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !state.fleet.authenticate(&payload.runner_id, token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "bad or missing bearer token" })),
        );
    }
    match state.fleet.heartbeat(&payload).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

async fn auth_login(State(state): State<AppState>) -> impl IntoResponse {
    match &state.oidc {
        Some(oidc) => {
            let oidc = oidc.clone();
            let state_token = super::auth::random_hex(16);
            let nonce = super::auth::random_hex(16);
            state.sessions.remember_state(state_token.clone()).await;
            let url = oidc.authorization_url(&state_token, &nonce);
            (
                StatusCode::FOUND,
                [(axum::http::header::LOCATION, url)],
                String::new(),
            )
                .into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "oidc not configured" })),
        )
            .into_response(),
    }
}

async fn auth_callback(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (Some(code), Some(oauth_state)) =
        (params.get("code").cloned(), params.get("state").cloned())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing code/state" })),
        )
            .into_response();
    };
    if !state.sessions.take_state(&oauth_state).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "unknown or replayed state" })),
        )
            .into_response();
    }
    let Some(oidc) = &state.oidc else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "oidc not configured" })),
        )
            .into_response();
    };
    let (id_token, _access) = match oidc.exchange_code(&code).await {
        Ok(tokens) => tokens,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };
    let claims = match oidc.verify_id_token(&id_token).await {
        Ok(claims) => claims,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response();
        }
    };
    let session = state
        .sessions
        .create(claims.email.clone(), claims.groups)
        .await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token": session.token,
            "email": session.email,
            "role": session.role,
        })),
    )
        .into_response()
}

/// Authorize one control-plane request: the pre-shared local
/// token grants a never-expiring Admin grant; otherwise a live
/// session must satisfy `min`. Missing or unknown credentials →
/// 401; a valid but under-privileged session → 403.
async fn authorize(
    headers: &axum::http::HeaderMap,
    state: &AppState,
    min: Role,
) -> Result<Grant, Box<axum::response::Response>> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    // Empty local tokens never match, so an absent bearer can
    // never equal an absent secret.
    if let Some(local) = &state.local_token {
        if !local.is_empty() && token == local {
            return Ok(Grant {
                role: Role::Admin,
                expires_at: None,
            });
        }
    }
    let session = match state.sessions.validate(token).await {
        Some(session) => session,
        None => {
            return Err(Box::new(
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": "bad or missing bearer token" })),
                )
                    .into_response(),
            ));
        }
    };
    let allowed = match min {
        Role::Viewer => true,
        Role::Operator => session.role.can_operate(),
        Role::Admin => session.role.can_admin(),
    };
    if !allowed {
        let need = match min {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        };
        return Err(Box::new(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": format!("{need} role required") })),
            )
                .into_response(),
        ));
    }
    Ok(Grant {
        role: session.role,
        expires_at: Some(session.expires_at),
    })
}

/// Daemon IPC call budget: a hung daemon degrades one source
/// to null instead of stalling the whole event.
const IPC_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// Daemon IPC result value (`None` when the daemon is
/// unreachable, slow, or reports an error).
async fn ipc_result(method: &str) -> Option<serde_json::Value> {
    let sock = runner_core::ipc::resolve_sock_path();
    let call = runner_core::ipc::ipc_call(&sock, method);
    let Ok(Ok(res)) = tokio::time::timeout(IPC_TIMEOUT, call).await else {
        return None;
    };
    if res.get("error").is_some() {
        return None;
    }
    res.get("result").cloned()
}

/// One metrics snapshot: PSI pressure, governor weights, active
/// jobs, OCI cache stats, swarm sessions. Every daemon-owned
/// source is best-effort (null when unreachable); the local OCI
/// cache always summarizes, even when empty.
async fn metrics_payload() -> serde_json::Value {
    let psi = runner_core::governor::psi::read_snapshot().ok().map(|s| {
        serde_json::json!({
            "cpu": s.cpu.some.avg10,
            "memory": s.memory.some.avg10,
            "io": s.io.full.avg10,
        })
    });
    let snapshot = ipc_result("snapshot").await;
    let governor = snapshot.as_ref().map(|s| {
        serde_json::json!({
            "weight": s.get("weight"),
            "slots": s.get("slots"),
            "in_flight": s.get("in_flight"),
            "queue_depth": s.get("queue_depth"),
        })
    });
    let jobs = snapshot.as_ref().and_then(|s| s.get("jobs").cloned());
    let swarms = ipc_result("swarm_list")
        .await
        .and_then(|v| v.get("swarms").cloned());
    let oci_cache = memoized_cache_summary();
    let ts_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serde_json::json!({
        "ts_secs": ts_secs,
        "psi": psi,
        "governor": governor,
        "jobs": jobs,
        "oci_cache": {
            "images": oci_cache.images,
            "layers": oci_cache.layers,
            "present_layers": oci_cache.present_layers,
            "size_bytes": oci_cache.size_bytes,
        },
        "swarms": swarms,
    })
}

/// Metrics tick: sub-second live feel without hammering the
/// daemon IPC socket.
const METRICS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// OCI summary freshness: disk scans are shared across viewers
/// instead of repeating on every tick.
const OCI_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// Lock a poison-tolerant mutex (a panicked holder must not wedge
/// metrics for the rest of the process).
fn lock_mutex<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Memoized default-cache summary: every viewer tick reads the
/// memo and disk is scanned only once it goes stale. The guard
/// is never held across IO or await.
fn memoized_cache_summary() -> runner_sandbox::oci::cache::CacheSummary {
    use std::sync::{LazyLock, Mutex};
    type Memo = Option<(std::time::Instant, runner_sandbox::oci::cache::CacheSummary)>;
    static MEMO: LazyLock<Mutex<Memo>> = LazyLock::new(|| Mutex::new(None));
    if let Some((at, summary)) = lock_mutex(&MEMO).clone() {
        if at.elapsed() < OCI_MEMO_TTL {
            return summary;
        }
    }
    let fresh = runner_sandbox::oci::cache::cache_summary();
    *lock_mutex(&MEMO) = Some((std::time::Instant::now(), fresh.clone()));
    fresh
}

/// Real-time metrics SSE (Viewer+): one JSON event every
/// 500ms, first tick immediate. Unreachable sources surface
/// as nulls, never break the stream; a lapsed session ends it
/// (the per-run local token never lapses).
async fn metrics_stream(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let grant = match authorize(&headers, &state, Role::Viewer).await {
        Ok(grant) => grant,
        Err(response) => return *response,
    };
    let events = futures_util::stream::unfold(
        (tokio::time::interval(METRICS_INTERVAL), grant.expires_at),
        |(mut ticker, expires_at)| async move {
            // Sessions lapse mid-stream: end the stream rather
            // than serve a dead credential's metrics. Checked both
            // before and after collection, so a grant lapsing
            // during a slow tick emits nothing fresh.
            if grant_expired(expires_at, std::time::Instant::now()) {
                return None;
            }
            ticker.tick().await;
            let payload = metrics_payload().await;
            if grant_expired(expires_at, std::time::Instant::now()) {
                return None;
            }
            let event = axum::response::sse::Event::default()
                .json_data(payload)
                .unwrap_or_else(|_| axum::response::sse::Event::default().comment("encode error"));
            Some((Ok::<_, axum::Error>(event), (ticker, expires_at)))
        },
    );
    axum::response::Sse::new(events).into_response()
}

/// Build the router (pure constructor; integration-tested over TCP).
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/health", get(health))
        .route("/api/v1/stream", get(metrics_stream))
        .route("/api/v1/fleet", get(fleet_inventory))
        .route("/api/v1/runners/register", post(register_runner))
        .route("/api/v1/runners/heartbeat", post(runner_heartbeat))
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .with_state(state)
}

/// Serve on a bound listener until error.
pub async fn serve_on(listener: tokio::net::TcpListener, state: AppState) -> anyhow::Result<()> {
    axum::serve(listener, router(state)).await?;
    Ok(())
}
