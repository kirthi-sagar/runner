//! Embedded Axum control plane: fleet API + OIDC login.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};

use super::auth::{OidcManager, SessionStore};
use super::fleet::{FleetRegistry, HeartbeatPayload, RunnerRegistration};

/// Shared server state (cloneable handle).
#[derive(Clone)]
pub struct AppState {
    pub fleet: Arc<FleetRegistry>,
    pub sessions: Arc<SessionStore>,
    pub oidc: Option<Arc<OidcManager>>,
}

impl AppState {
    pub fn new(fleet: FleetRegistry, sessions: SessionStore, oidc: Option<OidcManager>) -> Self {
        Self {
            fleet: Arc::new(fleet),
            sessions: Arc::new(sessions),
            oidc: oidc.map(Arc::new),
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
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "psi": psi,
        "governor": governor,
        "cloud_nodes_active": cloud_nodes_active,
        "cloud_spend_usd": cloud_spend_usd,
    }))
}

/// Daemon cloud stats over the local IPC socket: active node count +
/// ledgered month spend (both `None` when unreachable).
async fn cloud_stats() -> (Option<usize>, Option<f64>) {
    let sock = runner_core::ipc::resolve_sock_path();
    let Ok(res) = runner_core::ipc::ipc_call(&sock, "cloud_list").await else {
        return (None, None);
    };
    if res.get("error").is_some() {
        return (None, None);
    }
    let Some(result) = res.get("result") else {
        return (None, None);
    };
    let count = result
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| nodes.len());
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
        Json(serde_json::json!({ "token": session.token, "email": session.email })),
    )
        .into_response()
}

/// Build the router (pure constructor; integration-tested over TCP).
pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/", get(dashboard))
        .route("/dashboard", get(dashboard))
        .route("/health", get(health))
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
