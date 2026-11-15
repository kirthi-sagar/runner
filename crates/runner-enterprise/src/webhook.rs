//! Instant webhook listener: HMAC-verified CI events wake the
//! coordinator without waiting for the next poll cycle.
//!
//! Pure axum + tokio: takes only a port, a secret, and a shared
//! [`Notify`], so community and enterprise editions reuse it without
//! new crate dependencies. Refuses to bind without a secret.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use tokio::sync::Notify;

#[derive(Clone)]
struct WebhookState {
    secret: Vec<u8>,
    notify: Arc<Notify>,
}

/// Decode lowercase/uppercase hex into bytes.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push(hi << 4 | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify the request signature. GitHub sends
/// `X-Hub-Signature-256: sha256=<hex>` (HMAC-SHA256, constant-time);
/// GitLab sends the raw secret in `X-Gitlab-Token` (constant-time
/// compare). Missing/unparseable auth is rejected.
pub fn verify_signature(secret: &[u8], headers: &HeaderMap, body: &[u8]) -> Result<(), StatusCode> {
    if let Some(value) = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
    {
        let hex = value.strip_prefix("sha256=").unwrap_or("");
        let Some(expected) = hex_decode(hex) else {
            return Err(StatusCode::FORBIDDEN);
        };
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        mac.update(body);
        return mac
            .verify_slice(&expected)
            .map_err(|_| StatusCode::FORBIDDEN)
            .map(|_| ());
    }
    if let Some(token) = headers.get("x-gitlab-token").map(|v| v.as_bytes()) {
        if !secret.is_empty() && constant_time_eq(token, secret) {
            return Ok(());
        }
        return Err(StatusCode::FORBIDDEN);
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// True for queue-worthy events: GitHub `workflow_job` + `queued` action,
/// or a GitLab build hook (`object_kind == "build"`) still early enough
/// to dispatch (`created` / `pending`). Everything else is ignored.
pub fn is_dispatch_event(headers: &HeaderMap, payload: &serde_json::Value) -> bool {
    let github_event = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if github_event == "workflow_job" {
        return payload.get("action").and_then(|a| a.as_str()) == Some("queued");
    }
    if payload.get("object_kind").and_then(|k| k.as_str()) == Some("build") {
        let status = payload
            .get("build_status")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        return matches!(status, "created" | "pending");
    }
    false
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Err(status) = verify_signature(&state.secret, &headers, &body) {
        return (status, "bad signature").into_response();
    }
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
    };
    if is_dispatch_event(&headers, &payload) {
        eprintln!("runner: webhook dispatch event: waking coordinator");
        state.notify.notify_one();
        (StatusCode::ACCEPTED, "dispatch woken").into_response()
    } else {
        (StatusCode::OK, "ignored").into_response()
    }
}

fn router(secret: Vec<u8>, notify: Arc<Notify>) -> axum::Router {
    axum::Router::new()
        .route("/health", get(health))
        .route("/webhook", post(webhook))
        .with_state(WebhookState { secret, notify })
}

/// Serve the listener on 127.0.0.1:`port` until the future is dropped.
/// Fails closed: empty secrets refuse to bind.
pub async fn serve(port: u16, secret: String, notify: Arc<Notify>) -> anyhow::Result<()> {
    if secret.trim().is_empty() {
        anyhow::bail!("refusing to listen without a webhook secret");
    }
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("runner: webhook listener on 127.0.0.1:{port}");
    axum::serve(listener, router(secret.as_bytes().to_vec(), notify)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "topsecret";

    fn github_headers(body: &[u8]) -> HeaderMap {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(body);
        let sig: Vec<u8> = mac.finalize().into_bytes().to_vec();
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-hub-signature-256",
            format!("sha256={hex}").parse().unwrap(),
        );
        headers.insert("x-github-event", "workflow_job".parse().unwrap());
        headers
    }

    #[test]
    fn github_signature_round_trip() {
        let body = br#"{"action":"queued"}"#;
        let headers = github_headers(body);
        assert!(verify_signature(SECRET.as_bytes(), &headers, body).is_ok());
        // Tampered body fails.
        assert!(verify_signature(SECRET.as_bytes(), &headers, b"{}").is_err());
        // Wrong secret fails.
        assert!(verify_signature(b"nope", &headers, body).is_err());
        // Missing auth is 401.
        assert_eq!(
            verify_signature(SECRET.as_bytes(), &HeaderMap::new(), body),
            Err(StatusCode::UNAUTHORIZED)
        );
        // Malformed signature is 403.
        let mut bad = HeaderMap::new();
        bad.insert("x-hub-signature-256", "sha256=zz".parse().unwrap());
        assert_eq!(
            verify_signature(SECRET.as_bytes(), &bad, body),
            Err(StatusCode::FORBIDDEN)
        );
    }

    #[test]
    fn gitlab_token_compare() {
        let mut headers = HeaderMap::new();
        headers.insert("x-gitlab-token", SECRET.parse().unwrap());
        assert!(verify_signature(SECRET.as_bytes(), &headers, b"{}").is_ok());
        let mut wrong = HeaderMap::new();
        wrong.insert("x-gitlab-token", "wrong".parse().unwrap());
        assert!(verify_signature(SECRET.as_bytes(), &wrong, b"{}").is_err());
    }

    #[test]
    fn dispatch_events_filtered() {
        let headers = github_headers(br#"{"action":"queued"}"#);
        assert!(is_dispatch_event(
            &headers,
            &serde_json::json!({"action": "queued"})
        ));
        assert!(!is_dispatch_event(
            &headers,
            &serde_json::json!({"action": "completed"})
        ));
        let empty = HeaderMap::new();
        assert!(is_dispatch_event(
            &empty,
            &serde_json::json!({"object_kind": "build", "build_status": "pending"})
        ));
        assert!(!is_dispatch_event(
            &empty,
            &serde_json::json!({"object_kind": "build", "build_status": "success"})
        ));
        assert!(!is_dispatch_event(
            &empty,
            &serde_json::json!({"object_kind": "push"})
        ));
    }

    #[tokio::test]
    async fn live_loopback_accepts_signed_queued_event() {
        let notify = Arc::new(Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(SECRET.as_bytes().to_vec(), notify))
                .await
                .ok();
        });
        let body = serde_json::json!({"action": "queued"});
        let raw = serde_json::to_vec(&body).unwrap();
        let headers = github_headers(&raw);
        let client = reqwest::Client::new();
        let res = client
            .post(format!("http://127.0.0.1:{port}/webhook"))
            .header(
                "x-hub-signature-256",
                headers["x-hub-signature-256"].clone(),
            )
            .header("x-github-event", "workflow_job")
            .body(raw)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::ACCEPTED);
        let res = client
            .post(format!("http://127.0.0.1:{port}/webhook"))
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
        server.abort();
    }

    #[tokio::test]
    async fn empty_secret_refuses_to_bind() {
        assert!(serve(0, String::new(), Arc::new(Notify::new()))
            .await
            .is_err());
        assert!(serve(0, "   ".to_string(), Arc::new(Notify::new()))
            .await
            .is_err());
    }
}
