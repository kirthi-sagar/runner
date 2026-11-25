//! Dashboard console tests: SSE metrics emission and role
//! gating over loopback TCP (no external network).

use runner::control_plane::auth::{Role, SessionStore};
use runner::control_plane::fleet::FleetRegistry;
use runner::control_plane::server::{serve_on, AppState};
use std::sync::Arc;
use std::time::Duration;

/// Spawn the app on an ephemeral loopback port; returns the base
/// URL plus the session store handle for minting test sessions.
async fn spawn_dashboard(
    local_token: Option<String>,
    ttl: Duration,
) -> (String, Arc<SessionStore>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = AppState::new(
        FleetRegistry::new(),
        SessionStore::new(ttl),
        None,
        local_token,
    );
    let sessions = state.sessions.clone();
    tokio::spawn(async move { serve_on(listener, state).await });
    // Wait for readiness.
    for _ in 0..50 {
        if reqwest::get(format!("{base}/health")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (base, sessions)
}

/// Read the first SSE event payload, accumulating wire chunks
/// until the event terminator (bounded wait, never hangs CI).
/// Borrows the response so callers can keep reading after it.
async fn read_first_event(response: &mut reqwest::Response) -> serde_json::Value {
    let mut buf = Vec::new();
    let read = async {
        for _ in 0..32 {
            let Some(chunk) = response.chunk().await.unwrap() else {
                break;
            };
            buf.extend_from_slice(&chunk);
            if buf.windows(2).any(|window| window == b"\n\n") {
                break;
            }
        }
        buf
    };
    let buf = tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("first SSE event");
    let text = String::from_utf8(buf).expect("utf8 event");
    let line = text
        .lines()
        .find(|line| line.starts_with("data: "))
        .expect("data line");
    serde_json::from_str(line.trim_start_matches("data: ")).expect("json event")
}

#[tokio::test]
async fn stream_rejects_missing_and_unknown_bearers() {
    let (base, _) = spawn_dashboard(None, Duration::from_secs(60)).await;
    let http = reqwest::Client::new();
    let res = http
        .get(format!("{base}/api/v1/stream"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let res = http
        .get(format!("{base}/api/v1/stream"))
        .bearer_auth("bogus")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stream_serves_every_role_with_shaped_events() {
    let (base, sessions) = spawn_dashboard(None, Duration::from_secs(60)).await;
    let http = reqwest::Client::new();
    // Viewers observe: the lowest role streams 200 with shape.
    let viewer = sessions.create(Some("v@x.y".to_string()), vec![]).await;
    assert_eq!(viewer.role, Role::Viewer);
    let mut res = http
        .get(format!("{base}/api/v1/stream"))
        .bearer_auth(&viewer.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").unwrap().to_str().unwrap(),
        "text/event-stream"
    );
    let event = read_first_event(&mut res).await;
    for key in ["ts_secs", "psi", "governor", "jobs", "oci_cache", "swarms"] {
        assert!(event.get(key).is_some(), "missing {key}");
    }
    assert!(event["ts_secs"].as_u64().unwrap() > 0);
    assert!(event["oci_cache"]["images"].as_u64().is_some());

    // Operators and admins stream too.
    for (groups, role) in [
        (vec!["ops".to_string()], Role::Operator),
        (vec!["admins".to_string()], Role::Admin),
    ] {
        let session = sessions.create(Some("x@x.y".to_string()), groups).await;
        assert_eq!(session.role, role);
        let mut res = http
            .get(format!("{base}/api/v1/stream"))
            .bearer_auth(&session.token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
        let event = read_first_event(&mut res).await;
        assert!(event.get("ts_secs").is_some());
    }
}

#[tokio::test]
async fn stream_ends_when_session_lapses() {
    let (base, sessions) = spawn_dashboard(None, Duration::from_millis(150)).await;
    let http = reqwest::Client::new();
    let session = sessions.create(Some("e@x.y".to_string()), vec![]).await;
    let mut res = http
        .get(format!("{base}/api/v1/stream"))
        .bearer_auth(&session.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    // The first tick fires immediately on the live grant.
    let event = read_first_event(&mut res).await;
    assert!(event.get("ts_secs").is_some());
    // The grant lapses at 150ms, so the 500ms tick ends the
    // stream instead of emitting (bounded wait, never hangs).
    let rest = tokio::time::timeout(Duration::from_secs(10), async {
        while res.chunk().await.unwrap().is_some() {}
    })
    .await;
    assert!(rest.is_ok(), "stream did not end after lapse");
}

#[tokio::test]
async fn stream_accepts_local_console_token_as_admin() {
    let (base, _) =
        spawn_dashboard(Some("console-secret".to_string()), Duration::from_secs(60)).await;
    let http = reqwest::Client::new();
    let mut res = http
        .get(format!("{base}/api/v1/stream"))
        .bearer_auth("console-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let event = read_first_event(&mut res).await;
    assert!(event.get("governor").is_some());
    // A wrong token is still rejected when a local token exists.
    let res = http
        .get(format!("{base}/api/v1/stream"))
        .bearer_auth("wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
}
