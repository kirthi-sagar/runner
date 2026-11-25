//! Dashboard console tests: SSE metrics emission and role
//! gating over loopback TCP (no external network).

use runner::control_plane::auth::{Role, SessionStore};
use runner::control_plane::fleet::FleetRegistry;
use runner::control_plane::server::{serve_on, AppState};
use std::sync::Arc;
use std::time::Duration;

/// Hermetic audit trail: the guard keeps the dir alive while the
/// test holds it, so ledger writes never touch the real trail.
fn hermetic_ledger(tag: &str) -> (runner::test_support::TempDir, std::path::PathBuf) {
    let dir = runner::test_support::TempDir::new(tag).unwrap();
    let path = dir.path().join("audit.jsonl");
    (dir, path)
}

/// Spawn the app on an ephemeral loopback port; returns the base
/// URL plus the session store handle for minting test sessions.
/// Pins `RUNNER_SOCK` to a path nothing ever serves, so test
/// mutations can never reach a live production daemon (same
/// value on every call — safe under parallel tests). The audit
/// trail is always caller-owned: no test may write the default.
async fn spawn_dashboard(
    local_token: Option<String>,
    ttl: Duration,
    cache_dir: Option<std::path::PathBuf>,
    audit_log: std::path::PathBuf,
) -> (String, Arc<SessionStore>) {
    std::env::set_var(
        "RUNNER_SOCK",
        std::env::temp_dir().join("runner-test-no-daemon.sock"),
    );
    // Backstop sink: any default-trail resolution lands hermetic
    // (same value on every call — safe under parallel tests).
    std::env::set_var(
        "RUNNER_AUDIT_LOG",
        std::env::temp_dir().join("runner-test-audit-sink.jsonl"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = AppState::new(
        FleetRegistry::new(),
        SessionStore::new(ttl),
        None,
        local_token,
        cache_dir,
        Some(audit_log),
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
    let (_audit_dir, ledger) = hermetic_ledger("stream-rejects-missing-and-unknown-bearers");
    let (base, _) = spawn_dashboard(None, Duration::from_secs(60), None, ledger).await;
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
    let (_audit_dir, ledger) = hermetic_ledger("stream-serves-every-role-with-shaped-events");
    let (base, sessions) = spawn_dashboard(None, Duration::from_secs(60), None, ledger).await;
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
    let (_audit_dir, ledger) = hermetic_ledger("stream-ends-when-session-lapses");
    let (base, sessions) = spawn_dashboard(None, Duration::from_millis(150), None, ledger).await;
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
    let (_audit_dir, ledger) = hermetic_ledger("stream-accepts-local-console-token-as-admin");
    let (base, _) = spawn_dashboard(
        Some("console-secret".to_string()),
        Duration::from_secs(60),
        None,
        ledger,
    )
    .await;
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

#[tokio::test]
async fn dashboard_page_serves_single_bundle_airgapped() {
    let (_audit_dir, ledger) = hermetic_ledger("dashboard-page-serves-single-bundle-airgapped");
    let (base, _) = spawn_dashboard(None, Duration::from_secs(60), None, ledger).await;
    let page = reqwest::get(format!("{base}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    // Stream wiring contract: consumer endpoint plus every
    // element id the script binds.
    for marker in [
        "/api/v1/stream",
        "id=\"token\"",
        "id=\"stream\"",
        "id=\"g-cpu\"",
        "id=\"m-weight\"",
        "id=\"jobs\"",
        "id=\"oci-images\"",
        "id=\"swarms\"",
        "id=\"tick\"",
        "sessionStorage",
        "clearToken()",
        "id=\"role\"",
        "id=\"theme-toggle\"",
    ] {
        assert!(page.contains(marker), "missing {marker}");
    }
    // Air-gapped: no remote URLs, no external scripts.
    for banned in ["https://", "http://", "<script src", "<link href"] {
        assert!(!page.contains(banned), "leaks {banned}");
    }
}

#[tokio::test]
async fn mutations_gate_by_role_then_proxy_daemon() {
    let (_audit_dir, ledger) = hermetic_ledger("mutations-gate-by-role-then-proxy-daemon");
    let (base, sessions) = spawn_dashboard(None, Duration::from_secs(60), None, ledger).await;
    let http = reqwest::Client::new();
    let viewer = sessions.create(Some("v@x.y".to_string()), vec![]).await;
    let operator = sessions
        .create(Some("o@x.y".to_string()), vec!["ops".to_string()])
        .await;
    let admin = sessions
        .create(Some("a@x.y".to_string()), vec!["admins".to_string()])
        .await;
    // Cancel is Operator+: viewer forbidden, operator/admin
    // reach the (absent) daemon.
    let res = http
        .post(format!("{base}/api/v1/jobs/7/cancel"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let res = http
        .post(format!("{base}/api/v1/jobs/7/cancel"))
        .bearer_auth(&viewer.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    for session in [&operator, &admin] {
        let res = http
            .post(format!("{base}/api/v1/jobs/7/cancel"))
            .bearer_auth(&session.token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    }
    // Kill is Admin+: operators are forbidden too.
    for (session, want) in [
        (&viewer, reqwest::StatusCode::FORBIDDEN),
        (&operator, reqwest::StatusCode::FORBIDDEN),
        (&admin, reqwest::StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let res = http
            .post(format!("{base}/api/v1/swarms/s1/kill"))
            .bearer_auth(&session.token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want);
    }
}

#[tokio::test]
async fn prune_dry_run_reports_shape_without_deleting() {
    let (_audit_dir, ledger) = hermetic_ledger("prune-dry-run-reports-shape-without-deleting");
    let (base, sessions) = spawn_dashboard(None, Duration::from_secs(60), None, ledger).await;
    let http = reqwest::Client::new();
    let viewer = sessions.create(Some("v@x.y".to_string()), vec![]).await;
    let operator = sessions
        .create(Some("o@x.y".to_string()), vec!["ops".to_string()])
        .await;
    let res = http
        .post(format!("{base}/api/v1/cache/prune"))
        .bearer_auth(&viewer.token)
        .json(&serde_json::json!({ "dry_run": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    let res = http
        .post(format!("{base}/api/v1/cache/prune"))
        .bearer_auth(&operator.token)
        .json(&serde_json::json!({ "dry_run": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["dry_run"], true);
    for key in ["blobs_removed", "blobs_bytes", "tmps_removed", "tmps_bytes"] {
        assert!(
            body.get(key).and_then(|v| v.as_u64()).is_some(),
            "missing {key}"
        );
    }
    // A missing body fails loudly (exact code is axum's).
    let res = http
        .post(format!("{base}/api/v1/cache/prune"))
        .bearer_auth(&operator.token)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_client_error());
}

#[tokio::test]
async fn prune_real_run_removes_only_orphans_in_custom_dir() {
    use runner::sandbox::oci::cache::{ImageStore, LayerCache, StoredLayer, StoredManifest};
    let tmp = runner::test_support::TempDir::new("prune-dir").unwrap();
    let dir = tmp.path().join("layers");
    let cache = LayerCache::new(dir.clone());
    std::fs::create_dir_all(cache.dir()).unwrap();
    std::fs::write(cache.dir().join("a".repeat(64)), vec![1u8; 16]).unwrap();
    std::fs::write(cache.dir().join("b".repeat(64)), vec![2u8; 32]).unwrap();
    let store = ImageStore::new(cache.dir());
    store
        .write_manifest(
            "img:1",
            &StoredManifest {
                reference: "img:1".to_string(),
                manifest_digest: "sha256:bbbb".to_string(),
                layers: vec![StoredLayer {
                    digest: format!("sha256:{}", "a".repeat(64)),
                    size: 16,
                }],
                pulled_at_secs: 1,
            },
        )
        .unwrap();
    let (base, sessions) = spawn_dashboard(
        None,
        Duration::from_secs(60),
        Some(dir.clone()),
        tmp.path().join("audit.jsonl"),
    )
    .await;
    let http = reqwest::Client::new();
    let operator = sessions
        .create(Some("o@x.y".to_string()), vec!["ops".to_string()])
        .await;
    let res = http
        .post(format!("{base}/api/v1/cache/prune"))
        .bearer_auth(&operator.token)
        .json(&serde_json::json!({ "dry_run": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["dry_run"], false);
    assert_eq!(body["blobs_removed"], 1);
    assert_eq!(body["blobs_bytes"], 32);
    assert!(!cache.dir().join("b".repeat(64)).exists());
    assert!(cache.dir().join("a".repeat(64)).exists());
}

#[tokio::test]
async fn whoami_reports_role_and_identity() {
    let (_audit_dir, ledger) = hermetic_ledger("whoami-reports-role-and-identity");
    let (base, sessions) =
        spawn_dashboard(None, Duration::from_secs(60), None, ledger.clone()).await;
    let http = reqwest::Client::new();
    let res = http
        .get(format!("{base}/api/v1/whoami"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    for (groups, email, role) in [
        (vec![], Some("v@x.y".to_string()), "viewer"),
        (
            vec!["ops".to_string()],
            Some("o@x.y".to_string()),
            "operator",
        ),
        (vec!["admins".to_string()], None, "admin"),
    ] {
        let session = sessions.create(email.clone(), groups).await;
        let res = http
            .get(format!("{base}/api/v1/whoami"))
            .bearer_auth(&session.token)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), reqwest::StatusCode::OK);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["role"], role);
        match email {
            Some(email) => assert_eq!(body["email"], email),
            None => assert!(body["email"].is_null()),
        }
    }
    // The local console token reads as admin with no email.
    let (base, _) = spawn_dashboard(
        Some("console-secret".to_string()),
        Duration::from_secs(60),
        None,
        ledger,
    )
    .await;
    let res = http
        .get(format!("{base}/api/v1/whoami"))
        .bearer_auth("console-secret")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["role"], "admin");
    assert!(body["email"].is_null());
}

#[tokio::test]
async fn mutations_append_to_audit_trail() {
    use runner::audit::{AuditLog, LogLevel};
    let tmp = runner::test_support::TempDir::new("audit-ledger").unwrap();
    let ledger = tmp.path().join("audit.jsonl");
    let (base, sessions) =
        spawn_dashboard(None, Duration::from_secs(60), None, ledger.clone()).await;
    let http = reqwest::Client::new();
    let viewer = sessions.create(Some("v@x.y".to_string()), vec![]).await;
    let operator = sessions
        .create(Some("o@x.y".to_string()), vec!["ops".to_string()])
        .await;
    let admin = sessions
        .create(Some("a@x.y".to_string()), vec!["admins".to_string()])
        .await;
    // No daemon serves the hermetic socket: authorized attempts
    // fail loud and still record the attempt + outcome.
    let res = http
        .post(format!("{base}/api/v1/jobs/7/cancel"))
        .bearer_auth(&operator.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let res = http
        .post(format!("{base}/api/v1/swarms/s1/kill"))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let res = http
        .post(format!("{base}/api/v1/cache/prune"))
        .bearer_auth(&operator.token)
        .json(&serde_json::json!({ "dry_run": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let log = AuditLog::open(&ledger).unwrap();
    assert!(log.verify());
    assert_eq!(log.len(), 3);
    let body = std::fs::read_to_string(&ledger).unwrap();
    assert!(body.contains("cancel job '7' by o@x.y [operator]: daemon unreachable"));
    assert!(body.contains("kill swarm 's1' by a@x.y [admin]: daemon unreachable"));
    assert!(body.contains("prune cache by o@x.y [operator]: dry_run=true"));
    // Denied attempts leave no record.
    let res = http
        .post(format!("{base}/api/v1/jobs/7/cancel"))
        .bearer_auth(&viewer.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(AuditLog::open(&ledger).unwrap().len(), 3);
    // Levels type-check through the ledger schema.
    let levels: Vec<LogLevel> = body
        .lines()
        .map(|line| {
            serde_json::from_str::<runner::audit::AuditEntry>(line)
                .unwrap()
                .event
                .level
        })
        .collect();
    assert_eq!(
        levels,
        vec![LogLevel::Error, LogLevel::Error, LogLevel::Info]
    );
}

#[tokio::test]
async fn audit_attributes_emailless_sso_by_subject() {
    let (_audit_dir, ledger) = hermetic_ledger("audit-sso-subject");
    let (base, sessions) =
        spawn_dashboard(None, Duration::from_secs(60), None, ledger.clone()).await;
    let http = reqwest::Client::new();
    // No email claim: attribution falls back to the SSO subject,
    // never to the local console identity.
    let session = sessions
        .create_with_sub(None, vec!["ops".to_string()], Some("user-123".to_string()))
        .await;
    let res = http
        .post(format!("{base}/api/v1/jobs/7/cancel"))
        .bearer_auth(&session.token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = std::fs::read_to_string(&ledger).unwrap();
    assert!(body.contains("by sso:user-123 [operator]"), "{body}");
    assert!(!body.contains("local console"), "{body}");
}
