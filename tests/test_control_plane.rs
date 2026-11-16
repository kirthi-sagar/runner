//! Control plane tests: fleet lifecycle, OIDC URL shape, and live
//! HTTP route assertions over loopback TCP (no external network).

use runner::control_plane::auth::{OidcConfig, OidcManager, SessionStore};
use runner::control_plane::fleet::{FleetRegistry, HeartbeatPayload, RunnerRegistration};
use runner::control_plane::server::{serve_on, AppState};
use std::time::Duration;

fn registration(id: &str) -> RunnerRegistration {
    RunnerRegistration {
        runner_id: id.to_string(),
        hostname: "node-1".to_string(),
        capacity: 4,
        supported_providers: vec!["github".to_string(), "gitlab".to_string()],
    }
}

#[tokio::test]
async fn fleet_register_heartbeat_evict() {
    let fleet = FleetRegistry::with_ttl(Duration::from_millis(60));
    fleet.register(registration("r1")).await;
    fleet
        .heartbeat(&HeartbeatPayload {
            runner_id: "r1".to_string(),
            cpu_usage: 0.4,
            psi_pressure: 18.5,
            active_jobs: 1,
        })
        .await
        .unwrap();
    let active = fleet.active_runners().await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].psi_pressure, 18.5);
    tokio::time::sleep(Duration::from_millis(90)).await;
    assert_eq!(fleet.evict_stale().await, 1);
}

#[test]
fn oidc_login_url_has_state_nonce_and_scope() {
    let oidc = OidcManager::new(OidcConfig {
        issuer_url: "https://tenant.okta.com".to_string(),
        client_id: "cid".to_string(),
        client_secret: "sec".to_string(),
        redirect_uri: "https://runner.internal/auth/callback".to_string(),
    });
    let url = oidc.authorization_url("st-1", "n-1");
    assert!(url.contains("/oauth/authorize?"));
    assert!(url.contains("state=st-1"));
    assert!(url.contains("nonce=n-1"));
    assert!(url.contains("scope=openid%20email%20profile"));
}

/// Spawn the app on an ephemeral loopback port; returns base URL.
async fn spawn_app(oidc: Option<OidcManager>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = AppState::new(
        FleetRegistry::new(),
        SessionStore::new(Duration::from_secs(60)),
        oidc,
    );
    tokio::spawn(async move { serve_on(listener, state).await });
    // Wait for readiness.
    for _ in 0..50 {
        if reqwest::get(format!("{base}/health")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    base
}

#[tokio::test]
async fn http_health_fleet_register_heartbeat() {
    let base = spawn_app(None).await;
    let http = reqwest::Client::new();

    let health: serde_json::Value = http
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "healthy");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));
    // PSI enrichment: live numbers on Linux, nulls where unreadable.
    assert!(health.get("psi").is_some());
    if health["psi"].is_object() {
        for key in ["cpu", "memory", "io"] {
            assert!(health["psi"][key].is_number(), "{key}");
        }
        assert!(health["governor"].is_string());
    } else {
        assert!(health["psi"].is_null());
    }
    // Cloud count: a live number when the test host runs a daemon,
    // null otherwise (test must pass in both environments).
    assert!(health.get("cloud_nodes_active").is_some());
    assert!(health["cloud_nodes_active"].is_u64() || health["cloud_nodes_active"].is_null());

    let registered: serde_json::Value = http
        .post(format!("{base}/api/v1/runners/register"))
        .json(&registration("r9"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(registered["runner_id"], "r9");
    let token = registered["token"].as_str().unwrap().to_string();
    assert!(!token.is_empty());

    let heartbeat = http
        .post(format!("{base}/api/v1/runners/heartbeat"))
        .bearer_auth(&token)
        .json(&HeartbeatPayload {
            runner_id: "r9".to_string(),
            cpu_usage: 0.1,
            psi_pressure: 5.0,
            active_jobs: 0,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(heartbeat.status(), 200);

    let fleet: serde_json::Value = http
        .get(format!("{base}/api/v1/fleet"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fleet["runners"].as_array().unwrap().len(), 1);

    let ghost = http
        .post(format!("{base}/api/v1/runners/heartbeat"))
        .bearer_auth("bogus")
        .json(&HeartbeatPayload {
            runner_id: "ghost".to_string(),
            cpu_usage: 0.0,
            psi_pressure: 0.0,
            active_jobs: 0,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(ghost.status(), 401);
}

#[tokio::test]
async fn auth_routes_without_oidc() {
    let base = spawn_app(None).await;
    let http = reqwest::Client::new();
    let login = http.get(format!("{base}/auth/login")).send().await.unwrap();
    assert_eq!(login.status(), 503);
    let callback = http
        .get(format!("{base}/auth/callback"))
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), 400);
}

#[tokio::test]
async fn dashboard_routes_serve_embedded_html() {
    let base = spawn_app(None).await;
    let http = reqwest::Client::new();
    for path in ["/", "/dashboard"] {
        let res = http.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );
        let body = res.text().await.unwrap();
        assert!(
            body.contains("<title>runner fleet dashboard</title>"),
            "{path}"
        );
        // Zero external assets: no CDN, fonts, or script URLs.
        assert!(!body.contains("https://"), "{path}");
        assert!(!body.contains("http://"), "{path}");
        // Cloud badge mount point + live binding.
        assert!(body.contains("id=\"cloud\""), "{path}");
        assert!(body.contains("cloud_nodes_active"), "{path}");
    }
}
