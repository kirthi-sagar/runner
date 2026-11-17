//! Multi-forge daemon wiring: loopback API doubles prove the GitLab
//! and Bitbucket coordinator iterations poll → claim → sandbox-execute →
//! stream logs → report completion with zero credentials, and that the
//! daemon supervises forges without GitHub configured. Stub harness
//! follows the `test_cloud_lifecycle.rs` scripted-route precedent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner::config::RunnerConfig;
use runner::governor::supervisor::{new_shared_state, SharedState};
use runner_cli::coordinator::{enabled_forges, resolve_tokens, spawn_coordinator, Forge};
use runner_providers::providers::bitbucket::{poll_bitbucket_once, BitbucketProvider};
use runner_providers::providers::gitlab::{poll_gitlab_once, GitlabProvider};

struct Route {
    method: &'static str,
    path: &'static str,
    status: u16,
    reason: &'static str,
    body: &'static str,
}

/// Serve `expect` requests, routing by (method, path prefix without
/// query), recording `METHOD path` per hit. Unknown routes get 404.
fn serve_scripted(routes: Vec<Route>, expect: usize) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("stub bind");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_thread = seen.clone();
    std::thread::spawn(move || {
        for _ in 0..expect {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut buf = [0u8; 65536];
            let mut data = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        data.extend_from_slice(&buf[..n]);
                        if data.windows(4).any(|w| w == b"\r\n\r\n") || data.len() >= buf.len() {
                            break;
                        }
                    }
                }
            }
            let head = String::from_utf8_lossy(&data);
            let mut parts = head.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let target = parts.next().unwrap_or("").to_string();
            let path = target.split('?').next().unwrap_or("").to_string();
            seen_thread.lock().unwrap().push(format!("{method} {path}"));
            let route = routes
                .iter()
                .find(|r| r.method == method && path.starts_with(r.path));
            let (status, reason, body) = match route {
                Some(r) => (r.status, r.reason, r.body),
                None => (404, "Not Found", "{}"),
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).ok();
        }
    });
    (base, seen)
}

/// Block until no jobs are tracked (execution task finished) or panic
/// on timeout.
async fn wait_for_idle(state: &SharedState) {
    for _ in 0..600 {
        if state.read().await.in_flight_jobs().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for forge execution to finish");
}

#[tokio::test]
async fn gitlab_poll_dispatches_executes_and_reports() {
    let (base, seen) = serve_scripted(
        vec![
            Route {
                method: "POST",
                path: "/api/v4/jobs/request",
                status: 201,
                reason: "Created",
                body: r#"{"id":9,"token":"JT","steps":[{"script":["echo forged"]}],"variables":[{"key":"CI","value":"true"}],"git_info":{"repo_url":"https://x/y.git","ref":"main"}}"#,
            },
            Route {
                method: "PATCH",
                path: "/api/v4/jobs/9/trace",
                status: 200,
                reason: "OK",
                body: "{}",
            },
            Route {
                method: "PUT",
                path: "/api/v4/jobs/9",
                status: 200,
                reason: "OK",
                body: "{}",
            },
        ],
        3,
    );
    let provider = Arc::new(GitlabProvider::new(base, "RT", vec![]));
    let state = new_shared_state();
    let dispatched = poll_gitlab_once(&provider, &state, false, Duration::from_secs(60)).await;
    assert_eq!(dispatched, 1);
    assert_eq!(state.read().await.in_flight_jobs().len(), 1);

    wait_for_idle(&state).await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            "POST /api/v4/jobs/request".to_string(),
            "PATCH /api/v4/jobs/9/trace".to_string(),
            "PUT /api/v4/jobs/9".to_string(),
        ]
    );
    let health = state.read().await.forge_health();
    assert_eq!(health["gitlab"].queue_depth, 1);
    assert!(health["gitlab"].last_error.is_none());
}

#[tokio::test]
async fn bitbucket_poll_dispatches_executes_and_reports() {
    let (base, seen) = serve_scripted(
        vec![
            Route {
                method: "POST",
                path: "/site/oauth2/token",
                status: 200,
                reason: "OK",
                body: r#"{"access_token":"tok","expires_in":3600,"token_type":"Bearer"}"#,
            },
            Route {
                method: "GET",
                path: "/2.0/repositories/w//pipelines-config/runners/u/steps",
                status: 200,
                reason: "OK",
                body: r#"{"values":[{"uuid":"s-1","script":["echo canned"],"variables":{}}]}"#,
            },
            Route {
                method: "POST",
                path: "/2.0/repositories/w//pipelines/steps/s-1/log",
                status: 200,
                reason: "OK",
                body: "{}",
            },
            Route {
                method: "PUT",
                path: "/2.0/repositories/w//pipelines/steps/s-1/status",
                status: 200,
                reason: "OK",
                body: "{}",
            },
        ],
        4,
    );
    // Empty repo_slug: checkout is skipped, keeping this hermetic (the
    // clone URL would otherwise point at the real bitbucket.org host).
    let provider =
        Arc::new(BitbucketProvider::new("id", "secret", "w", "", "u", vec![]).with_base_url(&base));
    let state = new_shared_state();
    let dispatched = poll_bitbucket_once(&provider, &state, false, Duration::from_secs(60)).await;
    assert_eq!(dispatched, 1);

    wait_for_idle(&state).await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            "POST /site/oauth2/token".to_string(),
            "GET /2.0/repositories/w//pipelines-config/runners/u/steps".to_string(),
            "POST /2.0/repositories/w//pipelines/steps/s-1/log".to_string(),
            "PUT /2.0/repositories/w//pipelines/steps/s-1/status".to_string(),
        ]
    );
    let health = state.read().await.forge_health();
    assert_eq!(health["bitbucket"].queue_depth, 1);
    assert!(health["bitbucket"].last_error.is_none());
}

#[tokio::test]
async fn spawn_coordinator_supervises_forges_without_github() {
    // No other test in this binary reads process env, so these
    // mutations are uncontended.
    std::env::remove_var("RUNNER_GITHUB_TOKEN");
    std::env::set_var("RUNNER_GITLAB_TOKEN", "env-gitlab-token");

    // Idle stub: the loop must poll it (204 = no work).
    let (base, seen) = serve_scripted(
        vec![Route {
            method: "POST",
            path: "/api/v4/jobs/request",
            status: 204,
            reason: "No Content",
            body: "",
        }],
        1,
    );
    let mut config = RunnerConfig::default();
    config.gitlab.enabled = true;
    config.gitlab.url = base;
    config.gitlab.poll_secs = 5;
    config.cloud.max_monthly_spend = 50.0;
    // NOTE: no repo_owner/repo_name and no GitHub token: a v0.4.2
    // daemon would sit in governor-only mode here.

    let tokens = resolve_tokens(&config);
    assert_eq!(tokens.gitlab.as_deref(), Some("env-gitlab-token"));
    assert_eq!(enabled_forges(&config, &tokens), vec![Forge::Gitlab]);

    let state = new_shared_state();
    spawn_coordinator(&config, state.clone()).await;
    assert!(
        state.read().await.cloud_pool().is_some(),
        "pool must attach with a forge enabled"
    );

    // The spawned loop polls no sooner than its 5s floor.
    tokio::time::sleep(Duration::from_secs(7)).await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen, vec!["POST /api/v4/jobs/request".to_string()]);
}
