//! Mock cloud lifecycle: scripted loopback API doubles prove the full
//! `provision -> watchdog poll -> terminate` cycle per provider with
//! zero credentials. Follows the `test_stub` one-shot precedent
//! (std-only), extended to multi-route scripts with request logs.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use runner::governor::supervisor::new_shared_state;
use runner::mesh::cloud::digitalocean::DoClient;
use runner::mesh::cloud::render::RenderClient;
use runner::mesh::cloud::CloudPool;
use runner_providers::github::webhooks::{run_watchdog_cycle, WatchdogMap};

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

#[tokio::test]
async fn digitalocean_full_lifecycle_against_mock() {
    let (base, seen) = serve_scripted(
        vec![
            Route {
                method: "POST",
                path: "/v2/droplets",
                status: 202,
                reason: "Accepted",
                body: r#"{"droplet":{"id":99}}"#,
            },
            Route {
                method: "GET",
                path: "/v2/droplets/99/snapshots",
                status: 200,
                reason: "OK",
                body: r#"{"snapshots":[]}"#,
            },
            Route {
                method: "GET",
                path: "/v2/volumes",
                status: 200,
                reason: "OK",
                body: r#"{"volumes":[]}"#,
            },
            Route {
                method: "DELETE",
                path: "/v2/droplets/99",
                status: 204,
                reason: "No Content",
                body: "",
            },
        ],
        4,
    );
    let pool = CloudPool::from_clients(
        Some(DoClient::new("fake").unwrap().with_base_url(base)),
        None,
    );
    let node = pool.provision("digitalocean", "ci-test").await.unwrap();
    assert_eq!(node.id, "99");

    let state = new_shared_state();
    state.write().await.add_cloud_node(node);
    let mut controllers: WatchdogMap = std::collections::HashMap::new();
    let t0 = Instant::now();
    run_watchdog_cycle(&pool, &state, &mut controllers, t0, 0).await;
    assert_eq!(state.read().await.cloud_nodes().len(), 1);
    run_watchdog_cycle(
        &pool,
        &state,
        &mut controllers,
        t0 + Duration::from_secs(300),
        0,
    )
    .await;
    assert!(state.read().await.cloud_nodes().is_empty());

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "POST /v2/droplets".to_string(),
            "GET /v2/droplets/99/snapshots".to_string(),
            "GET /v2/volumes".to_string(),
            "DELETE /v2/droplets/99".to_string(),
        ]
    );
}

#[tokio::test]
async fn render_full_lifecycle_against_mock() {
    let (base, seen) = serve_scripted(
        vec![
            Route {
                method: "POST",
                path: "/v1/services",
                status: 201,
                reason: "Created",
                body: r#"{"id":"srv-1"}"#,
            },
            Route {
                method: "DELETE",
                path: "/v1/services/srv-1",
                status: 204,
                reason: "No Content",
                body: "",
            },
        ],
        2,
    );
    let services = format!("{base}/v1/services");
    let pool = CloudPool::from_clients(
        None,
        Some((
            RenderClient::new("fake").unwrap().with_base_url(services),
            "owner-1".to_string(),
        )),
    );
    let node = pool.provision("render", "ci-test").await.unwrap();
    assert_eq!(node.id, "srv-1");

    let state = new_shared_state();
    state.write().await.add_cloud_node(node);
    let mut controllers: WatchdogMap = std::collections::HashMap::new();
    let t0 = Instant::now();
    run_watchdog_cycle(&pool, &state, &mut controllers, t0, 0).await;
    assert_eq!(state.read().await.cloud_nodes().len(), 1);
    run_watchdog_cycle(
        &pool,
        &state,
        &mut controllers,
        t0 + Duration::from_secs(300),
        0,
    )
    .await;
    assert!(state.read().await.cloud_nodes().is_empty());

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "POST /v1/services".to_string(),
            "DELETE /v1/services/srv-1".to_string(),
        ]
    );
}
