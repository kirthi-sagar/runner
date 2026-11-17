//! Startup orphan reconciliation: loopback API doubles prove
//! `reconcile_active_nodes` discovers live `runner-ci-*` droplets and
//! workers (filtering foreign/suspended/wrong-type rows), parses launch
//! times, ledger-records launches idempotently, and populates daemon
//! state without duplicates. Stub harness follows the
//! `test_cloud_lifecycle.rs` scripted-route precedent.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runner::governor::supervisor::new_shared_state;
use runner::mesh::cloud::digitalocean::DoClient;
use runner::mesh::cloud::render::RenderClient;
use runner::mesh::cloud::CloudPool;
use runner_cli::coordinator::reconcile_into_state;

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

fn droplet_stub() -> (String, Arc<Mutex<Vec<String>>>) {
    serve_scripted(
        vec![Route {
            method: "GET",
            path: "/v2/droplets",
            status: 200,
            reason: "OK",
            body: r#"{"droplets":[
                {"id":77,"name":"runner-ci-9-7","status":"active","created_at":"2026-11-17T10:00:00Z"},
                {"id":78,"name":"personal-blog","status":"active","created_at":"2026-11-01T00:00:00Z"}
            ]}"#,
        }],
        10,
    )
}

fn services_stub() -> (String, Arc<Mutex<Vec<String>>>) {
    serve_scripted(
        vec![Route {
            method: "GET",
            path: "/",
            status: 200,
            reason: "OK",
            body: r#"[
                {"service":{"id":"srv-9","name":"runner-ci-3-5","type":"background_worker","suspended":"not_suspended","createdAt":"2026-11-17T11:00:00Z"}},
                {"service":{"id":"srv-10","name":"runner-ci-1-1","type":"background_worker","suspended":"suspended","createdAt":"2026-11-17T09:00:00Z"}},
                {"service":{"id":"srv-11","name":"runner-ci-web","type":"web_service","suspended":"not_suspended"}}
            ]"#,
        }],
        10,
    )
}

/// 2026-11-17T10:00:00Z.
const NOV_17_10: u64 = 1_794_909_600;
/// 2026-11-17T11:00:00Z.
const NOV_17_11: u64 = 1_794_913_200;

#[tokio::test]
async fn reconcile_discovers_filters_and_records_launches() {
    let (do_base, do_seen) = droplet_stub();
    let (render_base, render_seen) = services_stub();
    let dir = runner::test_support::TempDir::new("reconcile").unwrap();
    let pool = CloudPool::from_clients(
        Some(DoClient::new("fake").unwrap().with_base_url(do_base)),
        Some((
            RenderClient::new("fake")
                .unwrap()
                .with_base_url(render_base),
            "owner".to_string(),
        )),
    )
    .with_ledger(runner::mesh::cloud::ledger::SpendLedger::new(
        dir.path().join("spend_ledger.json"),
    ));

    let nodes = pool.reconcile_active_nodes().await.unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].id, "77");
    assert_eq!(nodes[0].provider, "digitalocean");
    assert_eq!(nodes[0].name, "runner-ci-9-7");
    assert_eq!(nodes[0].launched_at, NOV_17_10);
    assert_eq!(nodes[1].id, "srv-9");
    assert_eq!(nodes[1].provider, "render");
    assert_eq!(nodes[1].launched_at, NOV_17_11);

    assert_eq!(
        do_seen.lock().unwrap().clone(),
        vec!["GET /v2/droplets".to_string()]
    );
    assert_eq!(
        render_seen.lock().unwrap().clone(),
        vec!["GET /".to_string()]
    );

    // Launches ledger-recorded (idempotent: rerun adds nothing).
    let text = std::fs::read_to_string(dir.path().join("spend_ledger.json")).unwrap();
    assert!(
        text.contains("\"77\"") && text.contains("srv-9"),
        "got: {text}"
    );
    let again = pool.reconcile_active_nodes().await.unwrap();
    assert_eq!(again.len(), 2);
    let text2 = std::fs::read_to_string(dir.path().join("spend_ledger.json")).unwrap();
    assert_eq!(text, text2);
}

#[tokio::test]
async fn reconcile_into_state_populates_without_duplicates() {
    let (do_base, _) = droplet_stub();
    let (render_base, _) = services_stub();
    let pool = CloudPool::from_clients(
        Some(DoClient::new("fake").unwrap().with_base_url(do_base)),
        Some((
            RenderClient::new("fake")
                .unwrap()
                .with_base_url(render_base),
            "owner".to_string(),
        )),
    );
    let state = new_shared_state();
    assert_eq!(reconcile_into_state(&pool, &state).await, 2);
    assert_eq!(state.read().await.cloud_nodes().len(), 2);
    // Second pass discovers the same nodes but tracks nothing new.
    assert_eq!(reconcile_into_state(&pool, &state).await, 0);
    assert_eq!(state.read().await.cloud_nodes().len(), 2);
}
