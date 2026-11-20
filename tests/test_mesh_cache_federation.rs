//! Mesh cache federation tests: local miss → peer query → stream
//! import → local hit, across two live proxies with an injected static
//! peer resolver (no multicast on CI).

use runner::cache::server::{public_base_url, serve_on, CachePeer, CacheServerState, PeerResolver};
use std::sync::Arc;
use std::time::Duration;

/// Static peer list (manual `async_trait` expansion: integration tests
/// cannot use the macro crate, so the desugared signature is written
/// out explicitly).
struct StaticPeers {
    peers: Vec<CachePeer>,
}

impl PeerResolver for StaticPeers {
    fn cache_peers<'life0, 'async_trait>(
        &'life0 self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<CachePeer>> + Send + 'async_trait>>
    where
        Self: 'async_trait,
        'life0: 'async_trait,
    {
        let peers = self.peers.clone();
        Box::pin(async move { peers })
    }
}

/// Spawn a proxy on an ephemeral loopback port; returns (base, state).
async fn spawn_proxy_with_peers(peers: Vec<CachePeer>) -> (String, CacheServerState) {
    let dir = runner::test_support::TempDir::new("cache-federation").unwrap();
    let dir: &'static _ = Box::leak(Box::new(dir));
    let store = runner::cache::store::CacheStore::open(&dir.path().join("cache"), 1 << 30).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let mut state = CacheServerState::new(store, public_base_url("127.0.0.1:8787", port));
    state.peers = Arc::new(StaticPeers { peers });
    let served = state.clone();
    tokio::spawn(async move { serve_on(listener, served).await });
    let http = reqwest::Client::new();
    for _ in 0..50 {
        let res = http
            .get(format!(
                "{base}/_apis/artifactcache/cache?keys=warm&version=v"
            ))
            .header("authorization", format!("Bearer {}", state.token))
            .send()
            .await;
        if matches!(res.map(|r| r.status().as_u16()), Ok(204)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (base, state)
}

fn auth(http: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
    http.header("authorization", format!("Bearer {token}"))
}

/// Seed one committed archive on the given proxy; returns its id.
async fn seed_archive(http: &reqwest::Client, base: &str, token: &str) -> u64 {
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches")),
        token,
    )
    .json(&serde_json::json!({"key": "shared-blob", "version": "v1"}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();
    auth(
        http.patch(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .header("content-range", "bytes 0-7/*")
    .body(b"PEERDATA".to_vec())
    .send()
    .await
    .unwrap();
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .json(&serde_json::json!({"size": 8}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    id
}

#[tokio::test]
async fn federated_miss_imports_and_serves_peer_bytes() {
    // Node B holds the archive; node A knows B as its only peer.
    let (base_b, state_b) = spawn_proxy_with_peers(vec![]).await;
    let http = reqwest::Client::new();
    seed_archive(&http, &base_b, &state_b.token).await;

    let peer = CachePeer {
        node_id: "node-b".to_string(),
        base_url: base_b.clone(),
        token: state_b.token.clone(),
    };
    let (base_a, state_a) = spawn_proxy_with_peers(vec![peer]).await;

    // Lookup on A misses locally, federates, and serves peer bytes.
    let res = auth(
        http.get(format!(
            "{base_a}/_apis/artifactcache/cache?keys=shared-blob&version=v1"
        )),
        &state_a.token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let hit: serde_json::Value = res.json().await.unwrap();
    assert_eq!(hit["cacheKey"], "shared-blob");
    let location = hit["archiveLocation"].as_str().unwrap().to_string();
    // Served from A's own base (imported), not B's.
    assert!(location.starts_with(&base_a), "location: {location}");
    let res = http.get(&location).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.bytes().await.unwrap().as_ref(), b"PEERDATA");

    // Attribution: one federated hit + imported bytes on A.
    let stats = state_a.store.stats();
    assert_eq!(stats.remote_hits, 1);
    assert_eq!(stats.remote_bytes_imported, 8);
    assert_eq!(stats.entries, 1);

    // Second lookup is a pure local hit (no second import).
    let res = auth(
        http.get(format!(
            "{base_a}/_apis/artifactcache/cache?keys=shared-blob&version=v1"
        )),
        &state_a.token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(state_a.store.stats().remote_hits, 1);
    // Two local hits: the post-import re-resolve plus this lookup.
    assert_eq!(state_a.store.stats().hits, 2);
}

/// Seed one committed archive under a scope prefix ("" for legacy).
async fn seed_archive_under(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    prefix: &str,
    key: &str,
    payload: &[u8],
) {
    let res = auth(
        http.post(format!("{base}{prefix}/_apis/artifactcache/caches")),
        token,
    )
    .json(&serde_json::json!({"key": key, "version": "v1"}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();
    auth(
        http.patch(format!("{base}{prefix}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .header("content-range", format!("bytes 0-{}/*", payload.len() - 1))
    .body(payload.to_vec())
    .send()
    .await
    .unwrap();
    let res = auth(
        http.post(format!("{base}{prefix}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .json(&serde_json::json!({"size": payload.len()}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
}

#[tokio::test]
async fn federation_imports_only_the_requesting_scope() {
    // Node B holds the same key under two scopes with different bytes.
    let (base_b, state_b) = spawn_proxy_with_peers(vec![]).await;
    let http = reqwest::Client::new();
    seed_archive_under(
        &http,
        &base_b,
        &state_b.token,
        "/repos/acme/web",
        "lib",
        b"WEB-PEER",
    )
    .await;
    seed_archive_under(
        &http,
        &base_b,
        &state_b.token,
        "/repos/acme/api",
        "lib",
        b"API-PEER",
    )
    .await;

    let peer = CachePeer {
        node_id: "node-b".to_string(),
        base_url: base_b.clone(),
        token: state_b.token.clone(),
    };
    let (base_a, state_a) = spawn_proxy_with_peers(vec![peer]).await;

    // Scoped lookup federates and imports only that scope's bytes.
    let res = auth(
        http.get(format!(
            "{base_a}/repos/acme/web/_apis/artifactcache/cache?keys=lib&version=v1"
        )),
        &state_a.token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let hit: serde_json::Value = res.json().await.unwrap();
    let location = hit["archiveLocation"].as_str().unwrap().to_string();
    assert!(location.starts_with(&base_a), "location: {location}");
    let bytes = http
        .get(&location)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), b"WEB-PEER");
    assert_eq!(state_a.store.stats().entries, 1);

    // The twin scope imports its own bytes independently — never the
    // already-imported sibling.
    let res = auth(
        http.get(format!(
            "{base_a}/repos/acme/api/_apis/artifactcache/cache?keys=lib&version=v1"
        )),
        &state_a.token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let hit: serde_json::Value = res.json().await.unwrap();
    let location = hit["archiveLocation"].as_str().unwrap().to_string();
    let bytes = http
        .get(&location)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), b"API-PEER");
    assert_eq!(state_a.store.stats().entries, 2);
}

#[tokio::test]
async fn dead_and_empty_peers_fall_back_to_miss() {
    let dead = CachePeer {
        node_id: "dead".to_string(),
        base_url: "http://127.0.0.1:9".to_string(),
        token: "bogus".to_string(),
    };
    let (base, state) = spawn_proxy_with_peers(vec![dead]).await;
    let http = reqwest::Client::new();
    // Refused connection degrades to a local miss, fast.
    let start = std::time::Instant::now();
    let res = auth(
        http.get(format!(
            "{base}/_apis/artifactcache/cache?keys=nothing&version=v1"
        )),
        &state.token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "federation must not stall lookups"
    );

    // No peers at all: instant local miss.
    let (base, state) = spawn_proxy_with_peers(vec![]).await;
    let res = auth(
        http.get(format!(
            "{base}/_apis/artifactcache/cache?keys=nothing&version=v1"
        )),
        &state.token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 204);
    assert_eq!(state.store.stats().remote_hits, 0);
}
