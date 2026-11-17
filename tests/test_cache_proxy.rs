//! LAN cache proxy protocol tests: full reserve → chunk → commit →
//! lookup → download round-trips over live loopback HTTP, plus miss,
//! conflict, size-mismatch, range, auth, and restore-key behaviors.

use runner::cache::server::{public_base_url, serve_on, CacheServerState, CACHE_RUNTIME_TOKEN};
use runner::cache::store::CacheStore;
use std::time::Duration;

/// Spawn the proxy on an ephemeral loopback port; returns (base URL, store).
async fn spawn_proxy() -> (String, CacheStore) {
    let dir = runner::test_support::TempDir::new("cache-proxy").unwrap();
    // Leak the dir: the server task outlives this fn but the process
    // owns cleanup (TempDir drops at process exit via leaked Box).
    let dir: &'static _ = Box::leak(Box::new(dir));
    let store = CacheStore::open(&dir.path().join("cache"), 1 << 30).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let state = CacheServerState {
        store: store.clone(),
        public_base: public_base_url("127.0.0.1:8787", port),
    };
    tokio::spawn(async move { serve_on(listener, state).await });
    // Wait for readiness (miss probe doubles as a warmup).
    let http = reqwest::Client::new();
    for _ in 0..50 {
        let res = http
            .get(format!(
                "{base}/_apis/artifactcache/cache?keys=warm&version=v"
            ))
            .header("authorization", format!("Bearer {CACHE_RUNTIME_TOKEN}"))
            .send()
            .await;
        if matches!(res.map(|r| r.status().as_u16()), Ok(204)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (base, store)
}

fn auth(http: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    http.header("authorization", format!("Bearer {CACHE_RUNTIME_TOKEN}"))
}

#[tokio::test]
async fn full_roundtrip_serves_identical_bytes() {
    let (base, _) = spawn_proxy().await;
    let http = reqwest::Client::new();
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();

    // Reserve.
    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches")))
        .json(&serde_json::json!({"key": "npm-abc", "version": "v1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();

    // Out-of-order chunks (concurrent-uploader order).
    for (start, end) in [(3000u64, 4999u64), (0, 2999)] {
        let res = auth(http.patch(format!("{base}/_apis/artifactcache/caches/{id}")))
            .header("content-range", format!("bytes {start}-{end}/*"))
            .body(payload[start as usize..=end as usize].to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);
    }

    // Commit + duplicate reserve conflicts.
    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches/{id}")))
        .json(&serde_json::json!({"size": 5000}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches")))
        .json(&serde_json::json!({"key": "npm-abc", "version": "v1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 409);

    // Lookup hit carries a working archiveLocation.
    let res = auth(http.get(format!(
        "{base}/_apis/artifactcache/cache?keys=npm-abc&version=v1"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let hit: serde_json::Value = res.json().await.unwrap();
    assert_eq!(hit["cacheKey"], "npm-abc");
    let location = hit["archiveLocation"].as_str().unwrap().to_string();
    assert!(location.contains("/_apis/artifactcache/artifacts/"));

    // Plain download (no auth, like the real client) is byte-identical.
    let res = http.get(&location).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["content-length"], "5000");
    assert_eq!(res.bytes().await.unwrap().as_ref(), payload.as_slice());

    // HEAD + Range support for concurrent downloaders.
    let res = http.head(&location).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.headers()["content-length"], "5000");
    let res = http
        .get(&location)
        .header("range", "bytes=100-199")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 206);
    assert_eq!(res.bytes().await.unwrap().as_ref(), &payload[100..200]);
    let res = http
        .get(&location)
        .header("range", "bytes=9999-10099")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 416);
}

#[tokio::test]
async fn misses_restore_prefixes_auth_and_size_mismatch() {
    let (base, _) = spawn_proxy().await;
    let http = reqwest::Client::new();

    // Miss.
    let res = auth(http.get(format!("{base}/_apis/artifactcache/cache?keys=k&version=v")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 204);

    // Seed two entries sharing a prefix.
    for key in ["npm-aaa", "npm-bbb"] {
        let res = auth(http.post(format!("{base}/_apis/artifactcache/caches")))
            .json(&serde_json::json!({"key": key, "version": "v"}))
            .send()
            .await
            .unwrap();
        let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
            .as_u64()
            .unwrap();
        auth(http.patch(format!("{base}/_apis/artifactcache/caches/{id}")))
            .header("content-range", "bytes 0-2/*")
            .body(b"xyz".to_vec())
            .send()
            .await
            .unwrap();
        auth(http.post(format!("{base}/_apis/artifactcache/caches/{id}")))
            .json(&serde_json::json!({"size": 3}))
            .send()
            .await
            .unwrap();
    }
    // Primary exact hit wins over restore prefixes.
    let res = auth(http.get(format!(
        "{base}/_apis/artifactcache/cache?keys=npm-aaa,npm-&version=v"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        res.json::<serde_json::Value>().await.unwrap()["cacheKey"],
        "npm-aaa"
    );
    // Restore prefix falls back in order (most-recently-used wins ties).
    let res = auth(http.get(format!(
        "{base}/_apis/artifactcache/cache?keys=zzz,npm-&version=v"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);

    // Auth enforced off the download path.
    let res = http
        .get(format!("{base}/_apis/artifactcache/cache?keys=k&version=v"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
    let res = http
        .post(format!("{base}/_apis/artifactcache/caches"))
        .json(&serde_json::json!({"key": "k", "version": "v"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);

    // Declared-size mismatch refuses commit.
    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches")))
        .json(&serde_json::json!({"key": "short", "version": "v"}))
        .send()
        .await
        .unwrap();
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();
    auth(http.patch(format!("{base}/_apis/artifactcache/caches/{id}")))
        .header("content-range", "bytes 0-2/*")
        .body(b"xyz".to_vec())
        .send()
        .await
        .unwrap();
    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches/{id}")))
        .json(&serde_json::json!({"size": 99}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 400);

    // Unknown ids 404.
    let res = auth(http.patch(format!("{base}/_apis/artifactcache/caches/424242")))
        .header("content-range", "bytes 0-0/*")
        .body(b"x".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
    let res = http
        .get(format!("{base}/_apis/artifactcache/artifacts/424242"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
}

#[tokio::test]
async fn large_archive_streams_end_to_end() {
    let (base, store) = spawn_proxy().await;
    let http = reqwest::Client::new();
    // 20 MiB deterministic payload, uploaded in 4 MiB chunks.
    const SIZE: usize = 20 * 1024 * 1024;
    let payload: Vec<u8> = (0..SIZE as u32).map(|i| (i % 251) as u8).collect();

    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches")))
        .json(&serde_json::json!({"key": "big-blob", "version": "v1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 201);
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();
    for (n, chunk) in payload.chunks(4 * 1024 * 1024).enumerate() {
        let start = n * 4 * 1024 * 1024;
        let end = start + chunk.len() - 1;
        let res = auth(http.patch(format!("{base}/_apis/artifactcache/caches/{id}")))
            .header("content-range", format!("bytes {start}-{end}/*"))
            .body(chunk.to_vec())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200);
    }
    let res = auth(http.post(format!("{base}/_apis/artifactcache/caches/{id}")))
        .json(&serde_json::json!({"size": SIZE}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);

    // Full streamed download is byte-identical.
    let res = http
        .get(format!("{base}/_apis/artifactcache/artifacts/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.bytes().await.unwrap().as_ref(), payload.as_slice());

    // Mid-file range slice.
    let res = http
        .get(format!("{base}/_apis/artifactcache/artifacts/{id}"))
        .header("range", "bytes=1048576-2097151")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 206);
    assert_eq!(
        res.bytes().await.unwrap().as_ref(),
        &payload[1048576..2097152]
    );

    // Served counters reflect both downloads.
    let stats = store.stats();
    assert_eq!(stats.bytes_served, (SIZE + 1024 * 1024) as u64);
}
