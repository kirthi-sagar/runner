//! LAN cache proxy protocol tests: full reserve → chunk → commit →
//! lookup → download round-trips over live loopback HTTP, plus miss,
//! conflict, size-mismatch, range, auth, signed-URL, and restore-key
//! behaviors.

use runner::cache::server::{public_base_url, serve_on, sign_download_token, CacheServerState};
use std::time::Duration;

/// Spawn the proxy on an ephemeral loopback port with fresh per-boot
/// credentials; returns (base URL, server state handle).
async fn spawn_proxy() -> (String, CacheServerState) {
    let dir = runner::test_support::TempDir::new("cache-proxy").unwrap();
    // Leak the dir: the server task outlives this fn but the process
    // owns cleanup (TempDir drops at process exit via leaked Box).
    let dir: &'static _ = Box::leak(Box::new(dir));
    let store = runner::cache::store::CacheStore::open(&dir.path().join("cache"), 1 << 30).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let state = CacheServerState::new(store, public_base_url("127.0.0.1:8787", port));
    let served = state.clone();
    tokio::spawn(async move { serve_on(listener, served).await });
    // Wait for readiness (miss probe doubles as a warmup).
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

#[tokio::test]
async fn full_roundtrip_serves_identical_bytes() {
    let (base, state) = spawn_proxy().await;
    let token = &state.token;
    let http = reqwest::Client::new();
    let payload: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();

    // Reserve.
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches")),
        token,
    )
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
        let res = auth(
            http.patch(format!("{base}/_apis/artifactcache/caches/{id}")),
            token,
        )
        .header("content-range", format!("bytes {start}-{end}/*"))
        .body(payload[start as usize..=end as usize].to_vec())
        .send()
        .await
        .unwrap();
        assert_eq!(res.status().as_u16(), 200);
    }

    // Commit + duplicate reserve conflicts.
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .json(&serde_json::json!({"size": 5000}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches")),
        token,
    )
    .json(&serde_json::json!({"key": "npm-abc", "version": "v1"}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 409);

    // Lookup hit carries a working signed archiveLocation.
    let res = auth(
        http.get(format!(
            "{base}/_apis/artifactcache/cache?keys=npm-abc&version=v1"
        )),
        token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let hit: serde_json::Value = res.json().await.unwrap();
    assert_eq!(hit["cacheKey"], "npm-abc");
    let location = hit["archiveLocation"].as_str().unwrap().to_string();
    assert!(location.contains("/_apis/artifactcache/artifacts/"));
    assert!(
        location.contains("?token="),
        "signed capability: {location}"
    );

    // Signed download (no bearer, like the real client) is byte-identical.
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

    // Unsigned, tampered, and cross-id download tokens all 401.
    let bare = format!("{base}/_apis/artifactcache/artifacts/{id}");
    let res = http.get(&bare).send().await.unwrap();
    assert_eq!(res.status().as_u16(), 401);
    let res = http
        .get(format!("{bare}?token=tampered"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
    let foreign = sign_download_token(&[9u8; 32], id).unwrap();
    let res = http
        .get(format!("{bare}?token={foreign}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
    let swapped = sign_download_token(&state.download_secret, id + 1000).unwrap();
    let res = http
        .get(format!("{bare}?token={swapped}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);
}

#[tokio::test]
async fn misses_restore_prefixes_auth_and_size_mismatch() {
    let (base, state) = spawn_proxy().await;
    let token = &state.token;
    let http = reqwest::Client::new();

    // Miss.
    let res = auth(
        http.get(format!("{base}/_apis/artifactcache/cache?keys=k&version=v")),
        token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 204);

    // Seed two entries sharing a prefix.
    for key in ["npm-aaa", "npm-bbb"] {
        let res = auth(
            http.post(format!("{base}/_apis/artifactcache/caches")),
            token,
        )
        .json(&serde_json::json!({"key": key, "version": "v"}))
        .send()
        .await
        .unwrap();
        let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
            .as_u64()
            .unwrap();
        auth(
            http.patch(format!("{base}/_apis/artifactcache/caches/{id}")),
            token,
        )
        .header("content-range", "bytes 0-2/*")
        .body(b"xyz".to_vec())
        .send()
        .await
        .unwrap();
        auth(
            http.post(format!("{base}/_apis/artifactcache/caches/{id}")),
            token,
        )
        .json(&serde_json::json!({"size": 3}))
        .send()
        .await
        .unwrap();
    }
    // Primary exact hit wins over restore prefixes.
    let res = auth(
        http.get(format!(
            "{base}/_apis/artifactcache/cache?keys=npm-aaa,npm-&version=v"
        )),
        token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        res.json::<serde_json::Value>().await.unwrap()["cacheKey"],
        "npm-aaa"
    );
    // Restore prefix falls back in order (most-recently-used wins ties).
    let res = auth(
        http.get(format!(
            "{base}/_apis/artifactcache/cache?keys=zzz,npm-&version=v"
        )),
        token,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);

    // Auth enforced on API routes; wrong bearer also 401s.
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
    let res = http
        .get(format!("{base}/_apis/artifactcache/cache?keys=k&version=v"))
        .header("authorization", "Bearer wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 401);

    // Declared-size mismatch refuses commit.
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches")),
        token,
    )
    .json(&serde_json::json!({"key": "short", "version": "v"}))
    .send()
    .await
    .unwrap();
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();
    auth(
        http.patch(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .header("content-range", "bytes 0-2/*")
    .body(b"xyz".to_vec())
    .send()
    .await
    .unwrap();
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .json(&serde_json::json!({"size": 99}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 400);

    // Unknown ids 404 (with a validly signed token for the unknown id).
    let res = auth(
        http.patch(format!("{base}/_apis/artifactcache/caches/424242")),
        token,
    )
    .header("content-range", "bytes 0-0/*")
    .body(b"x".to_vec())
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 404);
    let signed = sign_download_token(&state.download_secret, 424242).unwrap();
    let res = http
        .get(format!(
            "{base}/_apis/artifactcache/artifacts/424242?token={signed}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404);
}

#[tokio::test]
async fn large_archive_streams_end_to_end() {
    let (base, state) = spawn_proxy().await;
    let token = &state.token;
    let http = reqwest::Client::new();
    // 20 MiB deterministic payload, uploaded in 4 MiB chunks.
    const SIZE: usize = 20 * 1024 * 1024;
    let payload: Vec<u8> = (0..SIZE as u32).map(|i| (i % 251) as u8).collect();

    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches")),
        token,
    )
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
        let res = auth(
            http.patch(format!("{base}/_apis/artifactcache/caches/{id}")),
            token,
        )
        .header("content-range", format!("bytes {start}-{end}/*"))
        .body(chunk.to_vec())
        .send()
        .await
        .unwrap();
        assert_eq!(res.status().as_u16(), 200);
    }
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .json(&serde_json::json!({"size": SIZE}))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let signed = sign_download_token(&state.download_secret, id).unwrap();

    // Full streamed download is byte-identical.
    let res = http
        .get(format!(
            "{base}/_apis/artifactcache/artifacts/{id}?token={signed}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200);
    assert_eq!(res.bytes().await.unwrap().as_ref(), payload.as_slice());

    // Mid-file range slice.
    let res = http
        .get(format!(
            "{base}/_apis/artifactcache/artifacts/{id}?token={signed}"
        ))
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
    let stats = state.store.stats();
    assert_eq!(stats.bytes_served, (SIZE + 1024 * 1024) as u64);
}

#[tokio::test]
async fn oversize_chunk_is_rejected_without_buffering() {
    let (base, state) = spawn_proxy().await;
    let token = &state.token;
    let http = reqwest::Client::new();
    let res = auth(
        http.post(format!("{base}/_apis/artifactcache/caches")),
        token,
    )
    .json(&serde_json::json!({"key": "huge", "version": "v1"}))
    .send()
    .await
    .unwrap();
    let id = res.json::<serde_json::Value>().await.unwrap()["cacheId"]
        .as_u64()
        .unwrap();
    // 33 MiB single chunk: declared length trips the 32 MiB cap fast.
    let big = vec![0u8; 33 * 1024 * 1024];
    let res = auth(
        http.patch(format!("{base}/_apis/artifactcache/caches/{id}")),
        token,
    )
    .header("content-range", "bytes 0-34603007/*")
    .body(big)
    .send()
    .await
    .unwrap();
    assert_eq!(res.status().as_u16(), 413);
}
