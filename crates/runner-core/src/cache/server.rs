//! Actions Cache proxy server (`/_apis/artifactcache/`).
//!
//! Speaks the protocol `actions/cache` expects (verified against
//! `@actions/cache`'s `cacheHttpClient`/`downloadUtils`): lookup with
//! restore-key fallbacks, numeric-id reserve/chunk/commit upload, and
//! archive download with HEAD + Range support. Loopback-only by
//! default; Bearer auth uses a per-boot random token, and artifact
//! downloads carry HMAC-signed capability URLs (the client's
//! downloader sends no credentials, so the signed query token is the
//! gate).

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use std::collections::HashMap;

use super::store::{CacheStore, ReserveOutcome, StoreError};

/// Worker-facing cache endpoint variable.
pub const ACTIONS_CACHE_URL_ENV: &str = "ACTIONS_CACHE_URL";
/// Worker-facing cache credential variable.
pub const ACTIONS_RUNTIME_TOKEN_ENV: &str = "ACTIONS_RUNTIME_TOKEN";

/// Env pairs injected into GitHub workers when the proxy is up. The
/// URL carries exactly one trailing slash (the client appends
/// `_apis/artifactcache/...` directly).
pub fn worker_env(base_url: &str, token: &str) -> Vec<(String, String)> {
    vec![
        (
            ACTIONS_CACHE_URL_ENV.to_string(),
            format!("{}/", base_url.trim_end_matches('/')),
        ),
        (ACTIONS_RUNTIME_TOKEN_ENV.to_string(), token.to_string()),
    ]
}

/// Shared server state (cloneable handle).
#[derive(Clone)]
pub struct CacheServerState {
    pub store: CacheStore,
    /// Public base URL advertised in `archiveLocation` (loopback).
    pub public_base: String,
    /// Per-boot bearer token injected into workers (never a constant:
    /// any fixed string would be identical on every host).
    pub token: String,
    /// Per-boot HMAC secret for signed download URLs (never leaves us).
    pub download_secret: [u8; 32],
    /// Outbound HTTP client for peer federation fetches.
    pub http: reqwest::Client,
    /// Peer discovery (mDNS in production, static in tests).
    pub peers: std::sync::Arc<dyn PeerResolver>,
}

impl std::fmt::Debug for CacheServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheServerState")
            .field("store", &self.store)
            .field("public_base", &self.public_base)
            .field("token", &"<redacted>")
            .field("download_secret", &"<redacted>")
            .finish()
    }
}

impl CacheServerState {
    /// Build state with fresh per-boot credentials from the OS RNG.
    pub fn new(store: CacheStore, public_base: String) -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let mut token_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        Self {
            store,
            public_base,
            token: base64_url_no_pad(&token_bytes),
            download_secret: secret,
            http: reqwest::Client::new(),
            peers: std::sync::Arc::new(MdnsPeerResolver),
        }
    }
}

/// One LAN peer's cache endpoint (resolved from mDNS TXT + addrs).
#[derive(Debug, Clone)]
pub struct CachePeer {
    pub node_id: String,
    pub base_url: String,
    pub token: String,
}

/// Peer discovery seam: production browses mDNS, tests inject statics.
#[async_trait::async_trait]
pub trait PeerResolver: Send + Sync {
    async fn cache_peers(&self) -> Vec<CachePeer>;
}

/// Production resolver: one short mDNS browse per call (off the async
/// runtime; multicast is blocking by nature).
pub struct MdnsPeerResolver;

#[async_trait::async_trait]
impl PeerResolver for MdnsPeerResolver {
    async fn cache_peers(&self) -> Vec<CachePeer> {
        let nodes = tokio::task::spawn_blocking(|| {
            crate::mesh::discovery::LanDiscovery::browse_only(std::time::Duration::from_millis(300))
        })
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
        nodes
            .into_iter()
            .filter_map(|n| {
                let metrics = n.metrics?;
                if !metrics.cache_enabled {
                    return None;
                }
                let port = metrics.cache_port?;
                if metrics.cache_token.is_empty() {
                    return None;
                }
                let ip = n
                    .addrs
                    .iter()
                    .find(|a| !a.is_loopback() && !a.is_unspecified())?;
                Some(CachePeer {
                    node_id: if metrics.node_id.is_empty() {
                        n.instance.clone()
                    } else {
                        metrics.node_id.clone()
                    },
                    base_url: format!("http://{ip}:{port}"),
                    token: metrics.cache_token.clone(),
                })
            })
            .take(MAX_FEDERATION_PEERS)
            .collect()
    }
}

/// Cap on peers queried per local miss (bounds spoof-amplified fan-out).
pub const MAX_FEDERATION_PEERS: usize = 8;
/// Per-peer lookup timeout: federation must never stall a lookup.
pub const PEER_LOOKUP_TIMEOUT_MS: u64 = 150;

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Sign an archive id into a download capability token. `Result`
/// instead of `expect`: HMAC accepts any key length in practice, but
/// a failure must 500 the lookup, never abort the daemon.
pub fn sign_download_token(secret: &[u8; 32], id: u64) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret)
        .map_err(|e| format!("HMAC init failed: {e}"))?;
    mac.update(&id.to_be_bytes());
    Ok(base64_url_no_pad(&mac.finalize().into_bytes()))
}

/// Verify a download capability token (constant-time comparison).
pub fn verify_download_token(secret: &[u8; 32], id: u64, token: &str) -> bool {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let Ok(sig) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(&id.to_be_bytes());
    mac.verify_slice(&sig).is_ok()
}

fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| token == expected)
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "bad or missing bearer token" })),
    )
        .into_response()
}

/// `GET cache?keys=a,b&version=v` → hit JSON or 204 miss.
async fn lookup_cache(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    if !authorized(&headers, &state.token) {
        return unauthorized();
    }
    let keys: Vec<String> = params
        .get("keys")
        .map(|k| k.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let version = params.get("version").cloned().unwrap_or_default();
    if keys.is_empty() || keys.iter().any(|k| k.is_empty()) || version.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "keys and version are required" })),
        )
            .into_response();
    }
    match state.store.lookup(&version, &keys) {
        Some(entry) => lookup_hit(&state, &entry).into_response(),
        None => match federate_lookup(&state, &version, &keys).await {
            // Imported from a peer: re-resolve locally so the response
            // carries our own signed URL and a consistent hit record.
            Some(_) => match state.store.lookup(&version, &keys) {
                Some(entry) => lookup_hit(&state, &entry).into_response(),
                None => StatusCode::NO_CONTENT.into_response(),
            },
            None => StatusCode::NO_CONTENT.into_response(),
        },
    }
}

fn lookup_hit(
    state: &CacheServerState,
    entry: &super::store::CacheEntryMeta,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let token = match sign_download_token(&state.download_secret, entry.id) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("runner: cache token signing failed ({e}); failing lookup");
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    axum::Json(serde_json::json!({
        "cacheKey": entry.key,
        "archiveLocation": format!(
            "{}/_apis/artifactcache/artifacts/{}?token={}",
            state.public_base, entry.id, token
        ),
    }))
    .into_response()
}

/// LAN fallback for a local miss: query discovered cache peers in
/// order, streaming the first hit into the local store. Every failure
/// mode (timeout, HTTP error, short stream, commit mismatch) falls
/// through to the next peer and finally to a local 204. Returns the
/// imported entry's key on success.
async fn federate_lookup(
    state: &CacheServerState,
    version: &str,
    keys: &[String],
) -> Option<String> {
    for peer in state.peers.cache_peers().await {
        if let Some(key) = fetch_from_peer(state, &peer, version, keys).await {
            return Some(key);
        }
    }
    None
}

async fn fetch_from_peer(
    state: &CacheServerState,
    peer: &CachePeer,
    version: &str,
    keys: &[String],
) -> Option<String> {
    let lookup_url = format!("{}/_apis/artifactcache/cache", peer.base_url);
    let mut request = state
        .http
        .get(&lookup_url)
        .header("authorization", format!("Bearer {}", peer.token))
        .timeout(std::time::Duration::from_millis(PEER_LOOKUP_TIMEOUT_MS));
    request = request.query(&[("keys", keys.join(",")), ("version", version.to_string())]);
    let hit: serde_json::Value = request.send().await.ok()?.json().await.ok()?;
    let (key, location) = (
        hit.get("cacheKey")?.as_str()?.to_string(),
        hit.get("archiveLocation")?.as_str()?.to_string(),
    );
    let mut download = state.http.get(&location).send().await.ok()?;
    if !download.status().is_success() {
        return None;
    }
    // Lengthless responses are refused: the commit must verify an
    // exact size, never trust a truncated stream.
    let expected: u64 = download
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())?;
    let id = match state.store.reserve(&key, version) {
        Ok(ReserveOutcome::Created(id)) => id,
        // Raced locally while fetching: already have it.
        Ok(ReserveOutcome::Exists(_)) => return Some(key),
        Err(_) => return None,
    };
    // Refuse peer archives that cannot fit before streaming a byte.
    if expected > state.store.max_bytes() {
        state.store.abort_upload(id);
        return None;
    }
    let mut offset = 0u64;
    loop {
        match download.chunk().await {
            Ok(Some(bytes)) => {
                // Running guard: a lying Content-Length must not fill disk.
                if offset + bytes.len() as u64 > state.store.max_bytes() {
                    state.store.abort_upload(id);
                    return None;
                }
                if state.store.write_chunk(id, offset, &bytes).is_err() {
                    state.store.abort_upload(id);
                    return None;
                }
                offset += bytes.len() as u64;
            }
            Ok(None) => break,
            Err(_) => {
                state.store.abort_upload(id);
                return None;
            }
        }
    }
    match state.store.commit(id, expected) {
        Ok(entry) => {
            state.store.record_remote_hit(entry.size);
            Some(key)
        }
        Err(_) => {
            state.store.abort_upload(id);
            None
        }
    }
}

/// `POST caches {key, version}` → 201 `{cacheId}` or 409 when present.
async fn reserve_cache(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if !authorized(&headers, &state.token) {
        return unauthorized();
    }
    let (Some(key), Some(version)) = (
        body.get("key").and_then(|v| v.as_str()),
        body.get("version").and_then(|v| v.as_str()),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "key and version are required" })),
        )
            .into_response();
    };
    match state.store.reserve(key, version) {
        Ok(ReserveOutcome::Created(id)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "cacheId": id })),
        )
            .into_response(),
        Ok(ReserveOutcome::Exists(id)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "cacheId": id })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// Parse `Content-Range: bytes {start}-{end}/*` (inclusive end).
fn parse_content_range(value: &str) -> Option<(u64, u64)> {
    let range = value.strip_prefix("bytes ")?;
    let (span, _) = range.split_once('/')?;
    let (start, end) = span.split_once('-')?;
    let (start, end) = (start.parse::<u64>().ok()?, end.parse::<u64>().ok()?);
    (start <= end).then_some((start, end))
}

/// Max bytes accepted in one PATCH chunk (real clients send ≤8 MiB;
/// 4x headroom, then 413).
pub const MAX_CHUNK_BYTES: u64 = 32 * 1024 * 1024;

/// `PATCH caches/{id}` chunk upload (explicit offsets; out-of-order safe).
/// The body streams straight to disk, capped per chunk and in total.
async fn upload_chunk(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    body: axum::body::Body,
) -> axum::response::Response {
    use futures_util::TryStreamExt;

    if !authorized(&headers, &state.token) {
        return unauthorized();
    }
    let Some((start, end)) = headers
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "valid Content-Range required" })),
        )
            .into_response();
    };
    // Fast reject: a declared body past the chunk cap never streams.
    if headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > MAX_CHUNK_BYTES)
    {
        return payload_too_large("chunk exceeds 32 MiB cap");
    }
    let mut stream = body.into_data_stream();
    let mut offset = start;
    let mut received = 0u64;
    loop {
        let chunk = match stream.try_next().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "chunk stream failed" })),
                )
                    .into_response();
            }
        };
        received += chunk.len() as u64;
        // Running guard for chunked bodies that lie about (or omit) length.
        if received > MAX_CHUNK_BYTES {
            state.store.abort_upload(id);
            return payload_too_large("chunk exceeds 32 MiB cap");
        }
        if let Err(e) = state.store.write_chunk(id, offset, &chunk) {
            return store_upload_error(id, e);
        }
        offset += chunk.len() as u64;
    }
    if received != end - start + 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "chunk length disagrees with Content-Range" })),
        )
            .into_response();
    }
    match state.store.staged_len(id) {
        Some(total) => Json(serde_json::json!({ "receivedBytes": total })).into_response(),
        None => store_upload_error(id, StoreError::UnknownUpload(id)),
    }
}

fn payload_too_large(msg: &str) -> axum::response::Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn store_upload_error(id: u64, e: StoreError) -> axum::response::Response {
    match e {
        StoreError::UnknownUpload(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("unknown upload {id}") })),
        )
            .into_response(),
        StoreError::SizeMismatch { .. } => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        StoreError::TooLarge { .. } => payload_too_large(&e.to_string()),
        StoreError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// `POST caches/{id} {size}` → commit (size-verified) or 400/404.
async fn commit_cache(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if !authorized(&headers, &state.token) {
        return unauthorized();
    }
    let Some(size) = body.get("size").and_then(|v| v.as_u64()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "size is required" })),
        )
            .into_response();
    };
    match state.store.commit(id, size) {
        Ok(entry) => Json(serde_json::json!({
            "cacheId": entry.id,
            "size": entry.size,
        }))
        .into_response(),
        Err(StoreError::UnknownUpload(_)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("unknown upload {id}") })),
        )
            .into_response(),
        Err(StoreError::SizeMismatch {
            staged, declared, ..
        }) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("size mismatch: staged {staged} != declared {declared}")
            })),
        )
            .into_response(),
        Err(StoreError::TooLarge { .. }) => payload_too_large("archive exceeds store budget"),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Parse `Range: bytes={start}-{end?}` (suffix ranges rejected).
fn parse_range(value: &str) -> Option<(u64, Option<u64>)> {
    let spec = value.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    if end.is_empty() {
        return Some((start, None));
    }
    let end = end.parse::<u64>().ok()?;
    (start <= end).then_some((start, Some(end)))
}

/// `GET artifacts/{id}`: full, HEAD, or single-range download.
/// Deliberately unauthenticated: the client's downloader sends no
/// credentials (verified against `downloadUtils.ts`).
async fn download_artifact(
    State(state): State<CacheServerState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Path(id): Path<u64>,
    method: Method,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    // The client sends no credentials here, so the signed capability
    // token minted at lookup time is the only gate. Missing, malformed,
    // or tampered tokens are indistinguishable: all 401.
    let authed = params
        .get("token")
        .is_some_and(|t| verify_download_token(&state.download_secret, id, t));
    if !authed {
        return unauthorized();
    }
    if method == Method::HEAD {
        return match state.store.entry_size(id) {
            Some(total) => (
                StatusCode::OK,
                [
                    ("content-length".to_string(), total.to_string()),
                    ("accept-ranges".to_string(), "bytes".to_string()),
                ],
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let range = headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);
    // Peek total first so unsatisfiable ranges 416 correctly.
    let total = match state.store.entry_size(id) {
        Some(total) => total,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let (start, len) = match range {
        Some((start, end)) if start < total => {
            let end = end
                .map(|e| e.min(total.saturating_sub(1)))
                .unwrap_or(total.saturating_sub(1));
            if start > end {
                return range_not_satisfiable(total);
            }
            (start, end - start + 1)
        }
        Some(_) => return range_not_satisfiable(total),
        None => (0, total),
    };
    let Some(path) = state.store.archive_path(id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Stream from disk: open, seek, bound, and serve without ever
    // materializing the archive in RAM.
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let stream = tokio_util::io::ReaderStream::new(file.take(len));
    state.store.record_served(id, len);
    // Non-loopback downloads are LAN peers, not local workers.
    if !peer.ip().is_loopback() {
        state.store.record_remote_served(len);
    }
    let end = start + len.saturating_sub(1);
    if range.is_some() {
        (
            StatusCode::PARTIAL_CONTENT,
            [
                ("content-length".to_string(), len.to_string()),
                ("accept-ranges".to_string(), "bytes".to_string()),
                (
                    "content-range".to_string(),
                    format!("bytes {start}-{end}/{total}"),
                ),
            ],
            axum::body::Body::from_stream(stream),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            [
                ("content-length".to_string(), len.to_string()),
                ("accept-ranges".to_string(), "bytes".to_string()),
            ],
            axum::body::Body::from_stream(stream),
        )
            .into_response()
    }
}

fn range_not_satisfiable(total: u64) -> axum::response::Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        [("content-range".to_string(), format!("bytes */{total}"))],
    )
        .into_response()
}

pub fn router(state: CacheServerState) -> axum::Router {
    axum::Router::new()
        .route("/_apis/artifactcache/cache", get(lookup_cache))
        .route(
            "/_apis/artifactcache/caches",
            axum::routing::post(reserve_cache),
        )
        .route(
            "/_apis/artifactcache/caches/:id",
            axum::routing::patch(upload_chunk).post(commit_cache),
        )
        .route("/_apis/artifactcache/artifacts/:id", get(download_artifact))
        .with_state(state)
}

/// Serve on a bound listener until error.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    state: CacheServerState,
) -> anyhow::Result<()> {
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Base URL advertised to workers: unspecified listen hosts become
/// loopback so `archiveLocation` always resolves from the worker.
pub fn public_base_url(listen: &str, port: u16) -> String {
    let host = listen
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(listen)
        .trim_matches(|c| c == '[' || c == ']');
    let host = match host {
        "" | "0.0.0.0" | "::" => "127.0.0.1",
        h => h,
    };
    format!("http://{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_range_parses_strictly() {
        assert_eq!(parse_content_range("bytes 0-199/*"), Some((0, 199)));
        assert_eq!(parse_content_range("bytes 8-15/16"), Some((8, 15)));
        for bad in ["", "bytes 5-4/*", "bytes x-y/*", "items 0-1/*", "bytes 0-"] {
            assert_eq!(parse_content_range(bad), None, "input: {bad}");
        }
    }

    #[test]
    fn range_requests_parse_strictly() {
        assert_eq!(parse_range("bytes=0-99"), Some((0, Some(99))));
        assert_eq!(parse_range("bytes=100-"), Some((100, None)));
        for bad in ["", "bytes=-99", "bytes=5-4", "bytes=x-", "items=0-1"] {
            assert_eq!(parse_range(bad), None, "input: {bad}");
        }
    }

    #[test]
    fn worker_env_has_single_trailing_slash() {
        let env = worker_env("http://127.0.0.1:8787", "tok");
        assert_eq!(env[0].0, "ACTIONS_CACHE_URL");
        assert_eq!(env[0].1, "http://127.0.0.1:8787/");
        assert_eq!(
            env[1],
            ("ACTIONS_RUNTIME_TOKEN".to_string(), "tok".to_string())
        );
        let env = worker_env("http://127.0.0.1:8787/", "tok");
        assert_eq!(env[0].1, "http://127.0.0.1:8787/");
    }

    #[test]
    fn download_tokens_verify_and_reject_tampering() {
        let secret = [7u8; 32];
        let token = sign_download_token(&secret, 42).unwrap();
        assert!(verify_download_token(&secret, 42, &token));
        assert!(!verify_download_token(&secret, 43, &token));
        assert!(!verify_download_token(&[8u8; 32], 42, &token));
        assert!(!verify_download_token(&secret, 42, "not-base64!!!"));
        assert!(!verify_download_token(&secret, 42, ""));
    }

    #[test]
    fn server_state_mints_fresh_credentials() {
        let dir = crate::test_support::TempDir::new("cache-creds").unwrap();
        let store = crate::cache::store::CacheStore::open(&dir.path().join("c"), 1).unwrap();
        let a = CacheServerState::new(store.clone(), "http://x".to_string());
        let b = CacheServerState::new(store, "http://x".to_string());
        assert_ne!(a.token, b.token);
        assert_ne!(a.download_secret, b.download_secret);
        assert!(!a.token.is_empty());
    }

    #[test]
    fn public_base_rewrites_unspecified_hosts() {
        assert_eq!(
            public_base_url("127.0.0.1:8787", 8787),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            public_base_url("0.0.0.0:8787", 8787),
            "http://127.0.0.1:8787"
        );
        assert_eq!(public_base_url("[::]:9000", 9000), "http://127.0.0.1:9000");
    }
}
