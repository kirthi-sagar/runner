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
use std::time::Duration;

use super::store::{CacheStore, ReserveOutcome, StoreError, GLOBAL_SCOPE};

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

/// Scope a proxy base URL: appends `/repos/{scope}` (no trailing
/// slash; `worker_env` adds it). Providers pre-scope the cached
/// endpoint before handing it to the worker seam.
pub fn scoped_base_url(base_url: &str, scope: &str) -> String {
    format!("{}/repos/{scope}", base_url.trim_end_matches('/'))
}

/// Scoped worker env: the base URL gains `/repos/{scope}` so the
/// client's `_apis/...` calls land on the namespaced routes.
pub fn worker_env_scoped(base_url: &str, token: &str, scope: &str) -> Vec<(String, String)> {
    worker_env(&scoped_base_url(base_url, scope), token)
}

/// Join validated `owner`/`repo` path segments into an `owner/repo`
/// scope (`None` → 400). Segments follow GitHub naming (alphanumeric
/// plus `.`, `_`, `-`); the scope is only ever an index key and hash
/// input, never a filesystem path.
fn scope_for(owner: &str, repo: &str) -> Option<String> {
    if valid_scope_segment(owner) && valid_scope_segment(repo) {
        Some(format!("{owner}/{repo}"))
    } else {
        None
    }
}

fn valid_scope_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment.len() <= 128
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn bad_request(msg: &str) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
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
            peers: std::sync::Arc::new(MdnsPeerResolver::new()),
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

/// Production resolver: instant snapshot of the continuous
/// background peer table — no browse, no I/O, no latency penalty
/// on cache misses.
#[derive(Debug, Clone)]
pub struct MdnsPeerResolver {
    table: crate::mesh::discovery::MdnsCachePeerTable,
}

impl Default for MdnsPeerResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsPeerResolver {
    /// Resolver over a fresh, unstarted table (unit tests; the daemon
    /// injects its started table via [`with_table`](Self::with_table)).
    pub fn new() -> Self {
        Self::with_table(crate::mesh::discovery::MdnsCachePeerTable::new())
    }

    /// Resolver over the daemon's shared peer table.
    pub fn with_table(table: crate::mesh::discovery::MdnsCachePeerTable) -> Self {
        Self { table }
    }
}

#[async_trait::async_trait]
impl PeerResolver for MdnsPeerResolver {
    async fn cache_peers(&self) -> Vec<CachePeer> {
        self.table
            .snapshot(std::time::Instant::now())
            .iter()
            .filter_map(cache_peer_from_node)
            .take(MAX_FEDERATION_PEERS)
            .collect()
    }
}

/// Resolve one discovered node to a cache endpoint (pure; unit-tested).
/// Strictly active cache servers only: federation must never aim at
/// nodes that did not opt in or cannot be addressed.
pub fn cache_peer_from_node(node: &crate::mesh::discovery::DiscoveredNode) -> Option<CachePeer> {
    let metrics = node.metrics.as_ref()?;
    if !metrics.cache_enabled {
        return None;
    }
    let port = metrics.cache_port?;
    if metrics.cache_token.is_empty() {
        return None;
    }
    let ip = node
        .addrs
        .iter()
        .find(|a| !a.is_loopback() && !a.is_unspecified())?;
    Some(CachePeer {
        node_id: if metrics.node_id.is_empty() {
            node.instance.clone()
        } else {
            metrics.node_id.clone()
        },
        base_url: format!("http://{ip}:{port}"),
        token: metrics.cache_token.clone(),
    })
}

/// Cap on peers queried per local miss (bounds spoof-amplified fan-out).
pub const MAX_FEDERATION_PEERS: usize = 8;
/// Per-peer lookup timeout: federation must never stall a lookup.
pub const PEER_LOOKUP_TIMEOUT_MS: u64 = 150;
/// Stream idle watchdog: no chunk bytes for 15s aborts the peer
/// transfer (stalled donors must not pin runner threads).
pub const PEER_STREAM_CHUNK_TIMEOUT: Duration = Duration::from_secs(15);
/// Overall transfer ceiling: 60s base + 1s per 10MB declared (~80
/// Mbps floor — generous on gigabit LAN, fatal to trickles).
pub fn peer_stream_total_timeout(expected: u64) -> Duration {
    Duration::from_secs(60 + expected / 10_000_000)
}

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

/// `GET cache?keys=a,b&version=v` → hit JSON or 204 miss (legacy
/// unscoped route: serves the `global` namespace).
async fn lookup_cache(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    lookup_cache_for(&state, headers, &params, GLOBAL_SCOPE).await
}

/// Scoped lookup: identical, namespaced to one repo.
async fn lookup_cache_scoped(
    State(state): State<CacheServerState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let Some(scope) = scope_for(&owner, &repo) else {
        return bad_request("invalid repo scope");
    };
    lookup_cache_for(&state, headers, &params, &scope).await
}

async fn lookup_cache_for(
    state: &CacheServerState,
    headers: HeaderMap,
    params: &HashMap<String, String>,
    scope: &str,
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
    match state.store.lookup(scope, &version, &keys) {
        Some(entry) => lookup_hit(state, &entry).into_response(),
        None => match federate_lookup(state, scope, &version, &keys).await {
            // Imported from a peer: re-resolve locally so the response
            // carries our own signed URL and a consistent hit record.
            Some(_) => match state.store.lookup(scope, &version, &keys) {
                Some(entry) => lookup_hit(state, &entry).into_response(),
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
        // Hex SHA-256 when recorded (null for pre-digest rows and
        // legacy peers, which skip verification but keep length checks).
        "digest": entry.sha256,
    }))
    .into_response()
}

/// LAN fallback for a local miss: scatter metadata probes to every
/// candidate peer at once, stream the archive from the first
/// responder holding the blob, and cancel the losers. Every failure
/// mode (timeout, HTTP error, short stream, commit mismatch) falls
/// through to a local 204. Returns the imported entry's key on
/// success.
///
/// Timing: probes run concurrently, each bounded by
/// `PEER_LOOKUP_TIMEOUT_MS`, so an all-miss resolves within one
/// probe budget — never the sum. A failed winner stream resolves to
/// `None` (losers were already cancelled, so there is no second
/// attempt); the store aborts the partial upload first.
async fn federate_lookup(
    state: &CacheServerState,
    scope: &str,
    version: &str,
    keys: &[String],
) -> Option<String> {
    let mut scatter = tokio::task::JoinSet::new();
    for peer in state.peers.cache_peers().await {
        let client = state.http.clone();
        let scope = scope.to_string();
        let version = version.to_string();
        let keys = keys.to_vec();
        scatter.spawn(async move { probe_peer(&client, &peer, &scope, &version, &keys).await });
    }
    while let Some(outcome) = scatter.join_next().await {
        // Miss, error, timeout, or a panicked probe: a later
        // finisher may still hold the blob.
        if let Ok(Some(hit)) = outcome {
            // First responder wins: cancel every slower probe
            // before streaming a byte from anyone else.
            scatter.abort_all();
            return stream_probe_hit(state, scope, version, hit).await;
        }
    }
    None
}

/// Peer lookup path for a scope: namespaced except `global`, so a
/// federated hit can only ever import the requesting scope's entries.
/// Pre-v1.7.0 peers 404 scoped paths, which falls through to a miss.
fn peer_lookup_url(peer: &CachePeer, scope: &str) -> String {
    if scope == GLOBAL_SCOPE {
        format!("{}/_apis/artifactcache/cache", peer.base_url)
    } else {
        format!("{}/repos/{scope}/_apis/artifactcache/cache", peer.base_url)
    }
}

/// Winning probe: the first responder's stream coordinates.
struct ProbeHit {
    key: String,
    location: String,
    /// Advertised hex SHA-256 (`None` for legacy peers, which skip
    /// digest verification but keep strict length checks).
    digest: Option<String>,
}

/// Metadata probe against one peer: hit coordinates on 200-with-JSON,
/// `None` on miss, error, timeout, or malformed body. Bounded by
/// `PEER_LOOKUP_TIMEOUT_MS`; never streams archive bytes.
async fn probe_peer(
    client: &reqwest::Client,
    peer: &CachePeer,
    scope: &str,
    version: &str,
    keys: &[String],
) -> Option<ProbeHit> {
    let lookup_url = peer_lookup_url(peer, scope);
    let mut request = client
        .get(&lookup_url)
        .header("authorization", format!("Bearer {}", peer.token))
        .timeout(std::time::Duration::from_millis(PEER_LOOKUP_TIMEOUT_MS));
    request = request.query(&[("keys", keys.join(",")), ("version", version.to_string())]);
    let hit: serde_json::Value = request.send().await.ok()?.json().await.ok()?;
    Some(ProbeHit {
        key: hit.get("cacheKey")?.as_str()?.to_string(),
        location: hit.get("archiveLocation")?.as_str()?.to_string(),
        digest: hit
            .get("digest")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// Stream the winner's archive into the local store with the usual
/// integrity guards (exact content-length, running disk bound,
/// in-flight digest, commit verification). Any failure aborts the
/// partial upload and resolves to `None`: the losers were already
/// cancelled, so there is no second attempt.
async fn stream_probe_hit(
    state: &CacheServerState,
    scope: &str,
    version: &str,
    hit: ProbeHit,
) -> Option<String> {
    let key = hit.key;
    let download = state.http.get(&hit.location).send().await.ok()?;
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
    let id = match state.store.reserve(scope, &key, version) {
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
    let stage = match state.store.stage_path(id) {
        Some(path) => path,
        None => {
            state.store.abort_upload(id);
            return None;
        }
    };
    let max_bytes = state.store.max_bytes();
    let source = ResponseChunks { response: download };
    let pumped = pump_to_staging(
        source,
        &stage,
        expected,
        max_bytes,
        hit.digest.as_deref(),
        PEER_STREAM_CHUNK_TIMEOUT,
        peer_stream_total_timeout(expected),
    )
    .await;
    let (staged, _) = match pumped {
        Ok(outcome) => outcome,
        Err(_) => {
            state.store.abort_upload(id);
            return None;
        }
    };
    // Strict length parity across the file boundary: the counted
    // bytes and the staged file must both equal the declaration
    // (commit re-verifies once more before installing).
    if staged != expected || state.store.staged_len(id) != Some(expected) {
        state.store.abort_upload(id);
        return None;
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

/// Sequential pump failure: every arm aborts the upload upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PumpError {
    /// No chunk bytes within the idle watchdog.
    IdleTimeout,
    /// Transfer exceeded the overall ceiling.
    TotalTimeout,
    /// Stream passed the declared length (trailing garbage).
    Overrun,
    /// Stream passed the store budget.
    TooLarge,
    /// Chunk fetch failed (truncated socket, reset).
    Chunk(String),
    /// Staging write failed.
    Write(String),
    /// In-flight digest disagrees with the advertised one.
    DigestMismatch { expected: String, actual: String },
}

/// One sequential chunk supplier for the staging pump: the live
/// adapter wraps a peer download, scripted fakes drive unit tests.
/// Boxed future keeps the trait object-safe without async-trait.
/// Boxed next-chunk future (keeps [`ChunkSource`] object-safe
/// without async-trait).
type ChunkFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Option<Result<bytes::Bytes, String>>> + Send + 'a>,
>;

trait ChunkSource {
    fn next_chunk(&mut self) -> ChunkFuture<'_>;
}

/// Live adapter: pull response chunks off the winning download.
struct ResponseChunks {
    response: reqwest::Response,
}

impl ChunkSource for ResponseChunks {
    fn next_chunk(&mut self) -> ChunkFuture<'_> {
        Box::pin(async move {
            match self.response.chunk().await {
                Ok(Some(bytes)) => Some(Ok(bytes)),
                Ok(None) => None,
                Err(e) => Some(Err(e.to_string())),
            }
        })
    }
}

/// Pump a chunk source sequentially into a staging file with async
/// buffered I/O: per-chunk idle watchdog plus an overall transfer
/// ceiling, running overrun/budget guards, and a running SHA-256
/// verified against the peer-advertised digest (`None` for legacy
/// peers skips the comparison). Returns staged bytes + hex digest.
/// Never touches the store mutex: reservation and commit bracket it.
#[allow(clippy::too_many_arguments)]
async fn pump_to_staging<C: ChunkSource>(
    mut source: C,
    stage_path: &std::path::Path,
    expected: u64,
    max_bytes: u64,
    expected_digest: Option<&str>,
    chunk_timeout: Duration,
    total_timeout: Duration,
) -> Result<(u64, String), PumpError> {
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;
    // Exclusive reservation: truncate any stale file, never append.
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(stage_path)
        .await
        .map_err(|e| PumpError::Write(e.to_string()))?;
    let mut writer = tokio::io::BufWriter::with_capacity(64 * 1024, file);
    let mut hasher = sha2::Sha256::new();
    let mut staged = 0u64;
    let body = async {
        loop {
            let chunk = match tokio::time::timeout(chunk_timeout, source.next_chunk()).await {
                Ok(Some(Ok(bytes))) => bytes,
                Ok(Some(Err(e))) => return Err(PumpError::Chunk(e)),
                Ok(None) => break,
                Err(_) => return Err(PumpError::IdleTimeout),
            };
            let end = staged.saturating_add(chunk.len() as u64);
            if end > expected {
                return Err(PumpError::Overrun);
            }
            if end > max_bytes {
                return Err(PumpError::TooLarge);
            }
            hasher.update(&chunk);
            writer
                .write_all(&chunk)
                .await
                .map_err(|e| PumpError::Write(e.to_string()))?;
            staged = end;
        }
        writer
            .flush()
            .await
            .map_err(|e| PumpError::Write(e.to_string()))?;
        let actual = format!("{:x}", hasher.finalize());
        if let Some(want) = expected_digest {
            if actual != want {
                return Err(PumpError::DigestMismatch {
                    expected: want.to_string(),
                    actual,
                });
            }
        }
        Ok((staged, actual))
    };
    match tokio::time::timeout(total_timeout, body).await {
        Ok(outcome) => outcome,
        Err(_) => Err(PumpError::TotalTimeout),
    }
}

/// `POST caches {key, version}` → 201 `{cacheId}` or 409 when present.
async fn reserve_cache(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    reserve_cache_for(&state, headers, &body, GLOBAL_SCOPE).await
}

/// Scoped reserve: the pending upload is namespaced to one repo.
async fn reserve_cache_scoped(
    State(state): State<CacheServerState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(scope) = scope_for(&owner, &repo) else {
        return bad_request("invalid repo scope");
    };
    reserve_cache_for(&state, headers, &body, &scope).await
}

async fn reserve_cache_for(
    state: &CacheServerState,
    headers: HeaderMap,
    body: &serde_json::Value,
    scope: &str,
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
    match state.store.reserve(scope, key, version) {
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
    upload_chunk_for(state, headers, id, body).await
}

/// Scoped chunk upload: uploads are id-keyed (the scope was fixed at
/// reserve), so this only validates the segments, then delegates.
async fn upload_chunk_scoped(
    State(state): State<CacheServerState>,
    Path((owner, repo, id)): Path<(String, String, u64)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> axum::response::Response {
    if scope_for(&owner, &repo).is_none() {
        return bad_request("invalid repo scope");
    }
    upload_chunk_for(state, headers, id, body).await
}

async fn upload_chunk_for(
    state: CacheServerState,
    headers: HeaderMap,
    id: u64,
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
    commit_cache_for(&state, headers, id, &body).await
}

/// Scoped commit: id-keyed like uploads; validates, then delegates.
async fn commit_cache_scoped(
    State(state): State<CacheServerState>,
    Path((owner, repo, id)): Path<(String, String, u64)>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if scope_for(&owner, &repo).is_none() {
        return bad_request("invalid repo scope");
    }
    commit_cache_for(&state, headers, id, &body).await
}

async fn commit_cache_for(
    state: &CacheServerState,
    headers: HeaderMap,
    id: u64,
    body: &serde_json::Value,
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
        // Scoped twins: same handlers, namespaced to one repo. Downloads
        // stay unscoped-only (lookup mints an absolute `archiveLocation`;
        // the HMAC token minted at scoped lookup time is the gate).
        .route(
            "/repos/:owner/:repo/_apis/artifactcache/cache",
            get(lookup_cache_scoped),
        )
        .route(
            "/repos/:owner/:repo/_apis/artifactcache/caches",
            axum::routing::post(reserve_cache_scoped),
        )
        .route(
            "/repos/:owner/:repo/_apis/artifactcache/caches/:id",
            axum::routing::patch(upload_chunk_scoped).post(commit_cache_scoped),
        )
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
    fn scope_segments_join_and_reject_cleanly() {
        assert_eq!(scope_for("acme", "web"), Some("acme/web".to_string()));
        assert_eq!(
            scope_for("my-org_1", "repo.js"),
            Some("my-org_1/repo.js".to_string())
        );
        for (owner, repo) in [
            ("", "web"),
            ("acme", ""),
            (".", "web"),
            ("acme", ".."),
            ("ac/me", "web"),
            ("acme", "w eb"),
            ("acme!", "web"),
        ] {
            assert_eq!(scope_for(owner, repo), None, "{owner}/{repo}");
        }
    }

    #[test]
    fn scoped_worker_env_nests_under_repos() {
        let env = worker_env_scoped("http://127.0.0.1:8787", "tok", "acme/web");
        assert_eq!(env[0].0, "ACTIONS_CACHE_URL");
        assert_eq!(env[0].1, "http://127.0.0.1:8787/repos/acme/web/");
        // Trailing slashes collapse; global stays unscoped.
        let env = worker_env_scoped("http://127.0.0.1:8787/", "tok", "acme/web");
        assert_eq!(env[0].1, "http://127.0.0.1:8787/repos/acme/web/");
        let peer = CachePeer {
            node_id: "n".to_string(),
            base_url: "http://10.0.0.2:8787".to_string(),
            token: "t".to_string(),
        };
        assert_eq!(
            peer_lookup_url(&peer, "acme/web"),
            "http://10.0.0.2:8787/repos/acme/web/_apis/artifactcache/cache"
        );
        assert_eq!(
            peer_lookup_url(&peer, GLOBAL_SCOPE),
            "http://10.0.0.2:8787/_apis/artifactcache/cache"
        );
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

    use crate::mesh::discovery::{DiscoveredNode, LanMetrics, MdnsCachePeerTable};

    fn active_node(node_id: &str, ip: &str) -> DiscoveredNode {
        DiscoveredNode {
            instance: format!("{node_id}._runner._tcp.local."),
            host: format!("{node_id}.local"),
            port: 9535,
            addrs: vec![ip.parse().unwrap()],
            metrics: Some(LanMetrics {
                cores: 8,
                ram_mb: 16384,
                slots: 4,
                cache_port: Some(8787),
                cache_enabled: true,
                node_id: node_id.to_string(),
                cache_token: "tok".to_string(),
            }),
        }
    }

    #[test]
    fn cache_peer_from_node_accepts_active_servers() {
        let peer = cache_peer_from_node(&active_node("node-a", "10.0.0.2")).unwrap();
        assert_eq!(peer.node_id, "node-a");
        assert_eq!(peer.base_url, "http://10.0.0.2:8787");
        assert_eq!(peer.token, "tok");
        // Empty broadcast id falls back to the instance name.
        let mut legacy = active_node("", "10.0.0.3");
        legacy.instance = "legacy._runner._tcp.local.".to_string();
        let peer = cache_peer_from_node(&legacy).unwrap();
        assert_eq!(peer.node_id, "legacy._runner._tcp.local.");
    }

    #[test]
    fn cache_peer_from_node_rejects_inactive() {
        // No metrics at all.
        let mut node = active_node("node-a", "10.0.0.2");
        node.metrics = None;
        assert!(cache_peer_from_node(&node).is_none());
        // Federation not enabled.
        let mut node = active_node("node-a", "10.0.0.2");
        node.metrics.as_mut().unwrap().cache_enabled = false;
        assert!(cache_peer_from_node(&node).is_none());
        // No cache port.
        let mut node = active_node("node-a", "10.0.0.2");
        node.metrics.as_mut().unwrap().cache_port = None;
        assert!(cache_peer_from_node(&node).is_none());
        // Empty bearer token.
        let mut node = active_node("node-a", "10.0.0.2");
        node.metrics.as_mut().unwrap().cache_token.clear();
        assert!(cache_peer_from_node(&node).is_none());
        // No usable address (loopback / unspecified / none).
        for addrs in [
            vec!["127.0.0.1".parse().unwrap()],
            vec!["0.0.0.0".parse().unwrap()],
            vec![],
        ] {
            let mut node = active_node("node-a", "10.0.0.2");
            node.addrs = addrs;
            assert!(cache_peer_from_node(&node).is_none());
        }
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Scripted fake peer: programmable lookup latency/status/body plus
    /// a download endpoint, with hit counters proving scatter (every
    /// peer probed) and winner-take-all (only the winner streams).
    struct ScriptPeer {
        base: String,
        lookups: Arc<AtomicUsize>,
        downloads: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct ScriptPeerConfig {
        lookup_delay: Duration,
        lookup_status: u16,
        lookup_body: serde_json::Value,
        download_bytes: Vec<u8>,
        /// Advertised digest (`None` omits the field: legacy peer).
        digest_override: Option<String>,
        /// Declared download length when the download must stall
        /// mid-body after the prefix bytes (`None` serves whole).
        stall_declared_len: Option<u64>,
    }

    fn hit_body(key: &str, base: &str, digest: Option<&str>) -> serde_json::Value {
        let mut body = serde_json::json!({
            "cacheKey": key,
            "archiveLocation": format!("{base}/download"),
        });
        if let Some(digest) = digest {
            body["digest"] = serde_json::Value::String(digest.to_string());
        }
        body
    }

    /// Download stream that emits one prefix chunk, then stalls
    /// forever (the test runtime drops it on completion).
    struct StallStream {
        prefix: Option<bytes::Bytes>,
    }

    impl futures_util::Stream for StallStream {
        type Item = Result<bytes::Bytes, std::io::Error>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            match self.prefix.take() {
                Some(bytes) => std::task::Poll::Ready(Some(Ok(bytes))),
                None => std::task::Poll::Pending,
            }
        }
    }

    async fn spawn_script_peer(key: &str, config: ScriptPeerConfig) -> ScriptPeer {
        use axum::{routing::get, Json, Router};
        let lookups = Arc::new(AtomicUsize::new(0));
        let downloads = Arc::new(AtomicUsize::new(0));
        // Bind first so the hit body can advertise the real download URL.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let body = if config.lookup_body.is_null() {
            hit_body(key, &base, config.digest_override.as_deref())
        } else {
            config.lookup_body.clone()
        };
        let app = Router::new()
            .route(
                "/_apis/artifactcache/cache",
                get({
                    let lookups = lookups.clone();
                    let config = config.clone();
                    move || {
                        let lookups = lookups.clone();
                        async move {
                            lookups.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(config.lookup_delay).await;
                            (
                                axum::http::StatusCode::from_u16(config.lookup_status).unwrap(),
                                Json(body.clone()),
                            )
                        }
                    }
                }),
            )
            .route(
                "/download",
                get({
                    let downloads = downloads.clone();
                    let bytes = config.download_bytes.clone();
                    let stall = config.stall_declared_len;
                    move || {
                        let downloads = downloads.clone();
                        async move {
                            use axum::response::IntoResponse;
                            downloads.fetch_add(1, Ordering::SeqCst);
                            match stall {
                                None => bytes.clone().into_response(),
                                // Explicit length + prefix chunk, then
                                // silence (production download_artifact
                                // proves hyper honors declared lengths
                                // on streams).
                                Some(declared) => (
                                    [("content-length".to_string(), declared.to_string())],
                                    axum::body::Body::from_stream(StallStream {
                                        prefix: Some(bytes::Bytes::copy_from_slice(&bytes)),
                                    }),
                                )
                                    .into_response(),
                            }
                        }
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await });
        ScriptPeer {
            base,
            lookups,
            downloads,
        }
    }

    fn hit_config(delay: Duration, bytes: &[u8]) -> ScriptPeerConfig {
        ScriptPeerConfig {
            lookup_delay: delay,
            lookup_status: 200,
            lookup_body: serde_json::Value::Null,
            download_bytes: bytes.to_vec(),
            digest_override: None,
            stall_declared_len: None,
        }
    }

    fn hex_digest(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    struct StaticPeers {
        peers: Vec<CachePeer>,
    }

    #[async_trait::async_trait]
    impl PeerResolver for StaticPeers {
        async fn cache_peers(&self) -> Vec<CachePeer> {
            self.peers.clone()
        }
    }

    fn peer_for(script: &ScriptPeer, node_id: &str) -> CachePeer {
        CachePeer {
            node_id: node_id.to_string(),
            base_url: script.base.clone(),
            token: "t".to_string(),
        }
    }

    fn requesting_state(
        peers: Vec<CachePeer>,
        max_bytes: u64,
    ) -> (CacheServerState, crate::test_support::TempDir) {
        let dir = crate::test_support::TempDir::new("federate-scatter").unwrap();
        let store = crate::cache::store::CacheStore::open(dir.path(), max_bytes).unwrap();
        let mut state = CacheServerState::new(store, "http://127.0.0.1:8787".to_string());
        state.peers = Arc::new(StaticPeers { peers });
        (state, dir)
    }

    /// Wait (bounded) for a counter to reach a value; loopback
    /// delivery has no strict happens-before with the assertion.
    async fn await_count(counter: &AtomicUsize, want: usize) {
        for _ in 0..200 {
            if counter.load(Ordering::SeqCst) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(counter.load(Ordering::SeqCst), want);
    }

    #[tokio::test]
    async fn federate_first_hit_wins_and_losers_never_stream() {
        // Slow peer FIRST with a valid hit: sequential code would take
        // its answer and never reach the fast peer, so a fast win
        // proves the probes overlapped — no wall-clock assertion needed.
        let slow =
            spawn_script_peer("slow-blob", hit_config(Duration::from_millis(50), b"SLOW")).await;
        let fast = spawn_script_peer(
            "fast-blob",
            hit_config(Duration::from_millis(10), b"FAST-PAYLOAD"),
        )
        .await;
        let (state, _dir) = requesting_state(
            vec![peer_for(&slow, "slow"), peer_for(&fast, "fast")],
            1 << 20,
        );
        // Exact primary key (lookup is exact-match; scripts ignore keys).
        let keys = vec!["fast-blob".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won.as_deref(), Some("fast-blob"));
        // Scattered (slow was probed) but winner-take-all (slow
        // never streamed, even after its answer lands).
        await_count(&slow.lookups, 1).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(slow.downloads.load(Ordering::SeqCst), 0);
        assert_eq!(fast.downloads.load(Ordering::SeqCst), 1);
        // Imported locally under the winning key.
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_some());
    }

    #[tokio::test]
    async fn federate_all_miss_resolves_none_within_bound() {
        let gone = spawn_script_peer(
            "",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 404,
                lookup_body: serde_json::json!({"error": "nope"}),
                download_bytes: vec![],
                digest_override: None,
                stall_declared_len: None,
            },
        )
        .await;
        let empty = spawn_script_peer(
            "",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 204,
                lookup_body: serde_json::json!({}),
                download_bytes: vec![],
                digest_override: None,
                stall_declared_len: None,
            },
        )
        .await;
        // Hanging peer FIRST: exercises the probe timeout arm without
        // stalling the verdict past one probe budget.
        let hang = spawn_script_peer(
            "",
            ScriptPeerConfig {
                lookup_delay: Duration::from_secs(30),
                lookup_status: 200,
                lookup_body: serde_json::json!({}),
                download_bytes: vec![],
                digest_override: None,
                stall_declared_len: None,
            },
        )
        .await;
        let (state, _dir) = requesting_state(
            vec![
                peer_for(&hang, "hang"),
                peer_for(&gone, "gone"),
                peer_for(&empty, "empty"),
            ],
            1 << 20,
        );
        let keys = vec!["k".to_string()];
        let start = std::time::Instant::now();
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        let elapsed = start.elapsed();
        assert_eq!(won, None);
        // One probe budget (150ms), never the sum — 2s is 10x headroom.
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        // No short-circuit on early misses: everyone was probed, and
        // with no winner nothing streamed.
        for peer in [&hang, &gone, &empty] {
            await_count(&peer.lookups, 1).await;
            assert_eq!(peer.downloads.load(Ordering::SeqCst), 0);
        }
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_none());
    }

    #[tokio::test]
    async fn federate_tolerates_peer_errors() {
        // 500 with a JSON body (parses, but carries no hit).
        let broken = spawn_script_peer(
            "",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 500,
                lookup_body: serde_json::json!({"error": "boom"}),
                download_bytes: vec![],
                digest_override: None,
                stall_declared_len: None,
            },
        )
        .await;
        // 200 with a shape that is not a hit at all.
        let weird = spawn_script_peer(
            "",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 200,
                lookup_body: serde_json::json!("just-a-string"),
                download_bytes: vec![],
                digest_override: None,
                stall_declared_len: None,
            },
        )
        .await;
        let good =
            spawn_script_peer("good-blob", hit_config(Duration::from_millis(20), b"GOOD")).await;
        let (state, _dir) = requesting_state(
            vec![
                peer_for(&broken, "broken"),
                peer_for(&weird, "weird"),
                peer_for(&good, "good"),
            ],
            1 << 20,
        );
        let keys = vec!["good-blob".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won.as_deref(), Some("good-blob"));
        assert_eq!(good.downloads.load(Ordering::SeqCst), 1);
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_some());
    }

    #[tokio::test]
    async fn federate_oversize_winner_aborts_and_releases() {
        // Winner declares 32 bytes; the requester's store caps at 16.
        let big = spawn_script_peer("big-blob", hit_config(Duration::ZERO, &[7u8; 32])).await;
        let (state, _dir) = requesting_state(vec![peer_for(&big, "big")], 16);
        let keys = vec!["k".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won, None);
        assert_eq!(big.downloads.load(Ordering::SeqCst), 1);
        // Nothing committed, and the aborted upload released its
        // pending slot (a fresh reserve starts clean).
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_none());
        assert!(matches!(
            state.store.reserve(GLOBAL_SCOPE, "big-blob", "v1"),
            Ok(crate::cache::store::ReserveOutcome::Created(_))
        ));
    }

    /// Raw-socket peer: honest lookup, lying download — declares 64
    /// bytes, sends 8, hangs up. axum cannot emit this shape (it
    /// always frames honestly), so the truncation arm needs raw TCP.
    async fn spawn_truncating_peer() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let hit = serde_json::json!({
            "cacheKey": "cut-blob",
            "archiveLocation": format!("{base}/download"),
        })
        .to_string();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while head.len() < 8192 {
                    match sock.read(&mut byte).await {
                        Ok(1) => {
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                let is_lookup = String::from_utf8_lossy(&head).contains("/_apis/artifactcache/");
                if is_lookup {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{hit}",
                        hit.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                } else {
                    let _ = sock
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\nconnection: close\r\n\r\n01234567")
                        .await;
                }
            }
        });
        base
    }

    #[tokio::test]
    async fn federate_truncated_winner_stream_aborts() {
        let base = spawn_truncating_peer().await;
        let peer = CachePeer {
            node_id: "cut".to_string(),
            base_url: base,
            token: "t".to_string(),
        };
        let (state, _dir) = requesting_state(vec![peer], 1 << 20);
        let keys = vec!["k".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won, None);
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_none());
        assert!(matches!(
            state.store.reserve(GLOBAL_SCOPE, "cut-blob", "v1"),
            Ok(crate::cache::store::ReserveOutcome::Created(_))
        ));
    }

    /// Scripted chunk supplier for pump unit tests (no HTTP).
    enum PumpScript {
        Emit(bytes::Bytes),
        EmitAfter(Duration, bytes::Bytes),
        Fail(String),
        StallForever,
    }

    struct ScriptSource {
        steps: std::collections::VecDeque<PumpScript>,
    }

    impl ScriptSource {
        fn new(steps: Vec<PumpScript>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl super::ChunkSource for ScriptSource {
        fn next_chunk(&mut self) -> super::ChunkFuture<'_> {
            Box::pin(async move {
                match self.steps.pop_front() {
                    Some(PumpScript::Emit(bytes)) => Some(Ok(bytes)),
                    Some(PumpScript::EmitAfter(delay, bytes)) => {
                        tokio::time::sleep(delay).await;
                        Some(Ok(bytes))
                    }
                    Some(PumpScript::Fail(e)) => Some(Err(e)),
                    Some(PumpScript::StallForever) => std::future::pending().await,
                    None => None,
                }
            })
        }
    }

    /// Pump into a scratch path (no store needed).
    fn pump_scratch() -> (crate::test_support::TempDir, std::path::PathBuf) {
        let dir = crate::test_support::TempDir::new("pump").unwrap();
        let path = dir.path().join("stage.tmp");
        (dir, path)
    }

    #[tokio::test]
    async fn pump_exact_pass_through_writes_and_digests() {
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![
            PumpScript::Emit(bytes::Bytes::from_static(b"0123")),
            PumpScript::Emit(bytes::Bytes::from_static(b"4567")),
        ]);
        let (staged, hex) = pump_to_staging(
            source,
            &path,
            8,
            1 << 20,
            None,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(staged, 8);
        assert_eq!(hex, hex_digest(b"01234567"));
        assert_eq!(std::fs::read(&path).unwrap(), b"01234567");
    }

    #[tokio::test]
    async fn pump_overrun_and_budget_guard() {
        // Trailing garbage past the declaration.
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![
            PumpScript::Emit(bytes::Bytes::from_static(b"01234567")),
            PumpScript::Emit(bytes::Bytes::from_static(b"EXTRA")),
        ]);
        assert_eq!(
            pump_to_staging(
                source,
                &path,
                8,
                1 << 20,
                None,
                Duration::from_secs(5),
                Duration::from_secs(5)
            )
            .await,
            Err(PumpError::Overrun)
        );
        // Budget breach before the declaration (16 bytes vs 15).
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![PumpScript::Emit(bytes::Bytes::from_static(
            b"0123456789abcdef",
        ))]);
        assert_eq!(
            pump_to_staging(
                source,
                &path,
                100,
                15,
                None,
                Duration::from_secs(5),
                Duration::from_secs(5)
            )
            .await,
            Err(PumpError::TooLarge)
        );
    }

    #[tokio::test]
    async fn pump_idle_timeout_fires_on_silence() {
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![
            PumpScript::Emit(bytes::Bytes::from_static(b"0123")),
            PumpScript::StallForever,
        ]);
        let start = std::time::Instant::now();
        assert_eq!(
            pump_to_staging(
                source,
                &path,
                1024,
                1 << 20,
                None,
                Duration::from_millis(50),
                Duration::from_secs(5)
            )
            .await,
            Err(PumpError::IdleTimeout)
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        // No flush on the failure path: staging cleanup is the
        // caller's abort (proven at the federate level below).
    }

    #[tokio::test]
    async fn pump_total_timeout_fires_on_trickle() {
        let (_dir, path) = pump_scratch();
        // 1 byte per 40ms against a 100ms ceiling: the idle watchdog
        // (5s) never fires, the overall ceiling does.
        let source = ScriptSource::new(
            (0..10)
                .map(|_| {
                    PumpScript::EmitAfter(
                        Duration::from_millis(40),
                        bytes::Bytes::from_static(b"x"),
                    )
                })
                .collect(),
        );
        assert_eq!(
            pump_to_staging(
                source,
                &path,
                10,
                1 << 20,
                None,
                Duration::from_secs(5),
                Duration::from_millis(100)
            )
            .await,
            Err(PumpError::TotalTimeout)
        );
    }

    #[tokio::test]
    async fn pump_chunk_error_and_digest_verdicts() {
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![
            PumpScript::Emit(bytes::Bytes::from_static(b"0123")),
            PumpScript::Fail("reset".to_string()),
        ]);
        assert_eq!(
            pump_to_staging(
                source,
                &path,
                8,
                1 << 20,
                None,
                Duration::from_secs(5),
                Duration::from_secs(5)
            )
            .await,
            Err(PumpError::Chunk("reset".to_string()))
        );
        // Wrong advertised digest.
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![PumpScript::Emit(bytes::Bytes::from_static(
            b"01234567",
        ))]);
        let wrong = "0".repeat(64);
        assert_eq!(
            pump_to_staging(
                source,
                &path,
                8,
                1 << 20,
                Some(&wrong),
                Duration::from_secs(5),
                Duration::from_secs(5)
            )
            .await,
            Err(PumpError::DigestMismatch {
                expected: wrong,
                actual: hex_digest(b"01234567"),
            })
        );
        // Correct digest passes.
        let (_dir, path) = pump_scratch();
        let source = ScriptSource::new(vec![PumpScript::Emit(bytes::Bytes::from_static(
            b"01234567",
        ))]);
        let right = hex_digest(b"01234567");
        let (staged, hex) = pump_to_staging(
            source,
            &path,
            8,
            1 << 20,
            Some(&right),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!((staged, hex), (8, right));
    }

    #[test]
    fn stream_total_timeout_scales_with_size() {
        assert_eq!(peer_stream_total_timeout(0), Duration::from_secs(60));
        assert_eq!(
            peer_stream_total_timeout(10_000_000),
            Duration::from_secs(61)
        );
        assert_eq!(
            peer_stream_total_timeout(100_000_000),
            Duration::from_secs(70)
        );
    }

    #[tokio::test]
    async fn federate_stalled_winner_stream_aborts() {
        // Declares 1024 bytes, emits 8, then stalls past the 15s
        // production idle watchdog (spec-literal timing).
        let stalled = spawn_script_peer(
            "stall-blob",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 200,
                lookup_body: serde_json::Value::Null,
                download_bytes: b"01234567".to_vec(),
                digest_override: None,
                stall_declared_len: Some(1024),
            },
        )
        .await;
        let (state, dir) = requesting_state(vec![peer_for(&stalled, "stalled")], 1 << 20);
        let keys = vec!["k".to_string()];
        let start = std::time::Instant::now();
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        let elapsed = start.elapsed();
        assert_eq!(won, None);
        // Waited out the watchdog (early refusal would return in ms).
        assert!(elapsed >= Duration::from_secs(10), "took {elapsed:?}");
        assert_eq!(stalled.downloads.load(Ordering::SeqCst), 1);
        // Staging swept: no .tmp survives the abort.
        let tmps: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(tmps.is_empty(), "stale staging: {tmps:?}");
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_none());
        assert!(matches!(
            state.store.reserve(GLOBAL_SCOPE, "stall-blob", "v1"),
            Ok(crate::cache::store::ReserveOutcome::Created(_))
        ));
    }

    #[tokio::test]
    async fn federate_large_archive_streams_intact_with_digest() {
        // 8 MiB deterministic payload with a correct digest: proves
        // multi-megabyte buffered throughput plus verify-pass.
        let bytes: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let digest = hex_digest(&bytes);
        let big = spawn_script_peer(
            "big-blob",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 200,
                lookup_body: serde_json::Value::Null,
                download_bytes: bytes.clone(),
                digest_override: Some(digest.clone()),
                stall_declared_len: None,
            },
        )
        .await;
        let (state, _dir) = requesting_state(vec![peer_for(&big, "big")], 1 << 30);
        let keys = vec!["big-blob".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won.as_deref(), Some("big-blob"));
        let entry = state.store.lookup(GLOBAL_SCOPE, "v1", &keys).unwrap();
        assert_eq!(entry.size, bytes.len() as u64);
        assert_eq!(entry.sha256.as_deref(), Some(digest.as_str()));
    }

    #[tokio::test]
    async fn federate_wrong_digest_aborts() {
        let liar = spawn_script_peer(
            "liar-blob",
            ScriptPeerConfig {
                lookup_delay: Duration::ZERO,
                lookup_status: 200,
                lookup_body: serde_json::Value::Null,
                download_bytes: b"actual-bytes".to_vec(),
                digest_override: Some("f".repeat(64)),
                stall_declared_len: None,
            },
        )
        .await;
        let (state, _dir) = requesting_state(vec![peer_for(&liar, "liar")], 1 << 20);
        let keys = vec!["k".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won, None);
        assert!(state.store.lookup(GLOBAL_SCOPE, "v1", &keys).is_none());
        assert!(matches!(
            state.store.reserve(GLOBAL_SCOPE, "liar-blob", "v1"),
            Ok(crate::cache::store::ReserveOutcome::Created(_))
        ));
    }

    #[tokio::test]
    async fn federate_legacy_peer_without_digest_streams() {
        // No digest field at all: length checks still apply, digest
        // verification skips (pins the backward-compat contract).
        let legacy = spawn_script_peer("legacy-blob", hit_config(Duration::ZERO, b"LEGACY")).await;
        let (state, _dir) = requesting_state(vec![peer_for(&legacy, "legacy")], 1 << 20);
        let keys = vec!["legacy-blob".to_string()];
        let won = federate_lookup(&state, GLOBAL_SCOPE, "v1", &keys).await;
        assert_eq!(won.as_deref(), Some("legacy-blob"));
        let entry = state.store.lookup(GLOBAL_SCOPE, "v1", &keys).unwrap();
        assert_eq!(
            entry.sha256.as_deref(),
            Some(hex_digest(b"LEGACY").as_str())
        );
    }

    #[tokio::test]
    async fn resolver_snapshots_table_without_io() {
        use std::time::Instant;
        let table = MdnsCachePeerTable::new();
        let now = Instant::now();
        // Inactive rows never surface; actives do, capped per miss.
        let mut quiet = active_node("quiet", "10.0.0.9");
        quiet.metrics.as_mut().unwrap().cache_enabled = false;
        table.register_heartbeat(quiet, now);
        for i in 0..MAX_FEDERATION_PEERS + 3 {
            table.register_heartbeat(
                active_node(&format!("node-{i}"), &format!("10.0.0.{}", i + 10)),
                now,
            );
        }
        let resolver = MdnsPeerResolver::with_table(table);
        let peers = resolver.cache_peers().await;
        assert_eq!(peers.len(), MAX_FEDERATION_PEERS);
        assert!(peers.iter().all(|p| p.node_id.starts_with("node-")));
    }
}
