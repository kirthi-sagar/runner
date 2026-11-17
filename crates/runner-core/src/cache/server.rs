//! Actions Cache proxy server (`/_apis/artifactcache/`).
//!
//! Speaks the protocol `actions/cache` expects (verified against
//! `@actions/cache`'s `cacheHttpClient`/`downloadUtils`): lookup with
//! restore-key fallbacks, numeric-id reserve/chunk/commit upload, and
//! archive download with HEAD + Range support. Loopback-only by
//! default; Bearer auth enforced everywhere except the artifact
//! download (the client's downloader sends no credentials).

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use std::collections::HashMap;

use super::store::{CacheStore, ReserveOutcome, StoreError};

/// Fixed loopback token the daemon injects into workers as
/// `ACTIONS_RUNTIME_TOKEN`.
pub const CACHE_RUNTIME_TOKEN: &str = "local-runner-cache-token";
/// Worker-facing cache endpoint variable.
pub const ACTIONS_CACHE_URL_ENV: &str = "ACTIONS_CACHE_URL";
/// Worker-facing cache credential variable.
pub const ACTIONS_RUNTIME_TOKEN_ENV: &str = "ACTIONS_RUNTIME_TOKEN";

/// Env pairs injected into GitHub workers when the proxy is up. The
/// URL carries exactly one trailing slash (the client appends
/// `_apis/artifactcache/...` directly).
pub fn worker_env(base_url: &str) -> Vec<(String, String)> {
    vec![
        (
            ACTIONS_CACHE_URL_ENV.to_string(),
            format!("{}/", base_url.trim_end_matches('/')),
        ),
        (
            ACTIONS_RUNTIME_TOKEN_ENV.to_string(),
            CACHE_RUNTIME_TOKEN.to_string(),
        ),
    ]
}

/// Shared server state (cloneable handle).
#[derive(Clone)]
pub struct CacheServerState {
    pub store: CacheStore,
    /// Public base URL advertised in `archiveLocation` (loopback).
    pub public_base: String,
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|token| token == CACHE_RUNTIME_TOKEN)
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
    if !authorized(&headers) {
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
        Some(entry) => Json(serde_json::json!({
            "cacheKey": entry.key,
            "archiveLocation": format!(
                "{}/_apis/artifactcache/artifacts/{}",
                state.public_base, entry.id
            ),
        }))
        .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// `POST caches {key, version}` → 201 `{cacheId}` or 409 when present.
async fn reserve_cache(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    if !authorized(&headers) {
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

/// `PATCH caches/{id}` chunk upload (explicit offsets; out-of-order safe).
/// The body streams straight to disk: no size cap, no full buffering.
async fn upload_chunk(
    State(state): State<CacheServerState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    body: axum::body::Body,
) -> axum::response::Response {
    use futures_util::TryStreamExt;

    if !authorized(&headers) {
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
        if let Err(e) = state.store.write_chunk(id, offset, &chunk) {
            return store_upload_error(id, e);
        }
        offset += chunk.len() as u64;
        received += chunk.len() as u64;
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
    if !authorized(&headers) {
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
    Path(id): Path<u64>,
    method: Method,
    headers: HeaderMap,
) -> axum::response::Response {
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
    axum::serve(listener, router(state)).await?;
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
        let env = worker_env("http://127.0.0.1:8787");
        assert_eq!(env[0].0, "ACTIONS_CACHE_URL");
        assert_eq!(env[0].1, "http://127.0.0.1:8787/");
        assert_eq!(
            env[1],
            (
                "ACTIONS_RUNTIME_TOKEN".to_string(),
                CACHE_RUNTIME_TOKEN.to_string()
            )
        );
        let env = worker_env("http://127.0.0.1:8787/");
        assert_eq!(env[0].1, "http://127.0.0.1:8787/");
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
