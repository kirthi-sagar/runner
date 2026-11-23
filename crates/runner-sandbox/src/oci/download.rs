//! Streaming OCI blob downloads: bearer-authed chunk streaming
//! with an idle watchdog, in-flight SHA-256 verification, and atomic
//! commit into the [`LayerCache`]. Digest mismatches fail closed and
//! scrub the staging file.

use super::cache::LayerCache;
use super::registry::{OciReference, RegistryClient};

/// Idle watchdog: no chunk bytes for 15s aborts the blob transfer.
/// (No total timeout by design: the job-level timeout bounds the
/// whole pull, and layers legitimately stream for minutes.)
pub const BLOB_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Staging write buffer (matches the cache pump).
const STAGE_BUF_BYTES: usize = 64 * 1024;

/// Fetch one blob into the cache, verifying bytes + digest + size.
/// Cache hits return without touching the network; every failure
/// leaves no staging file behind.
pub async fn download_blob(
    client: &RegistryClient,
    reference: &OciReference,
    digest: &str,
    expected_size: u64,
    cache: &LayerCache,
) -> Result<std::path::PathBuf, String> {
    if cache.contains(digest, expected_size) {
        return cache.path_for(digest);
    }
    cache.ensure_dir()?;
    let tmp = cache.tmp_path(digest)?;
    let outcome = download_blob_inner(
        client,
        reference,
        digest,
        expected_size,
        cache,
        &tmp,
        BLOB_CHUNK_TIMEOUT,
    )
    .await;
    match outcome {
        Ok(path) => Ok(path),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

async fn download_blob_inner(
    client: &RegistryClient,
    reference: &OciReference,
    digest: &str,
    expected_size: u64,
    cache: &LayerCache,
    tmp: &std::path::Path,
    chunk_timeout: std::time::Duration,
) -> Result<std::path::PathBuf, String> {
    use sha2::Digest;
    use tokio::io::AsyncWriteExt;

    let url = format!(
        "{}://{}/v2/{}/blobs/{}",
        reference.scheme(),
        reference.registry,
        reference.repository,
        digest
    );
    let mut response = client.get_blob(&url).await?;
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(tmp)
        .await
        .map_err(|e| format!("cannot stage blob {}: {e}", tmp.display()))?;
    let mut writer = tokio::io::BufWriter::with_capacity(STAGE_BUF_BYTES, file);
    let mut hasher = sha2::Sha256::new();
    let mut staged: u64 = 0;
    loop {
        let chunk = match tokio::time::timeout(chunk_timeout, response.chunk()).await {
            Ok(Ok(Some(bytes))) => bytes,
            Ok(Ok(None)) => break,
            Ok(Err(e)) => return Err(format!("blob stream failed: {e}")),
            Err(_) => {
                return Err(format!(
                    "blob stream stalled: no bytes for {chunk_timeout:?}"
                ))
            }
        };
        hasher.update(&chunk);
        writer
            .write_all(&chunk)
            .await
            .map_err(|e| format!("cannot stage blob {}: {e}", tmp.display()))?;
        staged = staged.saturating_add(chunk.len() as u64);
    }
    writer
        .flush()
        .await
        .map_err(|e| format!("cannot stage blob {}: {e}", tmp.display()))?;
    drop(writer);
    if staged != expected_size {
        return Err(format!(
            "blob size mismatch: got {staged} bytes, manifest declares {expected_size}"
        ));
    }
    let actual = format!("{:x}", hasher.finalize());
    let want = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("invalid blob digest '{digest}'"))?;
    if actual != want {
        return Err(format!(
            "blob digest mismatch for {digest} (stream hashed to sha256:{actual})"
        ));
    }
    cache.commit_tmp(tmp, digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Scripted blob endpoint: which digest it serves, what bytes,
    /// whether it stalls, whether it demands a bearer token.
    #[derive(Clone)]
    struct BlobScript {
        digest: String,
        body: Vec<u8>,
        stall_after: Option<usize>,
        require_auth: bool,
    }

    struct MockBlobs {
        base: String,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn respond(sock: &mut tokio::net::TcpStream, head: &str, body: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let _ = sock
            .write_all(
                format!(
                    "{head}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        let _ = sock.write_all(body).await;
    }

    async fn spawn_mock_blobs(script: BlobScript) -> MockBlobs {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("127.0.0.1:{port}");
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = hits.clone();
        let challenge_base = base.clone();
        tokio::spawn(async move {
            let base = challenge_base;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
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
                let head = String::from_utf8_lossy(&head).to_string();
                if head.contains("GET /token") {
                    respond(
                        &mut sock,
                        "HTTP/1.1 200 OK",
                        br#"{"token":"mock-blob-token"}"#,
                    )
                    .await;
                    continue;
                }
                let blob_path = format!("/blobs/{}", script.digest);
                if !head.contains(&blob_path) {
                    respond(&mut sock, "HTTP/1.1 404 Not Found", b"").await;
                    continue;
                }
                served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if script.require_auth
                    && !head.to_ascii_lowercase().contains("authorization: bearer ")
                {
                    respond(
                        &mut sock,
                        &format!("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"http://{base}/token\",scope=\"repository:library/blob:pull\""),
                        b"",
                    )
                    .await;
                    continue;
                }
                // Declared length is the FULL body even when stalling.
                let prefix = match script.stall_after {
                    Some(n) => &script.body[..n.min(script.body.len())],
                    None => &script.body[..],
                };
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close",
                    script.body.len()
                );
                let _ = sock.write_all(format!("{head}\r\n\r\n").as_bytes()).await;
                let _ = sock.write_all(prefix).await;
                if script.stall_after.is_some() {
                    // Stall past any test watchdog; teardown drops us.
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                }
            }
        });
        MockBlobs { base, hits }
    }

    fn blob_ref(base: &str) -> OciReference {
        OciReference::parse(&format!("{base}/library/blob:latest")).unwrap()
    }

    fn test_cache(dir: &std::path::Path) -> LayerCache {
        LayerCache::new(dir.join("layers"))
    }

    #[tokio::test]
    async fn download_commits_verified_blob() {
        let dir = runner_core::test_support::TempDir::new("blob-ok").unwrap();
        let body = vec![9u8; 4096];
        let digest = sha256_hex(&body);
        let blobs = spawn_mock_blobs(BlobScript {
            digest: digest.clone(),
            body: body.clone(),
            stall_after: None,
            require_auth: true,
        })
        .await;
        let cache = test_cache(dir.path());
        let path = download_blob(
            &RegistryClient::new(),
            &blob_ref(&blobs.base),
            &digest,
            body.len() as u64,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), body);
        // Staging file is gone (renamed, not copied).
        assert!(!cache.tmp_path(&digest).unwrap().exists());
        // Two blob hits: the 401 probe plus the authed fetch.
        assert_eq!(blobs.hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cache_hit_skips_network_entirely() {
        let dir = runner_core::test_support::TempDir::new("blob-hit").unwrap();
        let body = vec![7u8; 1024];
        let digest = sha256_hex(&body);
        let blobs = spawn_mock_blobs(BlobScript {
            digest: digest.clone(),
            body: body.clone(),
            stall_after: None,
            require_auth: false,
        })
        .await;
        let cache = test_cache(dir.path());
        // First fetch populates...
        download_blob(
            &RegistryClient::new(),
            &blob_ref(&blobs.base),
            &digest,
            body.len() as u64,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(blobs.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        // ...second fetch never touches the socket.
        let path = download_blob(
            &RegistryClient::new(),
            &blob_ref(&blobs.base),
            &digest,
            body.len() as u64,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), body);
        assert_eq!(blobs.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Wrong size is NOT a hit (truncated impostor re-downloads).
        assert!(!cache.contains(&digest, body.len() as u64 + 1));
    }

    #[tokio::test]
    async fn digest_mismatch_fails_closed_and_scrubs_tmp() {
        let dir = runner_core::test_support::TempDir::new("blob-liar").unwrap();
        // Serve bytes whose hash differs from the declared digest.
        let body = vec![1u8; 512];
        let declared = sha256_hex(&[2u8; 512]);
        let blobs = spawn_mock_blobs(BlobScript {
            digest: declared.clone(),
            body: body.clone(),
            stall_after: None,
            require_auth: false,
        })
        .await;
        let cache = test_cache(dir.path());
        let err = download_blob(
            &RegistryClient::new(),
            &blob_ref(&blobs.base),
            &declared,
            body.len() as u64,
            &cache,
        )
        .await
        .unwrap_err();
        assert!(err.contains("digest mismatch"), "{err}");
        assert!(!cache.tmp_path(&declared).unwrap().exists());
        assert!(cache.path_for(&declared).is_ok());
        assert!(!cache.path_for(&declared).unwrap().exists());
    }

    #[tokio::test]
    async fn short_stream_fails_on_size_before_hash() {
        let dir = runner_core::test_support::TempDir::new("blob-short").unwrap();
        let body = vec![3u8; 256];
        let digest = sha256_hex(&body);
        let blobs = spawn_mock_blobs(BlobScript {
            digest: digest.clone(),
            body,
            stall_after: None,
            require_auth: false,
        })
        .await;
        let cache = test_cache(dir.path());
        // Manifest claims more than the server sends.
        let err = download_blob(
            &RegistryClient::new(),
            &blob_ref(&blobs.base),
            &digest,
            512,
            &cache,
        )
        .await
        .unwrap_err();
        assert!(err.contains("size mismatch"), "{err}");
        assert!(!cache.tmp_path(&digest).unwrap().exists());
    }

    #[tokio::test]
    async fn watchdog_fires_on_mid_body_stall() {
        let dir = runner_core::test_support::TempDir::new("blob-stall").unwrap();
        let body = vec![5u8; 2048];
        let digest = sha256_hex(&body);
        let blobs = spawn_mock_blobs(BlobScript {
            digest: digest.clone(),
            body,
            stall_after: Some(128),
            require_auth: false,
        })
        .await;
        let cache = test_cache(dir.path());
        cache.ensure_dir().unwrap();
        let tmp = cache.tmp_path(&digest).unwrap();
        let client = RegistryClient::new();
        let reference = blob_ref(&blobs.base);
        // Scaled watchdog (production uses 15s; the mechanism is identical).
        let start = std::time::Instant::now();
        let err = download_blob_inner(
            &client,
            &reference,
            &digest,
            2048,
            &cache,
            &tmp,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        let elapsed = start.elapsed();
        assert!(err.contains("stalled"), "{err}");
        // Waited the full budget mid-stream (never failed fast on the
        // valid prefix) and never hung on the silence after it.
        assert!(
            elapsed >= std::time::Duration::from_millis(90),
            "{elapsed:?}"
        );
        assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
    }

    #[tokio::test]
    async fn missing_blob_maps_404_cleanly() {
        let dir = runner_core::test_support::TempDir::new("blob-404").unwrap();
        let body = vec![6u8; 64];
        let served = sha256_hex(&body);
        let blobs = spawn_mock_blobs(BlobScript {
            digest: served,
            body,
            stall_after: None,
            require_auth: false,
        })
        .await;
        let cache = test_cache(dir.path());
        let missing = sha256_hex(&[0u8; 64]);
        let err = download_blob(
            &RegistryClient::new(),
            &blob_ref(&blobs.base),
            &missing,
            64,
            &cache,
        )
        .await
        .unwrap_err();
        assert!(err.contains("not found"), "{err}");
        assert!(!cache.tmp_path(&missing).unwrap().exists());
    }
}
