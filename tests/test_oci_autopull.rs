//! Phase 4 end-to-end: auto-pull through a loopback mock registry
//! (launch wiring, MCP agent path, and `runner image` lib surface).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn hex_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        sum.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// One gzip layer holding a single file.
fn make_layer(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut tar_buf = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut tar_buf);
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, contents).unwrap();
        tar.into_inner().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    use std::io::Write;
    gz.write_all(&tar_buf).unwrap();
    gz.finish().unwrap()
}

struct MockRegistry {
    base: String,
    blob_hits: Arc<AtomicUsize>,
}

async fn respond_bytes(sock: &mut tokio::net::TcpStream, status: &str, extra: &str, body: &[u8]) {
    use tokio::io::AsyncWriteExt;
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
        body.len()
    );
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(body).await;
}

/// Loopback registry serving one two-layer image (no auth dance:
/// anonymous 200s exercise resolve + download + unpack).
async fn spawn_mock_registry() -> MockRegistry {
    let layer_one = make_layer("autopull-marker.txt", b"pulled");
    let layer_two = make_layer("nested/second.txt", b"stacked");
    let digest_one = hex_digest(&layer_one);
    let digest_two = hex_digest(&layer_two);
    let size_one = layer_one.len() as u64;
    let size_two = layer_two.len() as u64;
    let amd64 = format!("sha256:{}", "a".repeat(64));
    let arm64 = format!("sha256:{}", "b".repeat(64));
    let config = format!("sha256:{}", "c".repeat(64));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("127.0.0.1:{port}");
    let blob_hits = Arc::new(AtomicUsize::new(0));
    let served = blob_hits.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
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
            if head.contains("/manifests/test") {
                let body = serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                         "digest": amd64, "size": 500,
                         "platform": {"os": "linux", "architecture": "amd64"}},
                        {"mediaType": "application/vnd.oci.image.manifest.v1+json",
                         "digest": arm64, "size": 500,
                         "platform": {"os": "linux", "architecture": "arm64"}},
                    ],
                })
                .to_string();
                respond_bytes(&mut sock, "200 OK", "", body.as_bytes()).await;
            } else if head.contains(&amd64) || head.contains(&arm64) {
                let body = serde_json::json!({
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                               "digest": config, "size": 100},
                    "layers": [
                        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                         "digest": digest_one, "size": size_one},
                        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                         "digest": digest_two, "size": size_two},
                    ],
                })
                .to_string();
                respond_bytes(&mut sock, "200 OK", "", body.as_bytes()).await;
            } else if head.contains(&digest_one) {
                served.fetch_add(1, Ordering::SeqCst);
                respond_bytes(&mut sock, "200 OK", "", &layer_one).await;
            } else if head.contains(&digest_two) {
                served.fetch_add(1, Ordering::SeqCst);
                respond_bytes(&mut sock, "200 OK", "", &layer_two).await;
            } else {
                respond_bytes(&mut sock, "404 Not Found", "", b"").await;
            }
        }
    });
    MockRegistry { base, blob_hits }
}

/// Launch with auto-pull: the shim exits 7 only when both layer
/// files land in the bundle rootfs (unpack proof through the real
/// launch path, torn down afterwards).
#[cfg(unix)]
#[tokio::test]
async fn auto_pull_launch_unpacks_layers_into_bundle() {
    use runner_sandbox::oci::{execute_container_captured, ContainerLaunch};

    let registry = spawn_mock_registry().await;
    let dir = runner_core::test_support::TempDir::new("oci-autopull").unwrap();
    let shim = dir.path().join("bundle-rt");
    std::fs::write(
        &shim,
        "#!/bin/sh\ntest -f \"$3/rootfs/autopull-marker.txt\" && test -f \"$3/rootfs/nested/second.txt\" && exit 7\nexit 9\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

    let launch = ContainerLaunch {
        runtime_override: Some(shim),
        command: vec!["true".to_string()],
        timeout: std::time::Duration::from_secs(60),
        image: format!("{}/e2e:test", registry.base),
        auto_pull: true,
        layer_cache_dir: Some(dir.path().join("layers")),
        ..ContainerLaunch::default()
    };
    let out = execute_container_captured(launch).await.unwrap();
    assert_eq!(
        out.code,
        7,
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    // Both layers fetched exactly once.
    assert_eq!(registry.blob_hits.load(Ordering::SeqCst), 2);
}

/// MCP agent path: the shim cats the unpacked marker, so captured
/// stdout proves pull + unpack through `exec_command`.
#[cfg(unix)]
#[tokio::test]
async fn agent_exec_auto_pulls_through_mock_registry() {
    use runner_cli::agent::CliAgentTools;
    use runner_core::config::RunnerConfig;
    use runner_core::mcp::tools::{AgentTools, ExecRequest};

    let registry = spawn_mock_registry().await;
    let dir = runner_core::test_support::TempDir::new("oci-agent-pull").unwrap();
    let shim = dir.path().join("cat-rt");
    std::fs::write(&shim, "#!/bin/sh\ncat \"$3/rootfs/autopull-marker.txt\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut config = RunnerConfig::default();
    config.sandbox.container.runtime_path = Some(shim);
    config.sandbox.container.cache_dir = Some(dir.path().join("layers"));
    assert!(config.sandbox.container.auto_pull);
    let agent = CliAgentTools::new(config);
    let out = agent
        .exec(ExecRequest {
            command: vec!["true".to_string()],
            timeout_secs: 60,
            env: vec![],
            driver: "container".to_string(),
            image: Some(format!("{}/e2e:test", registry.base)),
            no_network: false,
            volumes: vec![],
        })
        .await
        .unwrap();
    assert_eq!(out["code"], 0);
    assert!(
        out["stdout"]
            .as_str()
            .unwrap_or_default()
            .contains("pulled"),
        "{out}"
    );
}

/// `runner image` lib surface: pull, list (presence + usage), and
/// prune (orphans go, referenced stay); the second pull downloads
/// nothing.
#[tokio::test]
async fn image_pull_list_prune_roundtrip() {
    use runner_cli::image::{list_images, open_store, prune_cache, pull_image};

    let registry = spawn_mock_registry().await;
    let dir = runner_core::test_support::TempDir::new("oci-image-cli").unwrap();
    let (cache, store) = open_store(Some(dir.path()));
    let image = format!("{}/e2e:test", registry.base);

    let outcome = pull_image(&cache, &store, &image).await.unwrap();
    assert!(outcome.reference.contains("e2e"), "{}", outcome.reference);
    assert_eq!(outcome.layers, 2);
    assert!(outcome.bytes > 0);
    // Second pull resolves again but downloads nothing.
    pull_image(&cache, &store, &image).await.unwrap();
    assert_eq!(registry.blob_hits.load(Ordering::SeqCst), 2);

    let listed = list_images(&store, &cache);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].layers.len(), 2);
    assert!(listed[0].layers.iter().all(|layer| layer.present));
    assert_eq!(listed[0].size_bytes, outcome.bytes);
    let text = runner_cli::image::render_list_text(&listed);
    assert!(text.contains("e2e"), "{text}");
    let json: serde_json::Value =
        serde_json::from_str(&runner_cli::image::render_list_json(&listed)).unwrap();
    assert_eq!(json[0]["layers"].as_array().unwrap().len(), 2);

    // Prune with a live record: nothing referenced goes.
    let outcome = prune_cache(&store, &cache, std::time::Duration::ZERO).unwrap();
    assert_eq!(outcome.blobs_removed, 0);
    // Planted orphan + stale tmp go.
    std::fs::write(cache.dir().join("f".repeat(64)), vec![1u8; 4]).unwrap();
    std::fs::write(cache.dir().join("crash.tmp"), vec![2u8; 6]).unwrap();
    let outcome = prune_cache(&store, &cache, std::time::Duration::ZERO).unwrap();
    assert_eq!(outcome.blobs_removed, 1);
    assert_eq!(outcome.blobs_bytes, 4);
    assert_eq!(outcome.tmps_removed, 1);
    assert_eq!(outcome.tmps_bytes, 6);
    assert_eq!(list_images(&store, &cache).len(), 1);
}

/// Bad references fail closed before any network traffic.
#[tokio::test]
async fn image_pull_rejects_bad_reference() {
    use runner_cli::image::{open_store, pull_image};

    let registry = spawn_mock_registry().await;
    let dir = runner_core::test_support::TempDir::new("oci-image-badref").unwrap();
    let (cache, store) = open_store(Some(dir.path()));
    let err = pull_image(&cache, &store, ":::").await.unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(registry.blob_hits.load(Ordering::SeqCst), 0);
}
