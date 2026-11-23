//! `runner image`: pull, list, and prune OCI image layers in the
//! local cache. Thin layer over `runner-sandbox`'s registry client,
//! layer cache, and manifest store; rendering is pure for tests.

use runner_sandbox::oci::cache::{ImageStore, LayerCache};
use std::path::Path;

/// Stale-download grace for `prune`: staging files older than this
/// are crashed downloads (the grace keeps a concurrent pull's live
/// `.tmp` safe).
pub const PRUNE_TMP_GRACE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Open the layer cache and manifest store (explicit config dir or
/// the platform default).
pub fn open_store(cache_dir: Option<&Path>) -> (LayerCache, ImageStore) {
    let dir = cache_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(LayerCache::default_dir);
    let cache = LayerCache::new(dir);
    let store = ImageStore::new(cache.dir());
    (cache, store)
}

/// Outcome of one `runner image pull`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullOutcome {
    pub reference: String,
    pub manifest_digest: String,
    pub layers: usize,
    pub bytes: u64,
}

/// Resolve, download (missing layers only), verify, and record one
/// image reference.
pub async fn pull_image(
    cache: &LayerCache,
    store: &ImageStore,
    image: &str,
) -> Result<PullOutcome, String> {
    use runner_sandbox::oci::{
        pull::ensure_image,
        registry::{OciReference, RegistryClient},
    };
    let reference = OciReference::parse(image)?;
    let client = RegistryClient::new();
    let resolved = ensure_image(&client, cache, store, &reference).await?;
    Ok(PullOutcome {
        reference: reference.normalized(),
        manifest_digest: resolved.manifest_digest,
        layers: resolved.layers.len(),
        bytes: resolved.layers.iter().map(|layer| layer.size).sum(),
    })
}

/// One cached layer inside a listed image.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ListedLayer {
    pub digest: String,
    pub size: u64,
    /// Blob present on disk at the recorded size.
    pub present: bool,
}

/// One cached image record with on-disk presence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ListedImage {
    pub reference: String,
    pub manifest_digest: String,
    pub pulled_at_secs: u64,
    pub layers: Vec<ListedLayer>,
    /// Bytes on disk (present layers only).
    pub size_bytes: u64,
}

/// All cached image records, sorted by reference.
pub fn list_images(store: &ImageStore, cache: &LayerCache) -> Vec<ListedImage> {
    store
        .list_manifests()
        .into_iter()
        .map(|(reference, manifest)| {
            let layers: Vec<ListedLayer> = manifest
                .layers
                .into_iter()
                .map(|layer| {
                    let present = cache.contains(&layer.digest, layer.size);
                    ListedLayer {
                        digest: layer.digest,
                        size: layer.size,
                        present,
                    }
                })
                .collect();
            let size_bytes = layers
                .iter()
                .filter(|layer| layer.present)
                .map(|layer| layer.size)
                .sum();
            ListedImage {
                reference,
                manifest_digest: manifest.manifest_digest,
                pulled_at_secs: manifest.pulled_at_secs,
                layers,
                size_bytes,
            }
        })
        .collect()
}

/// Human-readable image listing.
pub fn render_list_text(images: &[ListedImage]) -> String {
    if images.is_empty() {
        return "no cached images\n".to_string();
    }
    let mut out = String::new();
    for image in images {
        out.push_str(&format!(
            "{} ({}, {})\n",
            image.reference,
            image.manifest_digest,
            super::cache::format_bytes(image.size_bytes),
        ));
        for layer in &image.layers {
            out.push_str(&format!(
                "  {} {} {}\n",
                if layer.present { "cached" } else { "missing" },
                layer.digest,
                super::cache::format_bytes(layer.size),
            ));
        }
    }
    out
}

/// JSON image listing.
pub fn render_list_json(images: &[ListedImage]) -> String {
    serde_json::to_string_pretty(images).unwrap_or_else(|_| "[]".to_string())
}

/// Outcome of one `runner image prune`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PruneOutcome {
    pub blobs_removed: usize,
    pub blobs_bytes: u64,
    pub tmps_removed: usize,
    pub tmps_bytes: u64,
}

/// Remove unreferenced layer blobs and stale staging files (older
/// than `grace`). Continues past individual removal failures but
/// reports the first one so skips never pass silently.
pub fn prune_cache(
    store: &ImageStore,
    cache: &LayerCache,
    grace: std::time::Duration,
) -> Result<PruneOutcome, String> {
    let mut outcome = PruneOutcome::default();
    let mut first_error: Option<String> = None;
    let mut remove = |path: &std::path::PathBuf, outcome: &mut PruneOutcome, is_blob: bool| {
        let bytes = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);
        match std::fs::remove_file(path) {
            Ok(()) => {
                if is_blob {
                    outcome.blobs_removed += 1;
                    outcome.blobs_bytes += bytes;
                } else {
                    outcome.tmps_removed += 1;
                    outcome.tmps_bytes += bytes;
                }
            }
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(format!("cannot remove {}: {e}", path.display()));
                }
            }
        }
    };
    for path in store.unreferenced_blobs(cache) {
        remove(&path, &mut outcome, true);
    }
    for path in cache.stale_tmps(grace) {
        remove(&path, &mut outcome, false);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(tag: &str) -> (runner_core::test_support::TempDir, LayerCache, ImageStore) {
        let dir = runner_core::test_support::TempDir::new(tag).unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        (dir, cache, store)
    }

    #[test]
    fn empty_cache_lists_and_renders() {
        let (_dir, cache, store) = test_store("img-empty");
        let images = list_images(&store, &cache);
        assert!(images.is_empty());
        assert_eq!(render_list_text(&images), "no cached images\n");
        assert_eq!(render_list_json(&images), "[]");
    }

    #[test]
    fn list_reports_presence_and_renders_both_formats() {
        use runner_sandbox::oci::cache::{StoredLayer, StoredManifest};
        let (_dir, cache, store) = test_store("img-list");
        // One present blob (exact size), one absent.
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        std::fs::create_dir_all(cache.dir()).unwrap();
        std::fs::write(cache.dir().join("a".repeat(64)), vec![7u8; 16]).unwrap();
        store
            .write_manifest(
                "example.com/app:1",
                &StoredManifest {
                    reference: "example.com/app:1".to_string(),
                    manifest_digest: "sha256:bbbb".to_string(),
                    layers: vec![
                        StoredLayer {
                            digest: digest.to_string(),
                            size: 16,
                        },
                        StoredLayer {
                            digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
                            size: 32,
                        },
                    ],
                    pulled_at_secs: 1,
                },
            )
            .unwrap();
        let images = list_images(&store, &cache);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].size_bytes, 16);
        assert!(images[0].layers[0].present);
        assert!(!images[0].layers[1].present);
        let text = render_list_text(&images);
        assert!(text.contains("example.com/app:1"), "{text}");
        assert!(text.contains("cached"), "{text}");
        assert!(text.contains("missing"), "{text}");
        assert!(text.contains(digest), "{text}");
        let json: serde_json::Value = serde_json::from_str(&render_list_json(&images)).unwrap();
        assert_eq!(json[0]["reference"], "example.com/app:1");
        assert_eq!(json[0]["size_bytes"], 16);
    }

    #[test]
    fn prune_removes_orphans_and_stale_tmps_only() {
        use runner_sandbox::oci::cache::{StoredLayer, StoredManifest};
        let (_dir, cache, store) = test_store("img-prune");
        std::fs::create_dir_all(cache.dir()).unwrap();
        // Referenced blob stays.
        let kept = "d".repeat(64);
        std::fs::write(cache.dir().join(&kept), vec![1u8; 8]).unwrap();
        store
            .write_manifest(
                "example.com/kept:1",
                &StoredManifest {
                    reference: "example.com/kept:1".to_string(),
                    manifest_digest: "sha256:eeee".to_string(),
                    layers: vec![StoredLayer {
                        digest: format!("sha256:{kept}"),
                        size: 8,
                    }],
                    pulled_at_secs: 1,
                },
            )
            .unwrap();
        // Orphan blob + staging tmp go (zero grace: test tmps are fresh).
        let orphan = "e".repeat(64);
        std::fs::write(cache.dir().join(&orphan), vec![2u8; 4]).unwrap();
        std::fs::write(cache.dir().join("deadbeef.tmp"), vec![3u8; 6]).unwrap();
        let outcome = prune_cache(&store, &cache, std::time::Duration::ZERO).unwrap();
        assert_eq!(
            outcome,
            PruneOutcome {
                blobs_removed: 1,
                blobs_bytes: 4,
                tmps_removed: 1,
                tmps_bytes: 6,
            }
        );
        assert!(cache.dir().join(&kept).exists());
        assert!(!cache.dir().join(&orphan).exists());
        assert!(!cache.dir().join("deadbeef.tmp").exists());
        // Second prune is a no-op.
        let outcome = prune_cache(&store, &cache, std::time::Duration::ZERO).unwrap();
        assert_eq!(outcome, PruneOutcome::default());
    }

    #[test]
    fn prune_honors_tmp_grace() {
        let (_dir, cache, store) = test_store("img-grace");
        std::fs::create_dir_all(cache.dir()).unwrap();
        std::fs::write(cache.dir().join("live.tmp"), vec![9u8; 2]).unwrap();
        let outcome = prune_cache(&store, &cache, std::time::Duration::from_secs(3600)).unwrap();
        assert_eq!(outcome.tmps_removed, 0);
        assert!(cache.dir().join("live.tmp").exists());
    }
}
