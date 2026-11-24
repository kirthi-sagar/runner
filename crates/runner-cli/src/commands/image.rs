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
/// image reference. When an auth store is supplied, the registry's
/// mapped forge device token (if any) authenticates the token
/// request; unmapped registries and store misses stay anonymous.
pub async fn pull_image(
    cache: &LayerCache,
    store: &ImageStore,
    image: &str,
    auth_store: Option<&runner_core::auth::store::AuthStore>,
) -> Result<PullOutcome, String> {
    use runner_sandbox::oci::{
        pull::ensure_image,
        registry::{OciReference, RegistryClient},
    };
    let reference = OciReference::parse(image)?;
    let mut client = RegistryClient::new();
    if let Some(auth) = auth_store {
        if let Some(key) = super::auth::registry_forge_key(&reference.registry) {
            if let Some(credential) = auth.load_forge(&key) {
                client = client.with_basic_auth(credential.username, credential.access_token);
            }
        }
    }
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
            crate::cache::format_bytes(image.size_bytes),
        ));
        for layer in &image.layers {
            out.push_str(&format!(
                "  {} {} {}\n",
                if layer.present { "cached" } else { "missing" },
                layer.digest,
                crate::cache::format_bytes(layer.size),
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

/// Prune candidates, collected without touching disk (shared by
/// real pruning and `--dry-run` inspection).
pub struct PruneTargets {
    pub blobs: Vec<std::path::PathBuf>,
    pub tmps: Vec<std::path::PathBuf>,
}

/// Collect unreferenced blobs plus stale staging files (older than
/// `grace`). Pure collection: callers decide removal vs preview.
pub fn collect_prune_targets(
    store: &ImageStore,
    cache: &LayerCache,
    grace: std::time::Duration,
) -> PruneTargets {
    PruneTargets {
        blobs: store.unreferenced_blobs(cache),
        tmps: cache.stale_tmps(grace),
    }
}

/// Human-readable dry-run inspection: what pruning would remove.
pub fn render_prune_preview(targets: &PruneTargets) -> String {
    let bytes: u64 = targets
        .blobs
        .iter()
        .chain(targets.tmps.iter())
        .map(|path| std::fs::metadata(path).map(|m| m.len()).unwrap_or(0))
        .sum();
    let mut out = format!(
        "would remove {} blobs and {} staging files ({})\n",
        targets.blobs.len(),
        targets.tmps.len(),
        crate::cache::format_bytes(bytes),
    );
    for path in targets.blobs.iter().chain(targets.tmps.iter()) {
        out.push_str(&format!("  {}\n", path.display()));
    }
    out
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
    let targets = collect_prune_targets(store, cache, grace);
    for path in &targets.blobs {
        remove(path, &mut outcome, true);
    }
    for path in &targets.tmps {
        remove(path, &mut outcome, false);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(outcome)
}

/// One image removal result inside a multi-target `rm`.
pub struct RemoveReport {
    pub reference: String,
    pub outcome: Result<runner_sandbox::oci::cache::RemoveOutcome, String>,
}

/// Remove each image in order, continuing past failures (docker
/// `rmi` semantics: every target attempted, the caller decides the
/// exit code from the collected errors).
pub fn remove_images(
    store: &ImageStore,
    cache: &LayerCache,
    references: &[String],
) -> Vec<RemoveReport> {
    references
        .iter()
        .map(|reference| RemoveReport {
            outcome: store.remove_image(cache, reference),
            reference: reference.clone(),
        })
        .collect()
}

/// Human-readable per-image removal line.
pub fn render_remove_text(report: &RemoveReport) -> String {
    match &report.outcome {
        Ok(outcome) => {
            let layers = if outcome.shared_preserved == 1 {
                "1 shared layer".to_string()
            } else {
                format!("{} shared layers", outcome.shared_preserved)
            };
            format!(
                "Removed image '{}' (reclaimed {}, preserved {}).\n",
                report.reference,
                crate::cache::format_bytes(outcome.bytes_reclaimed),
                layers,
            )
        }
        Err(e) => format!("Cannot remove '{}': {e}\n", report.reference),
    }
}

/// Interactive confirmation predicate: `y`/`yes` (any case,
/// surrounding whitespace ignored) proceed; anything else —
/// including EOF on piped stdin — skips (fail-closed default).
pub fn confirm_remove_line(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
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

    #[test]
    fn remove_multi_attempts_all_and_reports_each() {
        use runner_sandbox::oci::cache::{StoredLayer, StoredManifest};
        let (_dir, cache, store) = test_store("img-rm-multi");
        std::fs::create_dir_all(cache.dir()).unwrap();
        std::fs::write(cache.dir().join("a".repeat(64)), vec![1u8; 8]).unwrap();
        for reference in ["gone:1", "also-gone:1"] {
            store
                .write_manifest(
                    reference,
                    &StoredManifest {
                        reference: reference.to_string(),
                        manifest_digest: "sha256:eeee".to_string(),
                        layers: vec![StoredLayer {
                            digest: format!("sha256:{}", "a".repeat(64)),
                            size: 8,
                        }],
                        pulled_at_secs: 1,
                    },
                )
                .unwrap();
        }
        // Two hits plus one miss: every target attempted in order.
        let reports = remove_images(
            &store,
            &cache,
            &[
                "gone:1".to_string(),
                "ghost:1".to_string(),
                "also-gone:1".to_string(),
            ],
        );
        assert_eq!(reports.len(), 3);
        assert!(reports[0].outcome.is_ok());
        assert!(reports[1].outcome.is_err());
        assert!(reports[2].outcome.is_ok());
        // First removal preserved the shared blob; the second
        // reclaimed it (nothing references it anymore).
        assert!(!cache.dir().join("a".repeat(64)).exists());
        let ok = render_remove_text(&reports[0]);
        assert!(ok.contains("Removed image 'gone:1'"), "{ok}");
        assert!(ok.contains("preserved 1 shared layer"), "{ok}");
        let err = render_remove_text(&reports[1]);
        assert!(err.contains("Cannot remove 'ghost:1'"), "{err}");
    }

    #[test]
    fn prune_preview_lists_without_deleting() {
        let (_dir, cache, store) = test_store("img-dryrun");
        std::fs::create_dir_all(cache.dir()).unwrap();
        let orphan = "f".repeat(64);
        std::fs::write(cache.dir().join(&orphan), vec![1u8; 4]).unwrap();
        std::fs::write(cache.dir().join("old.tmp"), vec![2u8; 6]).unwrap();
        let targets = collect_prune_targets(&store, &cache, std::time::Duration::ZERO);
        assert_eq!(targets.blobs.len(), 1);
        assert_eq!(targets.tmps.len(), 1);
        let preview = render_prune_preview(&targets);
        assert!(preview.contains("would remove 1 blobs"), "{preview}");
        assert!(preview.contains("1 staging files"), "{preview}");
        assert!(preview.contains(&orphan), "{preview}");
        assert!(preview.contains("old.tmp"), "{preview}");
        // Nothing touched.
        assert!(cache.dir().join(&orphan).exists());
        assert!(cache.dir().join("old.tmp").exists());
        let empty = render_prune_preview(&PruneTargets {
            blobs: vec![],
            tmps: vec![],
        });
        assert!(empty.contains("would remove 0 blobs"), "{empty}");
    }

    #[test]
    fn confirm_accepts_only_affirmative() {
        for yes in ["y", "Y", "yes", "YES", "  y  "] {
            assert!(confirm_remove_line(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "yep", "ye", "yy"] {
            assert!(!confirm_remove_line(no), "{no:?}");
        }
    }
}
