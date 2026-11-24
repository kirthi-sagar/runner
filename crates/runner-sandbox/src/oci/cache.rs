//! Content-addressed OCI layer cache: verified blobs land here
//! under their hex digests, so repeat pulls never touch the network.
//! Corrupt or partial files fail the hit check and re-download.

use std::path::{Path, PathBuf};

/// Safety signpost planted at the cache root: reassures humans (and
/// disk cleaners) that the directory is disposable cache.
pub const CACHE_SIGNPOST_NAME: &str = "README_SAFE_TO_DELETE.txt";

/// Signpost body: what lives here, why deletion is safe, and how
/// runner self-heals afterwards.
pub const CACHE_SIGNPOST_BODY: &str = "\
This directory is runner's container layer cache.

It holds downloaded container image layer blobs (content-addressed
files named by their SHA-256 digests) plus small per-image manifest
records. runner reads them to launch containers without
re-downloading images it already fetched.

SAFE TO DELETE: you may delete this entire directory at any time to
reclaim disk space. Deleting it will never harm your operating
system, break runner, or delete any of your personal files or code.

runner automatically re-downloads any layer it still needs the next
time you run a container. Nothing stored here is irreplaceable.
";

/// Plant the safety signpost when absent (never clobbers existing
/// content; fails closed so disk problems surface at bootstrap
/// instead of mid-download).
fn ensure_signpost(cache_root: &Path) -> Result<(), String> {
    let signpost = cache_root.join(CACHE_SIGNPOST_NAME);
    if signpost.exists() {
        return Ok(());
    }
    std::fs::write(&signpost, CACHE_SIGNPOST_BODY)
        .map_err(|e| format!("cannot write cache signpost {}: {e}", signpost.display()))
}

/// Content-addressed blob store rooted at one directory.
#[derive(Debug, Clone)]
pub struct LayerCache {
    dir: PathBuf,
}

impl LayerCache {
    /// Cache rooted at an explicit directory (config overrides feed
    /// this constructor; see [`default_dir`](Self::default_dir)).
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Default root: `$XDG_CACHE_HOME/runner/layers`, else
    /// `~/.cache/runner/layers` (`%LOCALAPPDATA%/runner/layers` on
    /// Windows, `%APPDATA%` fallback).
    pub fn default_dir() -> PathBuf {
        #[cfg(unix)]
        {
            if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|dir| !dir.is_empty()) {
                return PathBuf::from(xdg).join("runner").join("layers");
            }
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home)
                    .join(".cache")
                    .join("runner")
                    .join("layers");
            }
            PathBuf::from(".runner-layers")
        }
        #[cfg(not(unix))]
        {
            for key in ["LOCALAPPDATA", "APPDATA"] {
                if let Some(dir) = std::env::var_os(key) {
                    return PathBuf::from(dir).join("runner").join("layers");
                }
            }
            PathBuf::from(".runner-layers")
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Create the cache root (idempotent; call before staging)
    /// and plant the safety signpost when absent, so a manually
    /// deleted cache self-heals on the next bootstrap.
    pub fn ensure_dir(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create layer cache {}: {e}", self.dir.display()))?;
        ensure_signpost(&self.dir)
    }

    /// Hex portion of a `sha256:<hex>` digest (shape-checked).
    fn hex_of(digest: &str) -> Result<&str, String> {
        if digest.len() == 7 + 64
            && digest.starts_with("sha256:")
            && digest[7..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            Ok(&digest[7..])
        } else {
            Err(format!(
                "invalid layer digest '{digest}' (want sha256:<64 hex>)"
            ))
        }
    }

    /// Final resting path for one blob: `<dir>/<hex>`.
    pub fn path_for(&self, digest: &str) -> Result<PathBuf, String> {
        Ok(self.dir.join(Self::hex_of(digest)?))
    }

    /// Ephemeral download path, removed on any failure.
    pub fn tmp_path(&self, digest: &str) -> Result<PathBuf, String> {
        Ok(self.dir.join(format!("{}.tmp", Self::hex_of(digest)?)))
    }

    /// Hit check: the blob exists with exactly the declared size.
    /// Content hashes verify at download time, so a size match on an
    /// intact filesystem is a valid hit; anything else re-downloads.
    pub fn contains(&self, digest: &str, expected_size: u64) -> bool {
        let Ok(path) = self.path_for(digest) else {
            return false;
        };
        std::fs::metadata(&path)
            .map(|meta| meta.is_file() && meta.len() == expected_size)
            .unwrap_or(false)
    }

    /// Atomically install a verified staging file (same-directory
    /// rename; the caller verified bytes and digest first).
    pub fn commit_tmp(&self, tmp: &Path, digest: &str) -> Result<PathBuf, String> {
        let path = self.path_for(digest)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create layer cache {}: {e}", parent.display()))?;
        }
        std::fs::rename(tmp, &path)
            .map_err(|e| format!("cannot commit layer {}: {e}", path.display()))?;
        Ok(path)
    }

    /// Staging files older than `grace` (crashed downloads; the grace
    /// keeps a concurrent pull's live `.tmp` safe).
    pub fn stale_tmps(&self, grace: std::time::Duration) -> Vec<PathBuf> {
        let mut stale = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return stale;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_tmp = path.extension().is_some_and(|ext| ext == "tmp");
            if !is_tmp {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .map(|modified| modified.elapsed().unwrap_or_default() > grace)
                .unwrap_or(false);
            if old {
                stale.push(path);
            }
        }
        stale
    }
}

/// One cached layer entry inside a stored manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredLayer {
    pub digest: String,
    pub size: u64,
}

/// Resolved image record: which manifest a reference pulled, and the
/// layers it needs. Written on every pull (tags are mutable, so the
/// record always reflects the last resolution).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredManifest {
    pub reference: String,
    pub manifest_digest: String,
    pub layers: Vec<StoredLayer>,
    pub pulled_at_secs: u64,
}

/// Per-image manifest records under `<cache>/images/`, keyed by
/// percent-escaped reference (injective: distinct refs never share
/// a file).
#[derive(Debug, Clone)]
pub struct ImageStore {
    dir: PathBuf,
}

/// Percent-escape a reference into a safe filename (unreserved bytes
/// pass through; everything else becomes `%XX`, `%` first).
fn escape_ref(reference: &str) -> String {
    let mut out = String::with_capacity(reference.len());
    for byte in reference.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

impl ImageStore {
    pub fn new(cache_dir: &Path) -> Self {
        Self {
            dir: cache_dir.join("images"),
        }
    }

    pub fn manifest_path(&self, reference: &str) -> PathBuf {
        self.dir.join(format!("{}.json", escape_ref(reference)))
    }

    /// Read one record (`None` when missing or corrupt — caches are
    /// disposable, so corruption self-heals on the next pull).
    pub fn read_manifest(&self, reference: &str) -> Option<StoredManifest> {
        let bytes = std::fs::read(self.manifest_path(reference)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn write_manifest(&self, reference: &str, manifest: &StoredManifest) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create image store {}: {e}", self.dir.display()))?;
        // The store bootstrap creates the cache root as a side
        // effect (parent chain), so it plants the signpost too.
        if let Some(root) = self.dir.parent() {
            ensure_signpost(root)?;
        }
        let bytes = serde_json::to_string_pretty(manifest)
            .map_err(|e| format!("cannot encode manifest: {e}"))?;
        std::fs::write(self.manifest_path(reference), bytes)
            .map_err(|e| format!("cannot write manifest: {e}"))
    }

    /// All readable records (corrupt files skipped).
    pub fn list_manifests(&self) -> Vec<(String, StoredManifest)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(manifest) = serde_json::from_slice::<StoredManifest>(&bytes) {
                        out.push((manifest.reference.clone(), manifest));
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Layer blobs on disk that no manifest record references.
    pub fn unreferenced_blobs(&self, cache: &LayerCache) -> Vec<PathBuf> {
        use std::collections::HashSet;
        let mut referenced = HashSet::new();
        for (_, manifest) in self.list_manifests() {
            for layer in manifest.layers {
                referenced.insert(layer.digest);
            }
        }
        let mut orphaned = Vec::new();
        let Ok(entries) = std::fs::read_dir(cache.dir()) else {
            return orphaned;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            // 64 lowercase hex chars with no extension: a layer blob.
            let is_blob = name.len() == 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
                && path.extension().is_none();
            if !is_blob {
                continue;
            }
            if !referenced.contains(&format!("sha256:{name}")) {
                orphaned.push(path);
            }
        }
        orphaned.sort();
        orphaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> String {
        format!("sha256:{}", "c".repeat(64))
    }

    #[test]
    fn default_dir_is_layers_suffixed() {
        // Env-dependent root, stable suffix on every platform.
        let dir = LayerCache::default_dir();
        assert!(dir.ends_with(Path::new("runner").join("layers")), "{dir:?}");
    }

    #[test]
    fn paths_derive_from_hex_and_reject_garbage() {
        let cache = LayerCache::new(PathBuf::from("/tmp/layers"));
        let path = cache.path_for(&digest()).unwrap();
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "c".repeat(64));
        let tmp = cache.tmp_path(&digest()).unwrap();
        assert!(tmp.to_string_lossy().ends_with(".tmp"));
        for bad in ["", "sha256:xyz", "md5:00", "not-a-digest"] {
            assert!(cache.path_for(bad).is_err(), "{bad}");
            assert!(cache.tmp_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn contains_checks_existence_and_size() {
        let dir = runner_core::test_support::TempDir::new("layer-hit").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let digest = digest();
        // Missing: no hit.
        assert!(!cache.contains(&digest, 4));
        // Present but wrong size: no hit (truncated impostor).
        cache.ensure_dir().unwrap();
        std::fs::write(cache.path_for(&digest).unwrap(), b"xy").unwrap();
        assert!(!cache.contains(&digest, 4));
        // Exact: hit. Invalid digests never hit.
        std::fs::write(cache.path_for(&digest).unwrap(), b"wxyz").unwrap();
        assert!(cache.contains(&digest, 4));
        assert!(!cache.contains("bogus", 4));
    }

    #[test]
    fn commit_installs_and_consumes_tmp() {
        let dir = runner_core::test_support::TempDir::new("layer-commit").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let digest = digest();
        cache.ensure_dir().unwrap();
        let tmp = cache.tmp_path(&digest).unwrap();
        std::fs::write(&tmp, b"blob").unwrap();
        let path = cache.commit_tmp(&tmp, &digest).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"blob");
        assert!(!tmp.exists());
        assert!(cache.contains(&digest, 4));
    }

    #[test]
    fn ensure_dir_plants_safety_signpost() {
        let dir = runner_core::test_support::TempDir::new("layer-signpost").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        cache.ensure_dir().unwrap();
        let body =
            std::fs::read_to_string(dir.path().join("layers").join(CACHE_SIGNPOST_NAME)).unwrap();
        // All four reassurances present verbatim.
        assert!(body.contains("container image layer blobs"), "{body}");
        assert!(body.contains("SAFE TO DELETE"), "{body}");
        assert!(body.contains("never harm your operating"), "{body}");
        assert!(body.contains("automatically re-downloads"), "{body}");
    }

    #[test]
    fn signpost_self_heals_and_never_clobbers() {
        let dir = runner_core::test_support::TempDir::new("layer-heal").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        cache.ensure_dir().unwrap();
        // Deleting just the file restores it on re-bootstrap.
        let signpost = dir.path().join("layers").join(CACHE_SIGNPOST_NAME);
        std::fs::remove_file(&signpost).unwrap();
        cache.ensure_dir().unwrap();
        assert_eq!(
            std::fs::read_to_string(&signpost).unwrap(),
            CACHE_SIGNPOST_BODY
        );
        // Deleting the whole tree restores both on re-bootstrap.
        std::fs::remove_dir_all(dir.path().join("layers")).unwrap();
        cache.ensure_dir().unwrap();
        assert_eq!(
            std::fs::read_to_string(&signpost).unwrap(),
            CACHE_SIGNPOST_BODY
        );
        // Pre-existing content (even foreign) is never overwritten.
        std::fs::write(&signpost, "operator note").unwrap();
        cache.ensure_dir().unwrap();
        assert_eq!(std::fs::read_to_string(&signpost).unwrap(), "operator note");
    }

    #[test]
    fn manifest_store_bootstrap_plants_signpost() {
        let dir = runner_core::test_support::TempDir::new("layer-store-sign").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        store
            .write_manifest(
                "example.com/app:1",
                &StoredManifest {
                    reference: "example.com/app:1".to_string(),
                    manifest_digest: "sha256:bbbb".to_string(),
                    layers: vec![],
                    pulled_at_secs: 1,
                },
            )
            .unwrap();
        assert!(dir.path().join("layers").join(CACHE_SIGNPOST_NAME).exists());
    }
}
