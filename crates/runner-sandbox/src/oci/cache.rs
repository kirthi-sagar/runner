//! Content-addressed OCI layer cache: verified blobs land here
//! under their hex digests, so repeat pulls never touch the network.
//! Corrupt or partial files fail the hit check and re-download.

use std::path::{Path, PathBuf};

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

    /// Create the cache root (idempotent; call before staging).
    pub fn ensure_dir(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create layer cache {}: {e}", self.dir.display()))
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
}
