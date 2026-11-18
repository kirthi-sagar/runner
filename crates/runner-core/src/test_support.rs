//! Unique temp dir guard for tests: pid + counter + 64-bit random
//! nonce, with stale-dir removal so leaked `/tmp` entries can never
//! collide (Linux PID reuse) or poison a fresh test (stale index.json).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> std::io::Result<Self> {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nonce: u64 = rand::random();
        let path = std::env::temp_dir().join(format!(
            "runner-test-{}-{}-{:016x}-{tag}",
            std::process::id(),
            id,
            nonce
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn creates_start_clean_and_never_collide() {
        // Rapid creates (same pid, same tag) must all land on distinct,
        // existing, empty directories.
        let mut seen = HashSet::new();
        let mut guards = Vec::new();
        for _ in 0..100 {
            let dir = TempDir::new("nonce").unwrap();
            assert!(dir.path().is_dir());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
            assert!(seen.insert(dir.path().to_path_buf()), "path collision");
            guards.push(dir);
        }
        // Drop removes every directory (no leaks for later runs).
        drop(guards);
        assert!(seen.iter().all(|p| !p.exists()));
    }
}
