//! Transparent LAN cache: content-addressed disk store with LRU eviction.
//!
//! Backs the `ACTIONS_CACHE_URL` proxy server. Layout under the cache dir:
//!
//! * `index.json` — entries + aggregate stats (atomic temp+rename writes).
//! * `<sha256(version,key)>` — committed archives.
//! * `<id>.tmp` — in-progress chunked uploads.
//!
//! All operations are synchronous behind one short mutex (LAN-scale
//! critical sections; no async locks across file IO). A corrupt index
//! starts fresh with a loud log: cache loss means misses, never money.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default budget when `[cache] max_size_gb` is unset.
pub const DEFAULT_MAX_SIZE_GB: u64 = 10;

/// One committed archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntryMeta {
    pub id: u64,
    pub key: String,
    pub version: String,
    pub file: String,
    pub size: u64,
    pub created_unix_secs: u64,
    pub accessed_unix_secs: u64,
    pub hits: u64,
}

/// Aggregate counters (persisted with the index).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStatsData {
    pub hits: u64,
    pub misses: u64,
    pub bytes_served: u64,
    pub bytes_uploaded: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexFile {
    version: u32,
    next_id: u64,
    entries: Vec<CacheEntryMeta>,
    stats: CacheStatsData,
}

/// Point-in-time snapshot for IPC/MCP/CLI/dashboards.
#[derive(Debug, Clone, Serialize)]
pub struct CacheStatsSnapshot {
    pub entries: usize,
    pub size_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: f64,
    pub bytes_served: u64,
    pub bytes_uploaded: u64,
}

#[derive(Debug)]
struct StoreInner {
    entries: HashMap<u64, CacheEntryMeta>,
    /// Reserved-but-uncommitted uploads: id → (key, version).
    pending: HashMap<u64, (String, String)>,
    next_id: u64,
    stats: CacheStatsData,
}

/// Upload-stage failures (mapped to HTTP statuses by the server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    UnknownUpload(u64),
    SizeMismatch { id: u64, staged: u64, declared: u64 },
    Io(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownUpload(id) => write!(f, "unknown upload {id}"),
            Self::SizeMismatch {
                id,
                staged,
                declared,
            } => write!(
                f,
                "size mismatch for upload {id}: staged {staged} != declared {declared}"
            ),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Cloneable handle to the on-disk cache store.
#[derive(Debug, Clone)]
pub struct CacheStore {
    dir: PathBuf,
    max_bytes: u64,
    inner: std::sync::Arc<Mutex<StoreInner>>,
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Content stem for a (version, key) pair.
fn entry_filename(version: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(version.as_bytes());
    hasher.update([0]);
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl CacheStore {
    /// Open (creating) a store, loading the index and sweeping orphaned
    /// `.tmp` uploads. A corrupt index starts fresh (logged loudly).
    pub fn open(dir: &Path, max_bytes: u64) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create cache dir {}: {e}", dir.display()))?;
        // Sweep orphaned uploads from crashed/materialized runs.
        if let Ok(read) = std::fs::read_dir(dir) {
            for entry in read.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "tmp") {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        let index_path = dir.join("index.json");
        let mut index = match std::fs::read_to_string(&index_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IndexFile {
                version: 1,
                next_id: 1,
                entries: Vec::new(),
                stats: CacheStatsData::default(),
            },
            Err(e) => {
                return Err(format!(
                    "cannot read cache index {}: {e}",
                    index_path.display()
                ));
            }
            Ok(text) => match serde_json::from_str::<IndexFile>(&text) {
                Ok(index) => index,
                Err(e) => {
                    eprintln!("runner: corrupt cache index ({e}); starting fresh");
                    let backup = dir.join("index.json.corrupt");
                    let _ = std::fs::rename(&index_path, &backup);
                    IndexFile {
                        version: 1,
                        next_id: 1,
                        entries: Vec::new(),
                        stats: CacheStatsData::default(),
                    }
                }
            },
        };
        // Drop rows whose archives vanished out-of-band.
        index.entries.retain(|e| dir.join(&e.file).is_file());
        let store = Self {
            dir: dir.to_path_buf(),
            max_bytes,
            inner: std::sync::Arc::new(Mutex::new(StoreInner {
                entries: index.entries.into_iter().map(|e| (e.id, e)).collect(),
                pending: HashMap::new(),
                next_id: index.next_id.max(1),
                stats: index.stats,
            })),
        };
        store.persist()?;
        Ok(store)
    }

    fn persist(&self) -> Result<(), String> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| "cache index lock poisoned".to_string())?;
        let index = IndexFile {
            version: 1,
            next_id: inner.next_id,
            entries: inner.entries.values().cloned().collect(),
            stats: inner.stats.clone(),
        };
        drop(inner);
        let text =
            serde_json::to_string(&index).map_err(|e| format!("cannot encode index: {e}"))?;
        let tmp = self.dir.join("index.json.tmp");
        std::fs::write(&tmp, text)
            .map_err(|e| format!("cannot write index {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, self.dir.join("index.json"))
            .map_err(|e| format!("cannot commit index: {e}"))?;
        Ok(())
    }

    /// Look up (version, primary key + restore-key fallbacks). Exact match
    /// on the primary key; each fallback prefix-matches in order with the
    /// most-recently-used winner. Records hit/miss + access time.
    pub fn lookup(&self, version: &str, keys: &[String]) -> Option<CacheEntryMeta> {
        let mut inner = self.inner.lock().ok()?;
        let mut key_iter = keys.iter();
        let primary = key_iter.next()?;
        let found = inner
            .entries
            .values()
            .find(|e| e.version == version && e.key == *primary)
            .map(|e| e.id)
            .or_else(|| {
                key_iter
                    .filter_map(|prefix| {
                        inner
                            .entries
                            .values()
                            .filter(|e| e.version == version && e.key.starts_with(prefix.as_str()))
                            .max_by_key(|e| (e.accessed_unix_secs, e.id))
                            .map(|e| e.id)
                    })
                    .next()
            });
        match found {
            Some(id) => {
                let entry = inner.entries.get_mut(&id)?.clone();
                inner.stats.hits += 1;
                if let Some(stored) = inner.entries.get_mut(&id) {
                    stored.accessed_unix_secs = now_unix_secs();
                    stored.hits += 1;
                }
                drop(inner);
                let _ = self.persist();
                Some(entry)
            }
            None => {
                inner.stats.misses += 1;
                drop(inner);
                let _ = self.persist();
                None
            }
        }
    }

    /// Reserve an upload slot for (version, key). Returns the new numeric
    /// cache id, or the existing id when already committed or in flight.
    pub fn reserve(&self, key: &str, version: &str) -> Result<ReserveOutcome, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "cache index lock poisoned".to_string())?;
        if let Some(existing) = inner
            .entries
            .values()
            .find(|e| e.version == version && e.key == key)
        {
            return Ok(ReserveOutcome::Exists(existing.id));
        }
        if let Some((id, _)) = inner
            .pending
            .iter()
            .find(|(_, (k, v))| k == key && v == version)
        {
            return Ok(ReserveOutcome::Exists(*id));
        }
        let id = inner.next_id;
        inner.next_id += 1;
        inner
            .pending
            .insert(id, (key.to_string(), version.to_string()));
        drop(inner);
        self.persist()?;
        Ok(ReserveOutcome::Created(id))
    }

    /// Write one chunk at an explicit byte offset (concurrent out-of-order
    /// chunks are safe: separate handles, no shared cursor).
    pub fn write_chunk(&self, id: u64, start: u64, bytes: &[u8]) -> Result<u64, StoreError> {
        use std::io::{Seek, SeekFrom, Write};
        if !self.has_pending(id) {
            return Err(StoreError::UnknownUpload(id));
        }
        let path = self.dir.join(format!("{id}.tmp"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            // Never truncate: chunks for one id arrive out of order.
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| StoreError::Io(format!("cannot stage upload {id}: {e}")))?;
        file.seek(SeekFrom::Start(start))
            .and_then(|_| file.write_all(bytes))
            .map_err(|e| StoreError::Io(format!("cannot write upload {id}: {e}")))?;
        file.metadata()
            .map(|m| m.len())
            .map_err(|e| StoreError::Io(format!("cannot stat upload {id}: {e}")))
    }

    fn has_pending(&self, id: u64) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.pending.contains_key(&id))
            .unwrap_or(false)
    }

    /// Commit a staged upload: verify total size, atomically move into the
    /// store, evict LRU over budget. Returns the committed entry.
    pub fn commit(&self, id: u64, size: u64) -> Result<CacheEntryMeta, StoreError> {
        let (key, version) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| StoreError::Io("cache index lock poisoned".to_string()))?;
            inner
                .pending
                .remove(&id)
                .ok_or(StoreError::UnknownUpload(id))?
        };
        let tmp = self.dir.join(format!("{id}.tmp"));
        let staged = std::fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
        if staged != size {
            return Err(StoreError::SizeMismatch {
                id,
                staged,
                declared: size,
            });
        }
        let file = entry_filename(&version, &key);
        std::fs::rename(&tmp, self.dir.join(&file))
            .map_err(|e| StoreError::Io(format!("cannot commit upload {id}: {e}")))?;
        let now = now_unix_secs();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| StoreError::Io("cache index lock poisoned".to_string()))?;
        // Defensive: same (version, key) committed twice keeps one row.
        inner
            .entries
            .retain(|_, e| !(e.version == version && e.key == key));
        inner.entries.insert(
            id,
            CacheEntryMeta {
                id,
                key,
                version,
                file,
                size,
                created_unix_secs: now,
                accessed_unix_secs: now,
                hits: 0,
            },
        );
        inner.stats.bytes_uploaded += size;
        // LRU eviction: least-recently-accessed first, never the commit.
        loop {
            let total: u64 = inner.entries.values().map(|e| e.size).sum();
            if total <= self.max_bytes {
                break;
            }
            let victim = inner
                .entries
                .values()
                .filter(|e| e.id != id)
                .min_by_key(|e| (e.accessed_unix_secs, e.id))
                .map(|e| e.id);
            let Some(victim) = victim else {
                break;
            };
            if let Some(evicted) = inner.entries.remove(&victim) {
                let _ = std::fs::remove_file(self.dir.join(&evicted.file));
            }
        }
        let entry = inner.entries.get(&id).cloned();
        drop(inner);
        self.persist().map_err(StoreError::Io)?;
        entry.ok_or(StoreError::UnknownUpload(id))
    }

    /// Total archive bytes for an entry without reading it (HEAD support).
    pub fn entry_size(&self, id: u64) -> Option<u64> {
        self.inner.lock().ok()?.entries.get(&id).map(|e| e.size)
    }

    /// Read archive bytes (full file or one range). Counts served bytes.
    pub fn read_bytes(
        &self,
        id: u64,
        start: u64,
        len: Option<u64>,
    ) -> Result<(Vec<u8>, u64), String> {
        use std::io::{Read, Seek, SeekFrom};
        let path = {
            let inner = self
                .inner
                .lock()
                .map_err(|_| "cache index lock poisoned".to_string())?;
            inner
                .entries
                .get(&id)
                .map(|e| self.dir.join(&e.file))
                .ok_or_else(|| format!("unknown cache id {id}"))?
        };
        let mut file =
            std::fs::File::open(&path).map_err(|_| format!("cache archive missing for id {id}"))?;
        let total = file
            .metadata()
            .map(|m| m.len())
            .map_err(|e| format!("cannot stat cache {id}: {e}"))?;
        file.seek(SeekFrom::Start(start.min(total)))
            .map_err(|e| format!("cannot seek cache {id}: {e}"))?;
        let take = len
            .unwrap_or(total.saturating_sub(start))
            .min(total.saturating_sub(start));
        let mut buf = vec![0u8; take as usize];
        file.read_exact(&mut buf)
            .map_err(|e| format!("cannot read cache {id}: {e}"))?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "cache index lock poisoned".to_string())?;
        inner.stats.bytes_served += buf.len() as u64;
        if let Some(entry) = inner.entries.get_mut(&id) {
            entry.accessed_unix_secs = now_unix_secs();
        }
        drop(inner);
        let _ = self.persist();
        Ok((buf, total))
    }

    /// Current counters + totals.
    pub fn stats(&self) -> CacheStatsSnapshot {
        let inner = self.inner.lock().map(|g| {
            (
                g.entries.len(),
                g.entries.values().map(|e| e.size).sum::<u64>(),
                g.stats.clone(),
            )
        });
        let (entries, size_bytes, stats) = inner.unwrap_or((0, 0, CacheStatsData::default()));
        let total = stats.hits + stats.misses;
        CacheStatsSnapshot {
            entries,
            size_bytes,
            hits: stats.hits,
            misses: stats.misses,
            hit_ratio: if total == 0 {
                0.0
            } else {
                stats.hits as f64 / total as f64
            },
            bytes_served: stats.bytes_served,
            bytes_uploaded: stats.bytes_uploaded,
        }
    }

    /// Purge archives: all, or entries unaccessed for `older_than_days`.
    /// A full clear resets counters; a partial clear keeps them.
    /// Returns (removed entries, freed bytes).
    pub fn clear(&self, older_than_days: Option<u64>) -> (usize, u64) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => return (0, 0),
        };
        let now = now_unix_secs();
        let cutoff = older_than_days.map(|days| now.saturating_sub(days * 86_400));
        let victims: Vec<u64> = inner
            .entries
            .values()
            .filter(|e| cutoff.is_none_or(|at| e.accessed_unix_secs < at))
            .map(|e| e.id)
            .collect();
        let mut freed = 0u64;
        for id in &victims {
            if let Some(entry) = inner.entries.remove(id) {
                freed += entry.size;
                let _ = std::fs::remove_file(self.dir.join(&entry.file));
            }
        }
        if older_than_days.is_none() {
            inner.stats = CacheStatsData::default();
        }
        let removed = victims.len();
        drop(inner);
        let _ = self.persist();
        (removed, freed)
    }
}

/// Outcome of [`CacheStore::reserve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    Created(u64),
    Exists(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn store(max_bytes: u64) -> (TempDir, CacheStore) {
        let dir = TempDir::new("cache-store").unwrap();
        let store = CacheStore::open(&dir.path().join("cache"), max_bytes).unwrap();
        (dir, store)
    }

    fn commit_bytes(store: &CacheStore, key: &str, version: &str, bytes: &[u8]) -> u64 {
        let id = match store.reserve(key, version).unwrap() {
            ReserveOutcome::Created(id) => id,
            ReserveOutcome::Exists(id) => panic!("unexpected exists for {key}: {id}"),
        };
        store.write_chunk(id, 0, bytes).unwrap();
        let entry = store.commit(id, bytes.len() as u64).unwrap();
        assert_eq!(entry.size, bytes.len() as u64);
        id
    }

    #[test]
    fn lookup_hits_misses_and_restore_prefixes() {
        let (_dir, store) = store(1 << 30);
        commit_bytes(&store, "npm-abc123", "v1", b"data");
        // Exact primary hit.
        let hit = store
            .lookup("v1", &["npm-abc123".to_string()])
            .expect("exact hit");
        assert_eq!(hit.key, "npm-abc123");
        // Miss records + unknown version misses.
        assert!(store.lookup("v1", &["nope".to_string()]).is_none());
        assert!(store.lookup("v9", &["npm-abc123".to_string()]).is_none());
        // Restore-key prefix fallback in order.
        let hit = store
            .lookup("v1", &["npm-zzz".to_string(), "npm-".to_string()])
            .expect("prefix hit");
        assert_eq!(hit.key, "npm-abc123");
        let stats = store.stats();
        assert_eq!((stats.hits, stats.misses), (2, 2));
        assert!((stats.hit_ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn reserve_conflicts_and_commit_verifies_size() {
        let (_dir, store) = store(1 << 30);
        let id = commit_bytes(&store, "k", "v", b"0123456789");
        assert_eq!(store.reserve("k", "v").unwrap(), ReserveOutcome::Exists(id));
        // Out-of-order chunks assemble; size mismatch refuses commit.
        let ReserveOutcome::Created(id2) = store.reserve("k2", "v").unwrap() else {
            panic!("expected created");
        };
        store.write_chunk(id2, 5, b"56789").unwrap();
        store.write_chunk(id2, 0, b"01234").unwrap();
        assert_eq!(
            store.commit(id2, 999).unwrap_err(),
            StoreError::SizeMismatch {
                id: id2,
                staged: 10,
                declared: 999
            }
        );
        // Failed commit consumed the reservation; re-reserve and retry.
        let ReserveOutcome::Created(id3) = store.reserve("k2", "v").unwrap() else {
            panic!("expected created");
        };
        store.write_chunk(id3, 0, b"0123456789").unwrap();
        store.commit(id3, 10).unwrap();
        let (bytes, total) = store.read_bytes(id3, 0, None).unwrap();
        assert_eq!(bytes, b"0123456789");
        assert_eq!(total, 10);
        assert!(matches!(
            store.commit(424242, 1).unwrap_err(),
            StoreError::UnknownUpload(424242)
        ));
    }

    #[test]
    fn lru_evicts_least_recently_accessed_first() {
        let (_dir, store) = store(20);
        commit_bytes(&store, "old", "v", b"0123456789"); // 10 B
        commit_bytes(&store, "new", "v", b"0123456789"); // 10 B, total 20
                                                         // Touch "old" in a later second so "new" is the LRU victim.
        std::thread::sleep(std::time::Duration::from_secs(1));
        store.lookup("v", &["old".to_string()]);
        commit_bytes(&store, "third", "v", b"01234"); // +5 B → evict one
        assert!(store.lookup("v", &["old".to_string()]).is_some());
        assert!(store.lookup("v", &["new".to_string()]).is_none());
        assert!(store.lookup("v", &["third".to_string()]).is_some());
        assert!(store.stats().size_bytes <= 20);
    }

    #[test]
    fn ranges_read_slices_and_count_served() {
        let (_dir, store) = store(1 << 30);
        let id = commit_bytes(&store, "k", "v", b"0123456789");
        let (bytes, total) = store.read_bytes(id, 4, Some(3)).unwrap();
        assert_eq!(bytes, b"456");
        assert_eq!(total, 10);
        // Over-long ranges clamp to EOF.
        let (bytes, _) = store.read_bytes(id, 8, Some(99)).unwrap();
        assert_eq!(bytes, b"89");
        assert_eq!(store.stats().bytes_served, 5);
        assert!(store.read_bytes(424242, 0, None).is_err());
    }

    #[test]
    fn clear_all_and_older_than() {
        let (_dir, store) = store(1 << 30);
        commit_bytes(&store, "a", "v", b"0123456789");
        commit_bytes(&store, "b", "v", b"0123456789");
        // Nothing is older than 30 days.
        assert_eq!(store.clear(Some(30)), (0, 0));
        assert_eq!(store.stats().entries, 2);
        // Everything is older than 0 days (accessed < now).
        std::thread::sleep(std::time::Duration::from_secs(1));
        let (removed, freed) = store.clear(Some(0));
        assert_eq!((removed, freed), (2, 20));
        assert_eq!(store.stats().entries, 0);
        // Full clear resets counters.
        commit_bytes(&store, "c", "v", b"0123456789");
        store.lookup("v", &["c".to_string()]);
        let (removed, _) = store.clear(None);
        assert_eq!(removed, 1);
        let stats = store.stats();
        assert_eq!((stats.hits, stats.misses, stats.entries), (0, 0, 0));
    }

    #[test]
    fn corrupt_index_starts_fresh_and_reloads() {
        let dir = TempDir::new("cache-corrupt").unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join("index.json"), "{oops").unwrap();
        std::fs::write(cache_dir.join("9.tmp"), b"orphan").unwrap();
        let store = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        assert_eq!(store.stats().entries, 0);
        assert!(cache_dir.join("index.json.corrupt").is_file());
        assert!(!cache_dir.join("9.tmp").exists());
        // Persisted state reloads across opens.
        commit_bytes(&store, "k", "v", b"0123456789");
        let reopened = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        assert_eq!(reopened.stats().entries, 1);
        assert!(reopened.lookup("v", &["k".to_string()]).is_some());
    }
}
