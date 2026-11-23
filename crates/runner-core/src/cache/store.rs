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
/// Namespace for legacy unscoped entries and clients (`global`).
pub const GLOBAL_SCOPE: &str = "global";

fn default_scope() -> String {
    GLOBAL_SCOPE.to_string()
}

/// One committed archive. `scope` is the `owner/repo` namespace
/// (`global` for legacy rows, which predate the field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntryMeta {
    pub id: u64,
    #[serde(default = "default_scope")]
    pub scope: String,
    pub key: String,
    pub version: String,
    pub file: String,
    pub size: u64,
    pub created_unix_secs: u64,
    pub accessed_unix_secs: u64,
    pub hits: u64,
    /// Hex SHA-256 of the committed bytes, hashed at commit time.
    /// `None` for rows committed before digest recording (old
    /// indexes keep parsing; old peers simply skip verification).
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Aggregate counters (persisted with the index). New fields must
/// stay `#[serde(default)]` so pre-existing indexes keep parsing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStatsData {
    pub hits: u64,
    pub misses: u64,
    pub bytes_served: u64,
    pub bytes_uploaded: u64,
    /// Peer hits served via federation fallback.
    #[serde(default)]
    pub remote_hits: u64,
    /// Archive bytes pulled in from LAN peers.
    #[serde(default)]
    pub remote_bytes_imported: u64,
    /// Archive bytes served to LAN peers (non-loopback downloads).
    #[serde(default)]
    pub remote_bytes_served: u64,
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
    pub remote_hits: u64,
    pub remote_bytes_imported: u64,
    pub remote_bytes_served: u64,
}

#[derive(Debug)]
struct StoreInner {
    entries: HashMap<u64, CacheEntryMeta>,
    /// Reserved-but-uncommitted uploads: id → (scope, key, version).
    pending: HashMap<u64, (String, String, String)>,
    next_id: u64,
    stats: CacheStatsData,
}

/// Upload-stage failures (mapped to HTTP statuses by the server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    UnknownUpload(u64),
    SizeMismatch { id: u64, staged: u64, declared: u64 },
    TooLarge { id: u64, size: u64, max: u64 },
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
            Self::TooLarge { id, size, max } => write!(
                f,
                "upload {id} too large: {size} bytes exceeds {max} byte ceiling"
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

/// Hex SHA-256 of a file's bytes (single streaming pass).
fn hash_file_hex(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Content stem for a (scope, version, key) triple.
fn entry_filename(scope: &str, version: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope.as_bytes());
    hasher.update([0]);
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
        // Sweep archives no row references: pre-v1.7.0 files (hashed
        // without scope) can never match again after the upgrade.
        {
            let live: std::collections::HashSet<&str> =
                index.entries.iter().map(|e| e.file.as_str()).collect();
            if let Ok(read) = std::fs::read_dir(dir) {
                for entry in read.flatten() {
                    let path = entry.path();
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if path.is_file()
                        && name != "index.json"
                        && name != "index.json.corrupt"
                        && !name.ends_with(".tmp")
                        && !live.contains(name.as_ref())
                    {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
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

    /// Look up (scope, version, primary key + restore-key fallbacks).
    /// Exact match on the primary key; each fallback prefix-matches in
    /// order with the most-recently-used winner. Records hit/miss +
    /// access time. Scopes never see each other's entries.
    pub fn lookup(&self, scope: &str, version: &str, keys: &[String]) -> Option<CacheEntryMeta> {
        let mut inner = self.inner.lock().ok()?;
        let mut key_iter = keys.iter();
        let primary = key_iter.next()?;
        let found = inner
            .entries
            .values()
            .find(|e| e.scope == scope && e.version == version && e.key == *primary)
            .map(|e| e.id)
            .or_else(|| {
                key_iter
                    .filter_map(|prefix| {
                        inner
                            .entries
                            .values()
                            .filter(|e| {
                                e.scope == scope
                                    && e.version == version
                                    && e.key.starts_with(prefix.as_str())
                            })
                            .max_by_key(|e| (e.accessed_unix_secs, e.id))
                            .map(|e| e.id)
                    })
                    .next()
            });
        // Read path: counters update in memory only. The index hits
        // disk on mutations (commit, clear, eviction) and clean shutdown.
        match found {
            Some(id) => {
                let entry = inner.entries.get_mut(&id)?.clone();
                inner.stats.hits += 1;
                if let Some(stored) = inner.entries.get_mut(&id) {
                    stored.accessed_unix_secs = now_unix_secs();
                    stored.hits += 1;
                }
                Some(entry)
            }
            None => {
                inner.stats.misses += 1;
                None
            }
        }
    }

    /// Flush in-memory counters/access times to `index.json`.
    /// Called on mutations (via [`CacheStore::commit`]/`clear`), and once
    /// on clean daemon shutdown so a quiet period loses nothing.
    pub fn flush(&self) -> Result<(), String> {
        self.persist()
    }

    /// Reserve an upload slot for (scope, version, key). Returns the
    /// new numeric cache id, or the existing id when already committed
    /// or in flight. Same key in another scope reserves independently.
    pub fn reserve(&self, scope: &str, key: &str, version: &str) -> Result<ReserveOutcome, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "cache index lock poisoned".to_string())?;
        if let Some(existing) = inner
            .entries
            .values()
            .find(|e| e.scope == scope && e.version == version && e.key == key)
        {
            return Ok(ReserveOutcome::Exists(existing.id));
        }
        if let Some((id, _)) = inner
            .pending
            .iter()
            .find(|(_, (s, k, v))| s == scope && k == key && v == version)
        {
            return Ok(ReserveOutcome::Exists(*id));
        }
        let id = inner.next_id;
        inner.next_id += 1;
        inner.pending.insert(
            id,
            (scope.to_string(), key.to_string(), version.to_string()),
        );
        // No persist: uncommitted ids are safely reusable after a crash
        // (nothing references them; orphans are swept at open), and the
        // next commit persists the advanced counter anyway.
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

    /// Staging path for a pending upload (`None` unless reserved).
    /// Lets the sequential peer-stream pump write with async buffered
    /// I/O while the store mutex stays out of the hot loop; the
    /// reservation guarantees exclusive ownership of the path.
    /// (Out-of-order worker chunks keep using [`write_chunk`](Self::write_chunk).)
    pub fn stage_path(&self, id: u64) -> Option<PathBuf> {
        let inner = self.inner.lock().ok()?;
        inner
            .pending
            .contains_key(&id)
            .then(|| self.dir.join(format!("{id}.tmp")))
    }

    /// Staged byte count for a pending upload (None when not pending).
    pub fn staged_len(&self, id: u64) -> Option<u64> {
        if !self.has_pending(id) {
            return None;
        }
        std::fs::metadata(self.dir.join(format!("{id}.tmp")))
            .map(|m| m.len())
            .ok()
    }

    /// Abandon a pending upload: drop the reservation and delete staged
    /// bytes. Idempotent; unknown ids only skip the map removal (the
    /// staging file is still swept when present).
    pub fn abort_upload(&self, id: u64) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.pending.remove(&id);
        }
        let _ = std::fs::remove_file(self.dir.join(format!("{id}.tmp")));
    }

    /// Commit a staged upload: verify total size, atomically move into the
    /// store, evict LRU over budget. Returns the committed entry.
    pub fn commit(&self, id: u64, size: u64) -> Result<CacheEntryMeta, StoreError> {
        let (scope, key, version) = {
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
        // Rejected commits sweep their staging files: a refused upload
        // must not linger on disk until the next restart.
        if staged != size {
            let _ = std::fs::remove_file(&tmp);
            return Err(StoreError::SizeMismatch {
                id,
                staged,
                declared: size,
            });
        }
        // Per-archive ceiling: no single archive may exceed the whole
        // store budget (a peer or worker must not evict everything).
        if size > self.max_bytes {
            let _ = std::fs::remove_file(&tmp);
            return Err(StoreError::TooLarge {
                id,
                size,
                max: self.max_bytes,
            });
        }
        // Digest what we install: unreadable staging fails closed
        // rather than committing unverifiable bytes.
        let sha256 = match hash_file_hex(&tmp) {
            Ok(digest) => digest,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(StoreError::Io(format!("cannot hash upload {id}: {e}")));
            }
        };
        let file = entry_filename(&scope, &version, &key);
        std::fs::rename(&tmp, self.dir.join(&file))
            .map_err(|e| StoreError::Io(format!("cannot commit upload {id}: {e}")))?;
        let now = now_unix_secs();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| StoreError::Io("cache index lock poisoned".to_string()))?;
        // Defensive: same (scope, version, key) committed twice keeps
        // one row (displaced archives are deleted immediately, so a
        // re-commit never orphans bytes).
        let displaced: Vec<u64> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.scope == scope && e.version == version && e.key == key)
            .map(|(id, _)| *id)
            .collect();
        for id in displaced {
            if let Some(old) = inner.entries.remove(&id) {
                let _ = std::fs::remove_file(self.dir.join(&old.file));
            }
        }
        inner.entries.insert(
            id,
            CacheEntryMeta {
                id,
                scope,
                key,
                version,
                file,
                size,
                created_unix_secs: now,
                accessed_unix_secs: now,
                hits: 0,
                sha256: Some(sha256),
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

    /// Store disk budget in bytes (also the per-archive ceiling).
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Total archive bytes for an entry without reading it (HEAD support).
    pub fn entry_size(&self, id: u64) -> Option<u64> {
        self.inner.lock().ok()?.entries.get(&id).map(|e| e.size)
    }

    /// Read archive bytes (full file or one range). Counts served bytes.
    /// Archive path for streaming serving (no bytes are read here).
    pub fn archive_path(&self, id: u64) -> Option<PathBuf> {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.entries.get(&id).map(|e| self.dir.join(&e.file)))
    }

    /// Record a served byte range: bumps served counters + LRU access.
    /// In-memory only (persisted on the next mutation or clean shutdown).
    pub fn record_served(&self, id: u64, bytes: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        // Unknown ids are a silent no-op (the server 404'd already).
        if inner.entries.contains_key(&id) {
            inner.stats.bytes_served += bytes;
            if let Some(entry) = inner.entries.get_mut(&id) {
                entry.accessed_unix_secs = now_unix_secs();
            }
        }
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
            remote_hits: stats.remote_hits,
            remote_bytes_imported: stats.remote_bytes_imported,
            remote_bytes_served: stats.remote_bytes_served,
        }
    }

    /// Record a federated hit: peer served us `imported` bytes.
    pub fn record_remote_hit(&self, imported_bytes: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.stats.remote_hits += 1;
        inner.stats.remote_bytes_imported += imported_bytes;
    }

    /// Record archive bytes served to a LAN peer download.
    pub fn record_remote_served(&self, bytes: u64) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.stats.remote_bytes_served += bytes;
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

    /// Evict entries older than `ttl_secs` by *creation* age (staleness,
    /// not access idleness — contrast [`CacheStore::clear`]). Counters
    /// are kept; the index persists only when something was removed.
    /// Returns (removed entries, freed bytes).
    pub fn evict_expired(&self, ttl_secs: u64) -> (usize, u64) {
        let mut inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => return (0, 0),
        };
        let now = now_unix_secs();
        let victims: Vec<u64> = inner
            .entries
            .values()
            .filter(|e| e.created_unix_secs.saturating_add(ttl_secs) < now)
            .map(|e| e.id)
            .collect();
        let mut freed = 0u64;
        for id in &victims {
            if let Some(entry) = inner.entries.remove(id) {
                freed += entry.size;
                let _ = std::fs::remove_file(self.dir.join(&entry.file));
            }
        }
        let removed = victims.len();
        drop(inner);
        if removed > 0 {
            let _ = self.persist();
        }
        (removed, freed)
    }

    /// Background TTL sweeper: evicts immediately on spawn, then every
    /// `sweep_secs` (60s floor). Returns `None` when `ttl_secs` is 0
    /// (sweep disabled); the daemon drops the handle (fire-and-forget).
    pub fn spawn_ttl_sweeper(
        &self,
        ttl_secs: u64,
        sweep_secs: u64,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if ttl_secs == 0 {
            return None;
        }
        let store = self.clone();
        let every = std::time::Duration::from_secs(sweep_secs.max(60));
        Some(tokio::spawn(async move {
            store.evict_expired(ttl_secs);
            let mut ticker = tokio::time::interval(every);
            // The spawn tick above already swept; skip the
            // interval's immediate first tick to avoid a double.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let (removed, freed) = store.evict_expired(ttl_secs);
                if removed > 0 {
                    eprintln!("runner: cache TTL sweep evicted {removed} entries ({freed} bytes)");
                }
            }
        }))
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

    fn commit_bytes(
        store: &CacheStore,
        scope: &str,
        key: &str,
        version: &str,
        bytes: &[u8],
    ) -> u64 {
        let id = match store.reserve(scope, key, version).unwrap() {
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
        commit_bytes(&store, GLOBAL_SCOPE, "npm-abc123", "v1", b"data");
        // Exact primary hit.
        let hit = store
            .lookup(GLOBAL_SCOPE, "v1", &["npm-abc123".to_string()])
            .expect("exact hit");
        assert_eq!(hit.key, "npm-abc123");
        // Miss records + unknown version misses.
        assert!(store
            .lookup(GLOBAL_SCOPE, "v1", &["nope".to_string()])
            .is_none());
        assert!(store
            .lookup(GLOBAL_SCOPE, "v9", &["npm-abc123".to_string()])
            .is_none());
        // Restore-key prefix fallback in order.
        let hit = store
            .lookup(
                GLOBAL_SCOPE,
                "v1",
                &["npm-zzz".to_string(), "npm-".to_string()],
            )
            .expect("prefix hit");
        assert_eq!(hit.key, "npm-abc123");
        let stats = store.stats();
        assert_eq!((stats.hits, stats.misses), (2, 2));
        assert!((stats.hit_ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn reserve_conflicts_and_commit_verifies_size() {
        let (_dir, store) = store(1 << 30);
        let id = commit_bytes(&store, GLOBAL_SCOPE, "k", "v", b"0123456789");
        assert_eq!(
            store.reserve(GLOBAL_SCOPE, "k", "v").unwrap(),
            ReserveOutcome::Exists(id)
        );
        // Out-of-order chunks assemble; size mismatch refuses commit.
        let ReserveOutcome::Created(id2) = store.reserve(GLOBAL_SCOPE, "k2", "v").unwrap() else {
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
        let ReserveOutcome::Created(id3) = store.reserve(GLOBAL_SCOPE, "k2", "v").unwrap() else {
            panic!("expected created");
        };
        store.write_chunk(id3, 0, b"0123456789").unwrap();
        store.commit(id3, 10).unwrap();
        let path = store.archive_path(id3).expect("committed archive resolves");
        assert_eq!(std::fs::read(&path).unwrap(), b"0123456789");
        assert!(matches!(
            store.commit(424242, 1).unwrap_err(),
            StoreError::UnknownUpload(424242)
        ));
    }

    #[test]
    fn lru_evicts_least_recently_accessed_first() {
        let (_dir, store) = store(20);
        commit_bytes(&store, GLOBAL_SCOPE, "old", "v", b"0123456789"); // 10 B
        commit_bytes(&store, GLOBAL_SCOPE, "new", "v", b"0123456789"); // 10 B, total 20
                                                                       // Touch "old" in a later second so "new" is the LRU victim.
        std::thread::sleep(std::time::Duration::from_secs(1));
        store.lookup(GLOBAL_SCOPE, "v", &["old".to_string()]);
        commit_bytes(&store, GLOBAL_SCOPE, "third", "v", b"01234"); // +5 B → evict one
        assert!(store
            .lookup(GLOBAL_SCOPE, "v", &["old".to_string()])
            .is_some());
        assert!(store
            .lookup(GLOBAL_SCOPE, "v", &["new".to_string()])
            .is_none());
        assert!(store
            .lookup(GLOBAL_SCOPE, "v", &["third".to_string()])
            .is_some());
        assert!(store.stats().size_bytes <= 20);
    }

    #[test]
    fn archive_path_resolves_and_served_counts() {
        let (_dir, store) = store(1 << 30);
        let id = commit_bytes(&store, GLOBAL_SCOPE, "k", "v", b"0123456789");
        let path = store.archive_path(id).expect("known id resolves");
        assert_eq!(std::fs::read(&path).unwrap(), b"0123456789");
        assert!(store.archive_path(424242).is_none());
        store.record_served(id, 3);
        store.record_served(id, 2);
        assert_eq!(store.stats().bytes_served, 5);
        // Unknown ids are a silent no-op (server already 404'd).
        store.record_served(424242, 99);
        assert_eq!(store.stats().bytes_served, 5);
    }

    #[test]
    fn clear_all_and_older_than() {
        let (_dir, store) = store(1 << 30);
        commit_bytes(&store, GLOBAL_SCOPE, "a", "v", b"0123456789");
        commit_bytes(&store, GLOBAL_SCOPE, "b", "v", b"0123456789");
        // Nothing is older than 30 days.
        assert_eq!(store.clear(Some(30)), (0, 0));
        assert_eq!(store.stats().entries, 2);
        // Everything is older than 0 days (accessed < now).
        std::thread::sleep(std::time::Duration::from_secs(1));
        let (removed, freed) = store.clear(Some(0));
        assert_eq!((removed, freed), (2, 20));
        assert_eq!(store.stats().entries, 0);
        // Full clear resets counters.
        commit_bytes(&store, GLOBAL_SCOPE, "c", "v", b"0123456789");
        store.lookup(GLOBAL_SCOPE, "v", &["c".to_string()]);
        let (removed, _) = store.clear(None);
        assert_eq!(removed, 1);
        let stats = store.stats();
        assert_eq!((stats.hits, stats.misses, stats.entries), (0, 0, 0));
    }

    #[test]
    fn reads_do_not_rewrite_the_index() {
        let dir = TempDir::new("cache-nopersist").unwrap();
        let cache_dir = dir.path().join("cache");
        let store = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        commit_bytes(&store, GLOBAL_SCOPE, "k", "v", b"0123456789");
        let before = std::fs::read(cache_dir.join("index.json")).unwrap();
        store.lookup(GLOBAL_SCOPE, "v", &["k".to_string()]);
        store.lookup(GLOBAL_SCOPE, "v", &["miss".to_string()]);
        store.record_served(1, 10);
        // Hot read path: zero disk writes.
        assert_eq!(std::fs::read(cache_dir.join("index.json")).unwrap(), before);
        // ...but in-memory counters advanced.
        assert_eq!((store.stats().hits, store.stats().misses), (1, 1));
        assert_eq!(store.stats().bytes_served, 10);
        // Explicit flush persists; reload observes the counters.
        store.flush().unwrap();
        drop(store);
        let reopened = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        assert_eq!((reopened.stats().hits, reopened.stats().misses), (1, 1));
    }

    #[test]
    fn commit_rejects_archives_past_store_budget() {
        let (dir, store) = store(16);
        let ReserveOutcome::Created(id) = store.reserve(GLOBAL_SCOPE, "big", "v").unwrap() else {
            panic!("expected created");
        };
        store.write_chunk(id, 0, &[0u8; 20]).unwrap();
        assert_eq!(
            store.commit(id, 20).unwrap_err(),
            StoreError::TooLarge {
                id,
                size: 20,
                max: 16
            }
        );
        // Rejected staging is swept, reservation consumed.
        assert!(store.staged_len(id).is_none());
        assert!(!dir.path().join("cache").join(format!("{id}.tmp")).exists());
    }

    #[test]
    fn legacy_index_without_remote_counters_still_parses() {
        let dir = TempDir::new("cache-legacy").unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(
            cache_dir.join("index.json"),
            r#"{"version":1,"next_id":1,"entries":[],"stats":{"hits":7,"misses":3,"bytes_served":100,"bytes_uploaded":50}}"#,
        )
        .unwrap();
        let store = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        let stats = store.stats();
        assert_eq!((stats.hits, stats.misses), (7, 3));
        assert_eq!(
            (
                stats.remote_hits,
                stats.remote_bytes_imported,
                stats.remote_bytes_served
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn remote_counters_record_and_snapshot() {
        let (_dir, store) = store(1 << 30);
        store.record_remote_hit(100);
        store.record_remote_hit(50);
        store.record_remote_served(100);
        let stats = store.stats();
        assert_eq!(stats.remote_hits, 2);
        assert_eq!(stats.remote_bytes_imported, 150);
        assert_eq!(stats.remote_bytes_served, 100);
    }

    #[test]
    fn abort_upload_drops_reservation_and_staged_bytes() {
        let (dir, store) = store(1 << 30);
        let ReserveOutcome::Created(id) = store.reserve(GLOBAL_SCOPE, "k", "v").unwrap() else {
            panic!("expected created");
        };
        store.write_chunk(id, 0, b"partial").unwrap();
        let tmp = dir.path().join("cache").join(format!("{id}.tmp"));
        assert!(tmp.is_file());
        store.abort_upload(id);
        assert!(!tmp.exists());
        // Idempotent; unknown ids silent.
        store.abort_upload(id);
        store.abort_upload(424242);
        // Reservation released: re-reserve yields a fresh id.
        assert!(matches!(
            store.reserve(GLOBAL_SCOPE, "k", "v").unwrap(),
            ReserveOutcome::Created(_)
        ));
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
        commit_bytes(&store, GLOBAL_SCOPE, "k", "v", b"0123456789");
        let reopened = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        assert_eq!(reopened.stats().entries, 1);
        assert!(reopened
            .lookup(GLOBAL_SCOPE, "v", &["k".to_string()])
            .is_some());
    }

    #[test]
    fn ttl_evicts_by_creation_age_not_access() {
        let (_dir, store) = store(1 << 30);
        commit_bytes(&store, GLOBAL_SCOPE, "old", "v", b"0123456789");
        // Fresh access must NOT rescue a creation-aged entry; the 2s
        // sleep plus ttl=1 keeps the fresh commit safe even if the
        // clock crosses a second boundary mid-test.
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(store
            .lookup(GLOBAL_SCOPE, "v", &["old".to_string()])
            .is_some());
        commit_bytes(&store, GLOBAL_SCOPE, "new", "v", b"0123456789");
        let (removed, freed) = store.evict_expired(1);
        assert_eq!((removed, freed), (1, 10));
        assert_eq!(store.stats().entries, 1);
        assert!(store
            .lookup(GLOBAL_SCOPE, "v", &["new".to_string()])
            .is_some());
        // Counters survive a TTL eviction (no reset like full clear).
        assert!(store.stats().hits >= 1);
    }

    #[test]
    fn ttl_sweep_disabled_when_zero() {
        let (_dir, store) = store(1 << 30);
        assert!(store.spawn_ttl_sweeper(0, 3600).is_none());
    }

    #[tokio::test]
    async fn sweeper_evicts_on_spawn_tick() {
        let (_dir, store) = store(1 << 30);
        commit_bytes(&store, GLOBAL_SCOPE, "stale", "v", b"0123456789");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let handle = store.spawn_ttl_sweeper(1, u64::MAX).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(store.stats().entries, 0);
        handle.abort();
    }

    #[test]
    fn scopes_are_isolated_by_key_and_prefix() {
        let (_dir, store) = store(1 << 30);
        commit_bytes(&store, "acme/web", "npm-abc123", "v1", b"web-bytes");
        // Same key + version in another scope: invisible, independently
        // reservable, and committed side by side.
        assert!(store
            .lookup("acme/api", "v1", &["npm-abc123".to_string()])
            .is_none());
        commit_bytes(&store, "acme/api", "npm-abc123", "v1", b"api-bytes");
        let web = store
            .lookup("acme/web", "v1", &["npm-abc123".to_string()])
            .unwrap();
        let api = store
            .lookup("acme/api", "v1", &["npm-abc123".to_string()])
            .unwrap();
        assert_ne!(web.id, api.id);
        assert_ne!(web.file, api.file);
        // Restore-key prefix fallback stays inside the scope.
        assert!(store
            .lookup(
                "acme/api",
                "v1",
                &["npm-zzz".to_string(), "npm-".to_string()]
            )
            .is_some_and(|e| e.scope == "acme/api"));
        assert!(store
            .lookup(
                "other/repo",
                "v1",
                &["npm-zzz".to_string(), "npm-".to_string()]
            )
            .is_none());
        // Duplicate reserve in the same scope still conflicts.
        assert!(matches!(
            store.reserve("acme/web", "npm-abc123", "v1").unwrap(),
            ReserveOutcome::Exists(_)
        ));
    }

    #[test]
    fn lru_eviction_is_scope_blind_and_fair() {
        let (_dir, store) = store(20);
        commit_bytes(&store, "a/r", "old", "v", b"0123456789"); // 10 B
        commit_bytes(&store, "b/r", "new", "v", b"0123456789"); // 10 B, total 20
                                                                // Touch "old" in a later second so "new" is the LRU victim even
                                                                // though the entrant belongs to a third scope.
        std::thread::sleep(std::time::Duration::from_secs(1));
        store.lookup("a/r", "v", &["old".to_string()]);
        commit_bytes(&store, "c/r", "third", "v", b"01234"); // +5 B → evict one
        assert!(store.lookup("a/r", "v", &["old".to_string()]).is_some());
        assert!(store.lookup("b/r", "v", &["new".to_string()]).is_none());
        assert!(store.lookup("c/r", "v", &["third".to_string()]).is_some());
        assert!(store.stats().size_bytes <= 20);
    }

    #[test]
    fn legacy_rows_default_to_global_and_orphans_sweep() {
        let dir = TempDir::new("cache-legacy-scope").unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        // Pre-v1.7.0 row: no scope field, archive hashed without scope.
        let legacy_file = "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
        std::fs::write(cache_dir.join(legacy_file), b"0123456789").unwrap();
        std::fs::write(
            cache_dir.join("index.json"),
            format!(
                r#"{{"version":1,"next_id":2,"entries":[{{"id":1,"key":"k","version":"v","file":"{legacy_file}","size":10,"created_unix_secs":1,"accessed_unix_secs":1,"hits":0}}],"stats":{{"hits":0,"misses":0,"bytes_served":0,"bytes_uploaded":0}}}}"#
            ),
        )
        .unwrap();
        // An unreferenced archive (crash debris): swept at open.
        let orphan = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        std::fs::write(cache_dir.join(orphan), b"0123456789").unwrap();
        let store = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        assert!(!cache_dir.join(orphan).exists());
        // The legacy row survives with its archive, defaulted into the
        // global scope: pre-upgrade bytes keep serving, no wipe.
        assert_eq!(store.stats().entries, 1);
        let hit = store.lookup(GLOBAL_SCOPE, "v", &["k".to_string()]).unwrap();
        assert_eq!(hit.scope, GLOBAL_SCOPE);
        assert_eq!(
            std::fs::read(cache_dir.join(legacy_file)).unwrap(),
            b"0123456789"
        );
        // Same triple re-reserves as Exists (409 upstream), and a scoped
        // twin coexists independently.
        assert!(matches!(
            store.reserve(GLOBAL_SCOPE, "k", "v").unwrap(),
            ReserveOutcome::Exists(1)
        ));
        commit_bytes(&store, "acme/web", "k", "v", b"scoped-bytes");
        assert_eq!(store.stats().entries, 2);
        // ...and scopes reload intact.
        drop(store);
        let reopened = CacheStore::open(&cache_dir, 1 << 30).unwrap();
        assert_eq!(reopened.stats().entries, 2);
        assert!(reopened
            .lookup(GLOBAL_SCOPE, "v", &["k".to_string()])
            .is_some());
        assert!(reopened
            .lookup("acme/web", "v", &["k".to_string()])
            .is_some());
    }

    fn hex_of(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    #[test]
    fn commit_records_sha256_and_survives_reload() {
        let (dir, store) = store(1 << 30);
        commit_bytes(&store, GLOBAL_SCOPE, "k", "v", b"digest-me");
        let entry = store.lookup(GLOBAL_SCOPE, "v", &["k".to_string()]).unwrap();
        assert_eq!(entry.sha256.as_deref(), Some(hex_of(b"digest-me").as_str()));
        drop(store);
        let reopened = CacheStore::open(&dir.path().join("cache"), 1 << 30).unwrap();
        let entry = reopened
            .lookup(GLOBAL_SCOPE, "v", &["k".to_string()])
            .unwrap();
        assert_eq!(entry.sha256.as_deref(), Some(hex_of(b"digest-me").as_str()));
    }

    #[test]
    fn stage_path_tracks_reservation_lifecycle() {
        let (_dir, store) = store(1 << 30);
        // Unknown id: no path.
        assert!(store.stage_path(999).is_none());
        let id = match store.reserve(GLOBAL_SCOPE, "k", "v").unwrap() {
            ReserveOutcome::Created(id) => id,
            ReserveOutcome::Exists(id) => panic!("unexpected exists: {id}"),
        };
        let path = store.stage_path(id).expect("reserved id stages");
        assert!(path.ends_with(format!("{id}.tmp")));
        // Abort releases the path; commit consumes the reservation.
        store.abort_upload(id);
        assert!(store.stage_path(id).is_none());
        let id = match store.reserve(GLOBAL_SCOPE, "k", "v").unwrap() {
            ReserveOutcome::Created(id) => id,
            ReserveOutcome::Exists(id) => panic!("unexpected exists: {id}"),
        };
        store.write_chunk(id, 0, b"x").unwrap();
        store.commit(id, 1).unwrap();
        assert!(store.stage_path(id).is_none());
    }

    #[test]
    fn legacy_index_without_digest_loads_with_none() {
        let dir = TempDir::new("legacy-index").unwrap();
        // Hand-written pre-digest index: no sha256 key anywhere.
        std::fs::write(dir.path().join("blobfile"), b"legacy-bytes").unwrap();
        std::fs::write(
            dir.path().join("index.json"),
            serde_json::json!({
                "version": 1,
                "next_id": 2,
                "entries": [{
                    "id": 1,
                    "scope": "global",
                    "key": "k",
                    "version": "v",
                    "file": "blobfile",
                    "size": 12,
                    "created_unix_secs": 1,
                    "accessed_unix_secs": 1,
                    "hits": 0
                }],
                "stats": {
                    "hits": 0,
                    "misses": 0,
                    "bytes_served": 0,
                    "bytes_uploaded": 0
                }
            })
            .to_string(),
        )
        .unwrap();
        let store = CacheStore::open(dir.path(), 1 << 30).unwrap();
        let entry = store.lookup(GLOBAL_SCOPE, "v", &["k".to_string()]).unwrap();
        assert_eq!(entry.sha256, None);
    }
}
