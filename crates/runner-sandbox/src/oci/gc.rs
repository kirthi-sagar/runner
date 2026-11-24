//! Disk pressure-gated layer cache eviction: cross-platform volume
//! sensing plus a two-tier watermark LRU governor. When the cache
//! volume breaches the high watermark, the oldest cold blobs evict
//! until the low watermark clears; on plentiful disks cold layers
//! are preserved indefinitely. Broken manifest records (any layer
//! missing) are cleaned so the cache never advertises images it
//! cannot unpack.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use super::cache::{ImageStore, LayerCache};

/// Free-space trigger floor: below this, eviction starts even when
/// the percentage gauge looks comfortable (small volumes).
pub const HIGH_FREE_MIN_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Free-space relief target: pruning stops once free space exceeds
/// this even when the percentage gauge still reads high (huge
/// volumes with ample absolute room).
pub const LOW_FREE_TARGET_BYTES: u64 = 15 * 1024 * 1024 * 1024;

/// Filesystem capacity snapshot for one volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeMetrics {
    pub total_bytes: u64,
    /// Bytes available to the caller (unprivileged free).
    pub free_bytes: u64,
}

impl VolumeMetrics {
    /// Utilization percent, 0–100 (degenerate zero-size volumes
    /// read fully pressured so GC errs toward freeing).
    pub fn used_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 100.0;
        }
        let free = self.free_bytes.min(self.total_bytes) as f64;
        100.0 * (1.0 - free / self.total_bytes as f64)
    }
}

/// Walk up to the nearest existing ancestor (the cache dir itself
/// may not exist yet; the filesystem root always does).
fn existing_anchor(path: &Path) -> &Path {
    let mut anchor = path;
    while !anchor.exists() {
        match anchor.parent() {
            Some(parent) => anchor = parent,
            None => break,
        }
    }
    anchor
}

/// Sense the volume hosting `path` (or its nearest existing
/// ancestor): total capacity, available free bytes.
pub fn sense_volume(path: &Path) -> Result<VolumeMetrics, String> {
    sense_volume_at(existing_anchor(path))
}

#[cfg(unix)]
fn sense_volume_at(path: &Path) -> Result<VolumeMetrics, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let raw = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("unrepresentable cache path {}", path.display()))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs with a valid NUL-terminated path and a live
    // out-pointer; rc checked before the struct is read.
    let rc = unsafe { libc::statvfs(raw.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(format!(
            "cannot stat cache volume {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let block = stat.f_frsize as u64;
    Ok(VolumeMetrics {
        total_bytes: (stat.f_blocks as u64).saturating_mul(block),
        free_bytes: (stat.f_bavail as u64).saturating_mul(block),
    })
}

#[cfg(windows)]
fn sense_volume_at(path: &Path) -> Result<VolumeMetrics, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut available: u64 = 0;
    let mut total: u64 = 0;
    // SAFETY: wide path is NUL-terminated and live; out-pointers are
    // live u64s; return code checked before reading them.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            &mut total,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "cannot stat cache volume {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(VolumeMetrics {
        total_bytes: total,
        free_bytes: available,
    })
}

/// Two-tier watermark eviction policy (see `[storage.gc]`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GcPolicy {
    pub auto_evict: bool,
    pub high_watermark_pct: f64,
    pub low_watermark_pct: f64,
    pub min_age: Duration,
}

impl GcPolicy {
    pub fn from_config(config: &runner_core::config::StorageGcConfig) -> Self {
        Self {
            auto_evict: config.auto_evict,
            high_watermark_pct: f64::from(config.high_watermark_pct),
            low_watermark_pct: f64::from(config.low_watermark_pct),
            min_age: Duration::from_secs(config.min_age_days.saturating_mul(86_400)),
        }
    }

    /// Eviction trigger: either pressure gauge breached (percent at
    /// or above the high watermark, or free bytes below the floor).
    pub fn should_trigger(&self, metrics: VolumeMetrics) -> bool {
        metrics.used_pct() >= self.high_watermark_pct || metrics.free_bytes < HIGH_FREE_MIN_BYTES
    }

    /// Relief target: pruning stops once either gauge shows comfort
    /// (below the low percent, or above the free-space target).
    pub fn reached_target(&self, metrics: VolumeMetrics) -> bool {
        metrics.used_pct() < self.low_watermark_pct || metrics.free_bytes > LOW_FREE_TARGET_BYTES
    }
}

/// One eviction candidate: a layer blob cold enough to reclaim.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BlobCandidate {
    digest: String,
    size: u64,
    age_secs: u64,
}

/// Collect cold layer blobs (atime age at or beyond the policy
/// floor), oldest first. Blobs with unreadable access times are
/// never candidates (fail-closed: unknown age is preserved).
fn collect_candidates(cache: &LayerCache, policy: GcPolicy, now: SystemTime) -> Vec<BlobCandidate> {
    let mut candidates = Vec::new();
    let Ok(entries) = std::fs::read_dir(cache.dir()) else {
        return candidates;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let is_blob = name.len() == 64
            && name.bytes().all(|b| b.is_ascii_hexdigit())
            && path.extension().is_none();
        if !is_blob {
            continue;
        }
        let (accessed, size) = match entry
            .metadata()
            .and_then(|m| m.accessed().map(|t| (t, m.len())))
        {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        // Future atimes (clock skew) read as zero age: fresh.
        let age = now.duration_since(accessed).unwrap_or_default();
        if age < policy.min_age {
            continue;
        }
        candidates.push(BlobCandidate {
            digest: format!("sha256:{name}"),
            size,
            age_secs: age.as_secs(),
        });
    }
    // Oldest access first (largest age first).
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.age_secs));
    candidates
}

/// Outcome of one eviction pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GcOutcome {
    pub triggered: bool,
    pub blobs_removed: usize,
    pub bytes_freed: u64,
    pub manifests_cleaned: usize,
}

/// Run one pressure-gated eviction pass: sense, trigger-check, evict
/// oldest cold blobs until the relief target (re-sensing per
/// deletion so concurrent writers stay honest), then drop manifest
/// records with any missing layer. The metrics closure is injected
/// so simulations script pressure deterministically; production
/// passes real sensing.
pub fn evict_to_target(
    cache: &LayerCache,
    store: &ImageStore,
    policy: GcPolicy,
    metrics: &dyn Fn() -> Result<VolumeMetrics, String>,
    now: SystemTime,
) -> Result<GcOutcome, String> {
    if !policy.auto_evict {
        return Ok(GcOutcome::default());
    }
    if !policy.should_trigger(metrics()?) {
        return Ok(GcOutcome::default());
    }
    let mut outcome = GcOutcome {
        triggered: true,
        ..GcOutcome::default()
    };
    for candidate in collect_candidates(cache, policy, now) {
        if policy.reached_target(metrics()?) {
            break;
        }
        let path: PathBuf = cache.path_for(&candidate.digest)?;
        match std::fs::remove_file(&path) {
            Ok(()) => {
                outcome.blobs_removed += 1;
                outcome.bytes_freed += candidate.size;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!("cannot evict layer {}: {e}", path.display()));
            }
        }
    }
    outcome.manifests_cleaned = clean_broken_manifests(store, cache);
    Ok(outcome)
}

/// Drop manifest records with any layer blob missing from disk
/// (evicted, crashed, or hand-deleted): a record that cannot unpack
/// is a lie the list surface must not tell. Returns the count.
fn clean_broken_manifests(store: &ImageStore, cache: &LayerCache) -> usize {
    let mut cleaned = 0;
    for (reference, manifest) in store.list_manifests() {
        let broken = manifest.layers.iter().any(|layer| {
            cache
                .path_for(&layer.digest)
                .map(|path| !path.exists())
                .unwrap_or(true)
        });
        if broken && std::fs::remove_file(store.manifest_path(&reference)).is_ok() {
            cleaned += 1;
        }
    }
    cleaned
}

/// Production entry: real volume sensing for the cache dir. The
/// Phase 4+ hook for automatic invocation (pull path / daemon tick);
/// Phase 3 exercises the injected policy core above.
pub fn maybe_auto_evict(
    cache: &LayerCache,
    store: &ImageStore,
    policy: GcPolicy,
    now: SystemTime,
) -> Result<GcOutcome, String> {
    evict_to_target(cache, store, policy, &|| sense_volume(cache.dir()), now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const GB: u64 = 1024 * 1024 * 1024;

    fn policy() -> GcPolicy {
        GcPolicy {
            auto_evict: true,
            high_watermark_pct: 90.0,
            low_watermark_pct: 80.0,
            min_age: Duration::from_secs(30 * 86_400),
        }
    }

    fn vol(total_bytes: u64, free_bytes: u64) -> VolumeMetrics {
        VolumeMetrics {
            total_bytes,
            free_bytes,
        }
    }

    fn write_blob(cache: &LayerCache, tag: u8, size: usize) -> String {
        let hex = format!("{:02x}", tag).repeat(32);
        std::fs::create_dir_all(cache.dir()).unwrap();
        std::fs::write(cache.dir().join(&hex), vec![tag; size]).unwrap();
        format!("sha256:{hex}")
    }

    #[test]
    fn sense_volume_reports_sane_metrics() {
        let dir = runner_core::test_support::TempDir::new("gc-sense").unwrap();
        let live = sense_volume(dir.path()).unwrap();
        assert!(live.total_bytes > 0);
        assert!(live.free_bytes <= live.total_bytes);
        assert!(live.used_pct() >= 0.0 && live.used_pct() <= 100.0);
        // Nonexistent children resolve through the existing parent
        // (same volume totals, deterministically).
        let missing = sense_volume(&dir.path().join("nope/nada")).unwrap();
        assert_eq!(missing.total_bytes, live.total_bytes);
    }

    #[test]
    fn watermarks_trigger_and_relieve_per_gauge() {
        let policy = policy();
        // Either pressure gauge triggers eviction (isolated: pct
        // trigger on a huge disk with ample free; free trigger on a
        // small disk under 90%).
        assert!(policy.should_trigger(vol(1000 * GB, 50 * GB)));
        assert!(policy.should_trigger(vol(50 * GB, 9 * GB)));
        // Plentiful disk invariant: below 90% AND ample free never
        // triggers, whatever the cache holds.
        assert!(!policy.should_trigger(vol(100 * GB, 50 * GB)));
        // Relief on either gauge stops pruning (huge disks with
        // ample absolute room short-circuit immediately).
        assert!(policy.reached_target(vol(100 * GB, 21 * GB)));
        assert!(policy.reached_target(vol(1000 * GB, 16 * GB)));
        assert!(!policy.reached_target(vol(100 * GB, 12 * GB)));
    }

    #[test]
    fn high_pressure_evicts_down_to_low_watermark() {
        let dir = runner_core::test_support::TempDir::new("gc-high").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        for tag in [1u8, 2, 3] {
            write_blob(&cache, tag, 1000);
        }
        // Simulated 10KB volume at 95%: the script reports
        // pressure for the trigger plus two loop checks, then relief
        // (below 80%) — exactly two deletions, then stop.
        let calls = Cell::new(0u32);
        let scripted = || {
            let call = calls.get();
            calls.set(call + 1);
            let free_bytes = if call < 3 { 500 } else { 2500 };
            Ok(VolumeMetrics {
                total_bytes: 10_000,
                free_bytes,
            })
        };
        let now = SystemTime::now() + Duration::from_secs(200 * 86_400);
        let outcome = evict_to_target(&cache, &store, policy(), &scripted, now).unwrap();
        assert!(outcome.triggered);
        assert_eq!(outcome.blobs_removed, 2);
        assert_eq!(outcome.bytes_freed, 2000);
        assert_eq!(calls.get(), 4);
    }

    #[test]
    fn plentiful_disk_preserves_ancient_layers() {
        let dir = runner_core::test_support::TempDir::new("gc-plentiful").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        write_blob(&cache, 9, 100);
        // 200-day-old blob under plentiful disk: never touched.
        let now = SystemTime::now() + Duration::from_secs(200 * 86_400);
        let outcome = evict_to_target(
            &cache,
            &store,
            policy(),
            &|| Ok(vol(100 * GB, 50 * GB)),
            now,
        )
        .unwrap();
        assert!(!outcome.triggered);
        assert_eq!(outcome.blobs_removed, 0);
        assert_eq!(std::fs::read_dir(cache.dir()).unwrap().count(), 1);
    }

    #[test]
    fn auto_evict_off_never_senses() {
        let dir = runner_core::test_support::TempDir::new("gc-off").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        let policy = GcPolicy {
            auto_evict: false,
            ..policy()
        };
        let outcome = evict_to_target(
            &cache,
            &store,
            policy,
            &|| panic!("sensing must not run when disabled"),
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(outcome, GcOutcome::default());
    }

    #[test]
    fn lru_evicts_oldest_first() {
        let dir = runner_core::test_support::TempDir::new("gc-lru").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        let old = write_blob(&cache, 0xaa, 100);
        // 2.1s gap guarantees distinct truncated age seconds on any
        // filesystem granularity CI runs (fresh blobs are never
        // re-read, so atime stays at creation under every atime
        // mount mode).
        std::thread::sleep(Duration::from_millis(2100));
        let new = write_blob(&cache, 0xbb, 100);
        // Pressure for the trigger plus one loop check, then relief:
        // exactly one deletion — the oldest blob.
        let calls = Cell::new(0u32);
        let scripted = || {
            let call = calls.get();
            calls.set(call + 1);
            let free_bytes = if call < 2 { 500 } else { 9000 };
            Ok(VolumeMetrics {
                total_bytes: 10_000,
                free_bytes,
            })
        };
        let now = SystemTime::now() + Duration::from_secs(200 * 86_400);
        let outcome = evict_to_target(&cache, &store, policy(), &scripted, now).unwrap();
        assert_eq!(outcome.blobs_removed, 1);
        assert!(!cache.path_for(&old).unwrap().exists());
        assert!(cache.path_for(&new).unwrap().exists());
    }

    #[test]
    fn eviction_cleans_manifests_with_missing_layers() {
        use crate::oci::cache::{StoredLayer, StoredManifest};

        let dir = runner_core::test_support::TempDir::new("gc-manifest").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        let doomed = write_blob(&cache, 0xcc, 100);
        let kept = write_blob(&cache, 0xdd, 100);
        for (reference, digest) in [("doomed:1", &doomed), ("kept:1", &kept)] {
            store
                .write_manifest(
                    reference,
                    &StoredManifest {
                        reference: reference.to_string(),
                        manifest_digest: "sha256:eeee".to_string(),
                        layers: vec![StoredLayer {
                            digest: digest.clone(),
                            size: 100,
                        }],
                        pulled_at_secs: 1,
                    },
                )
                .unwrap();
        }
        // Relief after exactly one deletion: one manifest breaks.
        let calls = Cell::new(0u32);
        let scripted = || {
            let call = calls.get();
            calls.set(call + 1);
            let free_bytes = if call < 2 { 500 } else { 9000 };
            Ok(VolumeMetrics {
                total_bytes: 10_000,
                free_bytes,
            })
        };
        let now = SystemTime::now() + Duration::from_secs(200 * 86_400);
        let outcome = evict_to_target(&cache, &store, policy(), &scripted, now).unwrap();
        assert_eq!(outcome.blobs_removed, 1);
        assert_eq!(outcome.manifests_cleaned, 1);
        // Exactly one record survives, and it unpacks whole.
        let live: Vec<String> = store
            .list_manifests()
            .into_iter()
            .map(|(reference, _)| reference)
            .collect();
        assert_eq!(live.len(), 1);
        let survivor = store.read_manifest(&live[0]).unwrap();
        for layer in &survivor.layers {
            assert!(cache.path_for(&layer.digest).unwrap().exists());
        }
    }

    #[test]
    fn sensing_failure_fails_the_pass_closed() {
        let dir = runner_core::test_support::TempDir::new("gc-err").unwrap();
        let cache = LayerCache::new(dir.path().join("layers"));
        let store = ImageStore::new(cache.dir());
        let err = evict_to_target(
            &cache,
            &store,
            policy(),
            &|| Err("no disk".to_string()),
            SystemTime::now(),
        )
        .unwrap_err();
        assert_eq!(err, "no disk");
    }
}
