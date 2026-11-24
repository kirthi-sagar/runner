//! OCI rootfs snapshot cache: each pulled image unpacks once into
//! an immutable baseline, and every container provisions by
//! hardware-cloning that baseline (~0ms, shared blocks) instead of
//! re-unpacking layers. Snapshots are content-keyed by manifest
//! digest, published atomically behind a `.complete` sentinel, and
//! evicted under the same `[storage.gc]` pressure policy as blobs
//! (they rebuild locally, so they go first).

use super::cache::LayerCache;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Crash-debris grace for incomplete snapshots and staging dirs
/// (mirrors the layer-prune tmp grace: a live publisher's partial
/// tree is never reaped).
pub const STALE_SNAPSHOT_GRACE: Duration = Duration::from_secs(3600);

/// Sentinel marking a fully published snapshot (written last).
const COMPLETE_MARKER: &str = ".complete";

/// Unpacked-image baseline store rooted at one directory.
#[derive(Debug, Clone)]
pub struct SnapshotCache {
    root: PathBuf,
}

/// One complete snapshot as seen by GC: content key and publish
/// time (the `.complete` mtime) in epoch seconds. Deliberately
/// du-free: sizes resolve per eviction via [`SnapshotCache::disk_usage_bytes`],
/// so young snapshots never pay a tree walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub digest: String,
    pub published_secs: u64,
}

/// How one bundle rootfs was provisioned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// Hardware-cloned from a complete snapshot baseline.
    ClonedFromSnapshot(runner_core::fs::cow::CowTreeStats),
    /// Unpacked from layers (first provision, lost publish race, or
    /// clone fallback).
    FreshlyUnpacked,
}

impl SnapshotCache {
    /// Snapshot store rooted at an explicit directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Default root: `$XDG_CACHE_HOME/runner/snapshots`, else
    /// `~/.cache/runner/snapshots` (mirrors [`LayerCache`], whose
    /// `%LOCALAPPDATA%`/`%APPDATA%` ladder applies on Windows).
    pub fn default_dir() -> PathBuf {
        #[cfg(unix)]
        {
            if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|dir| !dir.is_empty()) {
                return PathBuf::from(xdg).join("runner").join("snapshots");
            }
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home)
                    .join(".cache")
                    .join("runner")
                    .join("snapshots");
            }
            PathBuf::from(".runner-snapshots")
        }
        #[cfg(not(unix))]
        {
            for key in ["LOCALAPPDATA", "APPDATA"] {
                if let Some(dir) = std::env::var_os(key) {
                    return PathBuf::from(dir).join("runner").join("snapshots");
                }
            }
            PathBuf::from(".runner-snapshots")
        }
    }

    /// Snapshots nested inside the layer cache directory: same
    /// volume (no cross-device clones), same private permissions,
    /// and hermetic tests stay self-contained. Every layer-cache
    /// walker is name-pattern based, so the extra subdirectory is
    /// invisible to blob accounting.
    pub fn beside_layer_cache(cache: &LayerCache) -> Self {
        Self::new(cache.dir().join("snapshots"))
    }

    /// Store root (created lazily by publishing, never here).
    pub fn dir(&self) -> &Path {
        &self.root
    }

    /// Snapshot directory for a manifest digest (hex-validated, so
    /// garbage digests fail closed before touching disk). Symlink
    /// entries are refused outright: a planted link must never
    /// redirect reads, clones, or deletions outside the store.
    fn snapshot_dir(&self, manifest_digest: &str) -> Result<PathBuf, String> {
        let dir = self.root.join(LayerCache::hex_of(manifest_digest)?);
        if let Ok(meta) = std::fs::symlink_metadata(&dir) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "snapshot path is a symlink, refusing: {}",
                    dir.display()
                ));
            }
        }
        Ok(dir)
    }

    /// Baseline rootfs path for a manifest digest.
    pub fn rootfs_path(&self, manifest_digest: &str) -> Result<PathBuf, String> {
        Ok(self.snapshot_dir(manifest_digest)?.join("rootfs"))
    }

    fn complete_path(&self, manifest_digest: &str) -> Result<PathBuf, String> {
        Ok(self.snapshot_dir(manifest_digest)?.join(COMPLETE_MARKER))
    }

    /// A snapshot is usable only with its publish marker present (a
    /// bare directory is a crashed publish, never a baseline).
    /// Invalid digests simply miss.
    pub fn is_complete(&self, manifest_digest: &str) -> bool {
        self.complete_path(manifest_digest)
            .map(|marker| marker.is_file())
            .unwrap_or(false)
    }

    /// Exclusively claim a staging directory for a missing snapshot:
    /// `Some` workdir wins the publish race, `None` means another
    /// publisher owns it (complete, or fresh work in flight) and the
    /// caller should provision directly instead of waiting.
    pub fn begin_publish(&self, manifest_digest: &str) -> Result<Option<PathBuf>, String> {
        // Validates the digest (garbage fails closed here).
        self.snapshot_dir(manifest_digest)?;
        if self.is_complete(manifest_digest) {
            return Ok(None);
        }
        std::fs::create_dir_all(&self.root)
            .map_err(|e| format!("cannot create snapshot cache {}: {e}", self.root.display()))?;
        super::cache::ensure_signpost(&self.root)?;
        // A fresh staging dir means a live publisher: stand down.
        // Stale ones are crash debris: reap and take over.
        let hex = LayerCache::hex_of(manifest_digest)?;
        for entry in std::fs::read_dir(&self.root)
            .map_err(|e| format!("cannot list snapshot cache {}: {e}", self.root.display()))?
        {
            let entry = entry.map_err(|e| format!("cannot list snapshot cache: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(hex) || !name.contains(".tmp.") {
                continue;
            }
            let fresh = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .map(|mtime| {
                    SystemTime::now().duration_since(mtime).unwrap_or_default()
                        < STALE_SNAPSHOT_GRACE
                })
                .unwrap_or(true);
            if fresh {
                return Ok(None);
            }
            let _ = std::fs::remove_dir_all(entry.path());
        }
        let staging = self.root.join(format!(
            "{hex}.tmp.{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&staging)
            .map_err(|e| format!("cannot stage snapshot {}: {e}", staging.display()))?;
        Ok(Some(staging))
    }

    /// Atomically install a staged rootfs and mark it complete (the
    /// marker lands only after the rename, so readers never see a
    /// torn baseline). Returns the baseline rootfs path. Idempotent:
    /// a concurrently completed snapshot wins, our staging drops,
    /// and the existing baseline is returned untouched.
    pub fn commit_publish(&self, manifest_digest: &str, staging: &Path) -> Result<PathBuf, String> {
        let snapshot = self.snapshot_dir(manifest_digest)?;
        if self.is_complete(manifest_digest) {
            let _ = std::fs::remove_dir_all(staging);
            return Ok(snapshot.join("rootfs"));
        }
        let rootfs = snapshot.join("rootfs");
        let _ = std::fs::remove_dir_all(&rootfs);
        std::fs::create_dir_all(&snapshot)
            .map_err(|e| format!("cannot create snapshot {}: {e}", snapshot.display()))?;
        std::fs::rename(staging, &rootfs)
            .map_err(|e| format!("cannot publish snapshot {}: {e}", snapshot.display()))?;
        std::fs::write(snapshot.join(COMPLETE_MARKER), manifest_digest)
            .map_err(|e| format!("cannot mark snapshot {} complete: {e}", snapshot.display()))?;
        Ok(rootfs)
    }

    /// Drop one snapshot wholesale (GC eviction path).
    pub fn remove(&self, manifest_digest: &str) -> std::io::Result<()> {
        let snapshot = self
            .snapshot_dir(manifest_digest)
            .map_err(std::io::Error::other)?;
        std::fs::remove_dir_all(snapshot)
    }

    /// On-disk bytes under one snapshot (links never followed, so
    /// cycles are impossible and dangling links cost nothing).
    pub fn disk_usage_bytes(&self, manifest_digest: &str) -> u64 {
        let Ok(snapshot) = self.snapshot_dir(manifest_digest) else {
            return 0;
        };
        disk_usage_tree(&snapshot)
    }

    /// Complete snapshots with publish times, for GC age
    /// filtering. Symlink entries never list; incomplete baselines
    /// and unreadable entries never list (the stale reaper owns
    /// those, not eviction).
    pub fn snapshots(&self) -> Vec<SnapshotInfo> {
        let mut infos = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return infos;
        };
        for entry in entries.flatten() {
            let linked = entry
                .file_type()
                .map(|kind| kind.is_symlink())
                .unwrap_or(true);
            if linked {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let digest = format!("sha256:{name}");
            let marker = entry.path().join(COMPLETE_MARKER);
            let published = std::fs::metadata(&marker)
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|mtime| mtime.duration_since(SystemTime::UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs());
            let Some(published_secs) = published else {
                continue;
            };
            infos.push(SnapshotInfo {
                digest,
                published_secs,
            });
        }
        infos
    }

    /// Reap crash debris: staging dirs and marker-less snapshots
    /// older than `grace`. Returns the count reaped; unreadable ages
    /// are preserved, never guessed. Symlink entries are never
    /// touched, whatever they are named.
    pub fn reap_stale(&self, grace: Duration, now: SystemTime) -> usize {
        let mut reaped = 0;
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return reaped;
        };
        for entry in entries.flatten() {
            let linked = entry
                .file_type()
                .map(|kind| kind.is_symlink())
                .unwrap_or(true);
            if linked {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let staging = name.contains(".tmp.");
            let bare = name.len() == 64
                && name.bytes().all(|b| b.is_ascii_hexdigit())
                && !entry.path().join(COMPLETE_MARKER).is_file();
            if !staging && !bare {
                continue;
            }
            let old = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .map(|mtime| now.duration_since(mtime).unwrap_or_default() >= grace)
                .unwrap_or(false);
            if old && std::fs::remove_dir_all(entry.path()).is_ok() {
                reaped += 1;
            }
        }
        reaped
    }
}

/// Drop an empty placeholder directory so a tree clone can take
/// its place (bundle scaffolding pre-creates `rootfs/`). Succeeds
/// silently when missing; non-empty directories are left for the
/// clone to reject loudly — never deleted here.
fn clear_empty_dir(path: &Path) {
    let _ = std::fs::remove_dir(path);
}

/// Directory bytes without following symlinks (iterative worklist:
/// deep trees cannot overflow the call stack).
fn disk_usage_tree(root: &Path) -> u64 {
    let mut bytes = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
                stack.push(entry.path());
            } else if meta.file_type().is_file() {
                bytes += meta.len();
            }
        }
    }
    bytes
}

/// Provision one bundle rootfs: complete snapshots hardware-clone
/// straight in; otherwise unpack once into an exclusively-staged
/// snapshot and clone from there, so every path pays unpack at most
/// once. Lost publish races, clone failures, and publish failures
/// all degrade to a direct unpack with a stderr notice (snapshots
/// are an optimization — provisioning itself never depends on them).
pub fn provision_rootfs<T>(
    snapshots: &SnapshotCache,
    manifest_digest: &str,
    mut unpack: impl FnMut(&Path) -> Result<T, String>,
    bundle_rootfs: &Path,
) -> Result<ProvisionOutcome, String> {
    use runner_core::fs::cow::cow_clone_tree;

    if snapshots.is_complete(manifest_digest) {
        let baseline = snapshots.rootfs_path(manifest_digest)?;
        clear_empty_dir(bundle_rootfs);
        match cow_clone_tree(&baseline, bundle_rootfs) {
            Ok(stats) => return Ok(ProvisionOutcome::ClonedFromSnapshot(stats)),
            Err(e) => eprintln!("[runner::oci] snapshot clone failed ({e}); unpacking directly"),
        }
    }
    match snapshots.begin_publish(manifest_digest) {
        Ok(Some(staging)) => {
            // Staging unpacks fail open: a cache-local problem must
            // never abort the launch when a direct unpack can serve.
            if let Err(e) = unpack(&staging) {
                eprintln!("[runner::oci] snapshot staging failed ({e}); unpacking directly");
                let _ = std::fs::remove_dir_all(&staging);
                unpack(bundle_rootfs)?;
                return Ok(ProvisionOutcome::FreshlyUnpacked);
            }
            match snapshots.commit_publish(manifest_digest, &staging) {
                Ok(rootfs) => {
                    clear_empty_dir(bundle_rootfs);
                    match cow_clone_tree(&rootfs, bundle_rootfs) {
                        Ok(stats) => Ok(ProvisionOutcome::ClonedFromSnapshot(stats)),
                        Err(e) => {
                            eprintln!(
                                "[runner::oci] snapshot clone failed ({e}); unpacking directly"
                            );
                            unpack(bundle_rootfs)?;
                            Ok(ProvisionOutcome::FreshlyUnpacked)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[runner::oci] snapshot publish failed ({e}); unpacking directly");
                    let _ = std::fs::remove_dir_all(&staging);
                    unpack(bundle_rootfs)?;
                    Ok(ProvisionOutcome::FreshlyUnpacked)
                }
            }
        }
        Ok(None) => {
            unpack(bundle_rootfs)?;
            Ok(ProvisionOutcome::FreshlyUnpacked)
        }
        Err(e) => {
            eprintln!("[runner::oci] snapshot staging failed ({e}); unpacking directly");
            unpack(bundle_rootfs)?;
            Ok(ProvisionOutcome::FreshlyUnpacked)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runner_core::test_support::TempDir;

    fn digest(byte: u8) -> String {
        format!(
            "sha256:{}",
            [byte; 32]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    fn cache(dir: &Path) -> SnapshotCache {
        SnapshotCache::new(dir.join("snapshots"))
    }

    fn fake_unpack(marker: &[u8]) -> impl FnMut(&Path) -> Result<(), String> + '_ {
        move |target: &Path| {
            std::fs::create_dir_all(target.join("bin"))
                .map_err(|e| format!("fixture unpack failed: {e}"))?;
            std::fs::write(target.join("bin").join("app"), marker)
                .map_err(|e| format!("fixture unpack failed: {e}"))?;
            Ok(())
        }
    }

    #[test]
    fn snapshot_paths_derive_from_validated_hex() {
        let dir = TempDir::new("snap-paths").unwrap();
        let snapshots = cache(dir.path());
        let rootfs = snapshots.rootfs_path(&digest(1)).unwrap();
        assert!(rootfs.ends_with(Path::new("snapshots").join("01".repeat(32)).join("rootfs")));
        assert!(!snapshots.is_complete(&digest(1)));
        assert!(!snapshots.is_complete("not-a-digest"));
        assert!(snapshots.begin_publish("not-a-digest").is_err());
    }

    #[test]
    fn publish_roundtrip_marks_complete() {
        let dir = TempDir::new("snap-publish").unwrap();
        let snapshots = cache(dir.path());
        let staging = snapshots.begin_publish(&digest(2)).unwrap().unwrap();
        // A second publisher stands down while work is in flight.
        assert!(snapshots.begin_publish(&digest(2)).unwrap().is_none());
        std::fs::write(staging.join("f"), b"bytes").unwrap();
        let rootfs = snapshots.commit_publish(&digest(2), &staging).unwrap();
        assert!(snapshots.is_complete(&digest(2)));
        assert_eq!(std::fs::read(rootfs.join("f")).unwrap(), b"bytes");
        assert!(!staging.exists());
    }

    #[test]
    fn stale_partials_reap_by_grace() {
        let dir = TempDir::new("snap-reap").unwrap();
        let snapshots = cache(dir.path());
        let staging = snapshots.begin_publish(&digest(3)).unwrap().unwrap();
        // Fresh debris survives a generous grace.
        assert_eq!(
            snapshots.reap_stale(Duration::from_secs(3600), SystemTime::now()),
            0
        );
        assert!(staging.exists());
        // Zero grace reaps everything incomplete.
        assert_eq!(snapshots.reap_stale(Duration::ZERO, SystemTime::now()), 1);
        assert!(!staging.exists());
    }

    #[test]
    fn provision_unpacks_once_then_clones() {
        use std::cell::Cell;

        let dir = TempDir::new("snap-provision").unwrap();
        let snapshots = cache(dir.path());
        let unpacks = Cell::new(0u32);
        let mut unpack = |target: &Path| {
            unpacks.set(unpacks.get() + 1);
            fake_unpack(b"v1")(target)
        };
        // First provision unpacks and publishes, then clones the
        // fresh baseline into the bundle.
        let first = dir.path().join("bundle-one");
        let outcome = provision_rootfs(&snapshots, &digest(4), &mut unpack, &first).unwrap();
        assert!(matches!(outcome, ProvisionOutcome::ClonedFromSnapshot(_)));
        assert_eq!(unpacks.get(), 1);
        assert_eq!(std::fs::read(first.join("bin").join("app")).unwrap(), b"v1");
        // Second provision clones without unpacking again.
        let second = dir.path().join("bundle-two");
        let outcome = provision_rootfs(&snapshots, &digest(4), &mut unpack, &second).unwrap();
        assert!(matches!(outcome, ProvisionOutcome::ClonedFromSnapshot(_)));
        assert_eq!(unpacks.get(), 1);
        assert_eq!(
            std::fs::read(second.join("bin").join("app")).unwrap(),
            b"v1"
        );
    }

    #[test]
    fn provision_bypassed_by_lost_race_unpacks_directly() {
        let dir = TempDir::new("snap-race").unwrap();
        let snapshots = cache(dir.path());
        // Simulate a live publisher: an incomplete snapshot blocks
        // our own publish, so we unpack straight into the bundle.
        let _staging = snapshots.begin_publish(&digest(5)).unwrap().unwrap();
        let bundle = dir.path().join("bundle");
        let outcome =
            provision_rootfs(&snapshots, &digest(5), fake_unpack(b"v2"), &bundle).unwrap();
        assert!(matches!(outcome, ProvisionOutcome::FreshlyUnpacked));
        assert_eq!(
            std::fs::read(bundle.join("bin").join("app")).unwrap(),
            b"v2"
        );
    }

    #[test]
    fn provision_recovers_when_clone_rejects_exotics() {
        let dir = TempDir::new("snap-exotic").unwrap();
        let snapshots = cache(dir.path());
        // A complete snapshot containing content the tree walker
        // refuses: provisioning falls back to a direct unpack.
        let staging = snapshots.begin_publish(&digest(6)).unwrap().unwrap();
        #[cfg(unix)]
        {
            // A fifo survives publish (raw bytes) but defeats cloning.
            let fifo = staging.join("pipe");
            let status = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(status.success());
        }
        #[cfg(not(unix))]
        {
            std::fs::write(staging.join("f"), b"plain").unwrap();
        }
        snapshots.commit_publish(&digest(6), &staging).unwrap();
        let bundle = dir.path().join("bundle");
        let outcome =
            provision_rootfs(&snapshots, &digest(6), fake_unpack(b"v3"), &bundle).unwrap();
        #[cfg(unix)]
        assert!(matches!(outcome, ProvisionOutcome::FreshlyUnpacked));
        #[cfg(not(unix))]
        assert!(matches!(outcome, ProvisionOutcome::ClonedFromSnapshot(_)));
        assert_eq!(
            std::fs::read(bundle.join("bin").join("app")).unwrap(),
            b"v3"
        );
    }

    #[test]
    fn snapshot_listing_reports_times_for_gc() {
        let dir = TempDir::new("snap-list").unwrap();
        let snapshots = cache(dir.path());
        let staging = snapshots.begin_publish(&digest(7)).unwrap().unwrap();
        std::fs::write(staging.join("f"), vec![1u8; 100]).unwrap();
        snapshots.commit_publish(&digest(7), &staging).unwrap();
        // Incomplete snapshots never list.
        let _other = snapshots.begin_publish(&digest(8)).unwrap().unwrap();
        let infos = snapshots.snapshots();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].digest, digest(7));
        assert!(infos[0].published_secs > 0);
        // Sizes resolve on demand, never during listing.
        assert!(snapshots.disk_usage_bytes(&digest(7)) >= 100);
    }

    #[test]
    fn provision_clones_into_precreated_empty_rootfs() {
        let dir = TempDir::new("snap-empty-dst").unwrap();
        let snapshots = cache(dir.path());
        // Publish a baseline first (bundle dirs arrive separately).
        let staging = snapshots.begin_publish(&digest(9)).unwrap().unwrap();
        std::fs::write(staging.join("f"), b"base").unwrap();
        snapshots.commit_publish(&digest(9), &staging).unwrap();
        // Bundle scaffolding pre-creates the empty rootfs dir; the
        // clone must take its place, not fall back to unpacking.
        let bundle = dir.path().join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        let unpacks = std::cell::Cell::new(0u32);
        let mut unpack = |target: &Path| {
            unpacks.set(unpacks.get() + 1);
            fake_unpack(b"wrong")(target)
        };
        let outcome = provision_rootfs(&snapshots, &digest(9), &mut unpack, &bundle).unwrap();
        assert!(matches!(outcome, ProvisionOutcome::ClonedFromSnapshot(_)));
        assert_eq!(unpacks.get(), 0);
        assert_eq!(std::fs::read(bundle.join("f")).unwrap(), b"base");
    }

    #[test]
    fn provision_recovers_from_staging_unpack_failure() {
        use std::cell::Cell;

        let dir = TempDir::new("snap-stage-fail").unwrap();
        let snapshots = cache(dir.path());
        let calls = Cell::new(0u32);
        let mut unpack = |target: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                return Err("staging boom".to_string());
            }
            fake_unpack(b"direct")(target)
        };
        // Staging fails, so the launch still provisions by unpacking
        // straight into the bundle (and publishes nothing).
        let bundle = dir.path().join("bundle");
        let outcome = provision_rootfs(&snapshots, &digest(10), &mut unpack, &bundle).unwrap();
        assert!(matches!(outcome, ProvisionOutcome::FreshlyUnpacked));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            std::fs::read(bundle.join("bin").join("app")).unwrap(),
            b"direct"
        );
        assert!(!snapshots.is_complete(&digest(10)));
    }

    #[test]
    fn commit_is_idempotent_under_races() {
        let dir = TempDir::new("snap-idem").unwrap();
        let snapshots = cache(dir.path());
        // Our own staging, plus a rival that completes first.
        let ours = snapshots.begin_publish(&digest(11)).unwrap().unwrap();
        std::fs::write(ours.join("f"), b"ours").unwrap();
        let rival = snapshots.begin_publish(&digest(12)).unwrap().unwrap();
        std::fs::write(rival.join("f"), b"theirs").unwrap();
        snapshots.commit_publish(&digest(12), &rival).unwrap();
        // Committing our staging against their digest adopts their
        // baseline, drops our work, and changes nothing.
        let rootfs = snapshots.commit_publish(&digest(12), &ours).unwrap();
        assert_eq!(std::fs::read(rootfs.join("f")).unwrap(), b"theirs");
        assert!(!ours.exists());
        assert!(snapshots.is_complete(&digest(12)));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_entries_never_enter_the_store() {
        let dir = TempDir::new("snap-links").unwrap();
        let snapshots = cache(dir.path());
        std::fs::create_dir_all(dir.path().join("snapshots")).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"secret").unwrap();
        // A planted link shaped like a snapshot digest.
        let planted = dir.path().join("snapshots").join("ab".repeat(32));
        std::os::unix::fs::symlink(&outside, &planted).unwrap();
        let digest = format!("sha256:{}", "ab".repeat(32));
        assert!(!snapshots.is_complete(&digest));
        assert!(snapshots.snapshots().is_empty());
        assert_eq!(snapshots.disk_usage_bytes(&digest), 0);
        assert!(snapshots.remove(&digest).is_err());
        // Reaping leaves planted links alone.
        assert_eq!(snapshots.reap_stale(Duration::ZERO, SystemTime::now()), 0);
        assert!(outside.join("secret").exists());
    }
}
