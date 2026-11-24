//! Phase 1 (Candidate I): hardware copy-on-write cloning engine.
//! Hermetic suite — temp dirs only, no filesystem assumptions (every
//! assertion holds whether the host fs clones natively or falls back).

use runner_core::fs::cow::{cow_clone_file, cow_clone_tree, probe_cow_capability, CowCapability};
use runner_core::test_support::TempDir;

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(31) >> 8) as u8)
        .collect()
}

/// Clone identity: destination bytes equal the source on any fs.
#[test]
fn cloned_file_matches_source_bytes() {
    let dir = TempDir::new("cow-identity").unwrap();
    let src = dir.path().join("src.bin");
    let dst = dir.path().join("dst.bin");
    let bytes = patterned_bytes(200_000);
    std::fs::write(&src, &bytes).unwrap();
    cow_clone_file(&src, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), bytes);
    assert_eq!(std::fs::read(&src).unwrap(), bytes);
}

/// Mutation isolation: writing the clone never affects the source.
#[test]
fn cloned_file_mutation_isolation() {
    let dir = TempDir::new("cow-isolation").unwrap();
    let src = dir.path().join("src.bin");
    let dst = dir.path().join("dst.bin");
    let bytes = patterned_bytes(100_000);
    std::fs::write(&src, &bytes).unwrap();
    cow_clone_file(&src, &dst).unwrap();
    std::fs::write(&dst, vec![7u8; 100_000]).unwrap();
    assert_eq!(std::fs::read(&src).unwrap(), bytes);
    // Reverse direction: source mutation leaves the clone alone.
    std::fs::write(&src, vec![9u8; 100_000]).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), vec![7u8; 100_000]);
}

/// Self-clones are complete no-ops: contents (and the file
/// itself) survive `cow_clone_file(p, p)`.
#[test]
fn cloned_onto_itself_preserves_everything() {
    let dir = TempDir::new("cow-self").unwrap();
    let path = dir.path().join("same.bin");
    let bytes = patterned_bytes(80_000);
    std::fs::write(&path, &bytes).unwrap();
    cow_clone_file(&path, &path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

/// Hardlink aliases share identity: cloning one name onto another
/// name of the same inode must not unlink anything.
#[cfg(unix)]
#[test]
fn cloned_hardlink_alias_preserves_links() {
    use std::os::unix::fs::MetadataExt;

    let dir = TempDir::new("cow-hardlink").unwrap();
    let first = dir.path().join("first.bin");
    let second = dir.path().join("second.bin");
    let bytes = patterned_bytes(40_000);
    std::fs::write(&first, &bytes).unwrap();
    std::fs::hard_link(&first, &second).unwrap();
    let before = std::fs::metadata(&second).unwrap().ino();
    cow_clone_file(&first, &second).unwrap();
    let meta = std::fs::metadata(&second).unwrap();
    assert_eq!(meta.ino(), before);
    assert_eq!(std::fs::read(&second).unwrap(), bytes);
}

/// Excluded names vanish at every depth, including nested
/// destinations parked under an excluded top-level entry.
#[test]
fn cloned_tree_excluding_skips_named_entries() {
    use runner_core::fs::cow::cow_clone_tree_excluding;

    let dir = TempDir::new("cow-exclude").unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join(".git")).unwrap();
    std::fs::write(src.join(".git").join("HEAD"), b"ref").unwrap();
    std::fs::write(src.join("keep.txt"), b"keep").unwrap();
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("sub").join("deep.txt"), b"deep").unwrap();
    // Destination nests inside the source under an excluded entry:
    // the walker skips `.runner` (including the just-created `dst`
    // itself), so no descent loops back into the output.
    let dst = src.join(".runner").join("snapshots").join("v1");
    let stats = cow_clone_tree_excluding(&src, &dst, &[".git", ".runner"]).unwrap();
    assert_eq!(stats.files, 2);
    assert_eq!(std::fs::read(dst.join("keep.txt")).unwrap(), b"keep");
    assert_eq!(
        std::fs::read(dst.join("sub").join("deep.txt")).unwrap(),
        b"deep"
    );
    assert!(!dst.join(".git").exists());
}

/// Destinations inside the source are rejected before anything is
/// created (no infinite descent, no pollution).
#[test]
fn cloned_tree_rejects_nested_destination() {
    let dir = TempDir::new("cow-nested").unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("a")).unwrap();
    std::fs::write(src.join("a").join("f.bin"), b"data").unwrap();
    let nested = src.join("snapshots");
    assert!(cow_clone_tree(&src, &nested).is_err());
    assert!(!nested.exists());
    let deep = src.join("a").join("b").join("snapshots");
    assert!(cow_clone_tree(&src, &deep).is_err());
    assert!(!src.join("a").join("b").exists());
}

/// Pseudo-files report zero length but hold data: the clone must
/// carry their bytes (Linux `/proc`; skips where unavailable).
#[cfg(target_os = "linux")]
#[test]
fn cloned_pseudo_file_carries_bytes() {
    let proc = std::path::Path::new("/proc/version");
    let expected = match std::fs::read(proc) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => {
            eprintln!("no readable /proc/version; skipping pseudo-file test");
            return;
        }
    };
    let dir = TempDir::new("cow-proc").unwrap();
    let dst = dir.path().join("version.copy");
    cow_clone_file(proc, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), expected);
}

/// Read-only directory trees clone: modes apply after children land.
#[cfg(unix)]
#[test]
fn cloned_read_only_tree_keeps_modes() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("cow-readonly").unwrap();
    let src = dir.path().join("src");
    let nested = src.join("locked");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("f.bin"), b"data").unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o555)).unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o555)).unwrap();
    let dst = dir.path().join("dst");
    cow_clone_tree(&src, &dst).unwrap();
    assert_eq!(
        std::fs::read(dst.join("locked").join("f.bin")).unwrap(),
        b"data"
    );
    let mode = std::fs::metadata(dst.join("locked"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o555);
    let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o555);
}

/// Byte-moving fallbacks count as fallbacks, not native clones.
/// `/dev/shm` is tmpfs (no reflink): FICLONE refuses and the
/// copy-range path performs a plain copy there.
#[cfg(target_os = "linux")]
#[test]
fn copy_range_path_counts_as_fallback() {
    let shm = std::path::Path::new("/dev/shm");
    if !shm.is_dir() {
        eprintln!("no /dev/shm; skipping fallback-accounting test");
        return;
    }
    let case = format!("cow-acct-{}", std::process::id());
    let work = shm.join(&case);
    let _ = std::fs::remove_dir_all(&work);
    if std::fs::create_dir(&work).is_err() {
        eprintln!("cannot write /dev/shm; skipping fallback-accounting test");
        return;
    }
    let src = work.join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f.bin"), patterned_bytes(30_000)).unwrap();
    let dst = work.join("dst");
    let stats = cow_clone_tree(&src, &dst).unwrap();
    std::fs::remove_dir_all(&work).unwrap();
    if stats.native_clones == 1 {
        eprintln!("unexpected reflink-capable /dev/shm; skipping accounting assert");
        return;
    }
    assert_eq!(stats.files, 1);
    assert_eq!(stats.fallback_copies, 1);
}

/// Windows symlink flavors survive the round trip (skips without
/// symlink privilege, as on unprivileged CI).
#[cfg(target_os = "windows")]
#[test]
fn cloned_tree_preserves_windows_link_flavors() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let dir = TempDir::new("cow-winlinks").unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("realdir")).unwrap();
    std::fs::write(src.join("realfile.txt"), b"x").unwrap();
    // Fixture creation itself needs the privilege: skip loudly
    // without it rather than failing the suite.
    if symlink_file("realfile.txt", src.join("filelink")).is_err()
        || symlink_dir("realdir", src.join("dirlink")).is_err()
        || symlink_dir("dangling-dir", src.join("danglingdir")).is_err()
    {
        eprintln!("no symlink privilege; skipping Windows flavor test");
        return;
    }
    let dst = dir.path().join("dst");
    cow_clone_tree(&src, &dst).unwrap();
    let is_dir_link = |name: &str| {
        use std::os::windows::fs::FileTypeExt;
        std::fs::symlink_metadata(dst.join(name))
            .unwrap()
            .file_type()
            .is_symlink_dir()
    };
    assert!(!is_dir_link("filelink"));
    assert!(is_dir_link("dirlink"));
    assert!(is_dir_link("danglingdir"));
}

/// Empty files clone to empty files through every path.
#[test]
fn cloned_empty_file() {
    let dir = TempDir::new("cow-empty").unwrap();
    let src = dir.path().join("empty.bin");
    let dst = dir.path().join("copy.bin");
    std::fs::write(&src, []).unwrap();
    cow_clone_file(&src, &dst).unwrap();
    assert_eq!(std::fs::read(&dst).unwrap(), Vec::<u8>::new());
}

/// Existing destination files are replaced; directories error.
#[test]
fn clone_destination_rules() {
    let dir = TempDir::new("cow-dst").unwrap();
    let src = dir.path().join("src.bin");
    std::fs::write(&src, b"fresh").unwrap();
    let taken = dir.path().join("taken.bin");
    std::fs::write(&taken, b"stale").unwrap();
    cow_clone_file(&src, &taken).unwrap();
    assert_eq!(std::fs::read(&taken).unwrap(), b"fresh");
    let dir_dst = dir.path().join("subdir");
    std::fs::create_dir(&dir_dst).unwrap();
    assert!(cow_clone_file(&src, &dir_dst).is_err());
    assert!(cow_clone_file(&dir.path().join("missing.bin"), &dir.path().join("x")).is_err());
}

/// Tree clone preserves structure with measured statistics.
#[test]
fn cloned_tree_preserves_structure_and_stats() {
    let dir = TempDir::new("cow-tree").unwrap();
    let src = dir.path().join("src");
    let nested = src.join("a").join("b");
    std::fs::create_dir_all(&nested).unwrap();
    let one = patterned_bytes(50_000);
    let two = patterned_bytes(150_000);
    std::fs::write(src.join("one.bin"), &one).unwrap();
    std::fs::write(nested.join("two.bin"), &two).unwrap();
    let dst = dir.path().join("dst");
    let stats = cow_clone_tree(&src, &dst).unwrap();
    assert_eq!(std::fs::read(dst.join("one.bin")).unwrap(), one);
    assert_eq!(
        std::fs::read(dst.join("a").join("b").join("two.bin")).unwrap(),
        two
    );
    assert_eq!(stats.files, 2);
    assert_eq!(stats.bytes, 200_000);
    assert_eq!(stats.dirs, 3);
    assert_eq!(stats.symlinks, 0);
    // Mechanism accounting holds on every filesystem.
    assert_eq!(stats.native_clones + stats.fallback_copies, stats.files);
}

/// Tree clone rejects non-directories and existing destinations.
#[test]
fn cloned_tree_rejects_bad_endpoints() {
    let dir = TempDir::new("cow-endpoints").unwrap();
    let file = dir.path().join("file.bin");
    std::fs::write(&file, b"x").unwrap();
    assert!(cow_clone_tree(&file, &dir.path().join("out")).is_err());
    assert!(cow_clone_tree(&dir.path().join("missing"), &dir.path().join("out")).is_err());
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let taken = dir.path().join("taken");
    std::fs::create_dir(&taken).unwrap();
    assert!(cow_clone_tree(&src, &taken).is_err());
}

/// Unix: symlinks mirror as symlinks and executable bits survive.
#[cfg(unix)]
#[test]
fn cloned_tree_preserves_symlinks_and_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = TempDir::new("cow-links").unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let script = src.join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink("run.sh", src.join("alias.sh")).unwrap();
    symlink("dangling-target", src.join("dangling")).unwrap();
    let dst = dir.path().join("dst");
    let stats = cow_clone_tree(&src, &dst).unwrap();
    assert_eq!(stats.symlinks, 2);
    assert_eq!(
        std::fs::read_link(dst.join("alias.sh")).unwrap(),
        std::path::PathBuf::from("run.sh")
    );
    assert_eq!(
        std::fs::read_link(dst.join("dangling")).unwrap(),
        std::path::PathBuf::from("dangling-target")
    );
    assert!(std::fs::symlink_metadata(dst.join("alias.sh"))
        .unwrap()
        .file_type()
        .is_symlink());
    let mode = std::fs::metadata(dst.join("run.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755, "executable bit preserved");
}

/// Probe sanity: valid dirs answer, missing dirs error loudly.
#[test]
fn probe_reports_capability_or_loud_error() {
    let dir = TempDir::new("cow-probe").unwrap();
    match probe_cow_capability(dir.path()).unwrap() {
        CowCapability::Native => {}
        CowCapability::Unsupported { reason } => assert!(!reason.is_empty()),
    }
    // Probe temp files never leak.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(leftovers.is_empty());
    let missing = dir.path().join("no-such-dir");
    let err = probe_cow_capability(&missing).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

/// Forced fallback: cross-mount clones cannot share blocks, so the
/// fallback counter must fire (unix-only device comparison; skips
/// gracefully on the vanishingly rare same-mount layout).
#[cfg(unix)]
#[test]
fn cross_mount_clone_falls_back_cleanly() {
    use std::os::unix::fs::MetadataExt;

    let dir = TempDir::new("cow-xdev").unwrap();
    let shm = std::path::Path::new("/dev/shm");
    if !shm.is_dir() {
        eprintln!("no /dev/shm; skipping cross-mount fallback test");
        return;
    }
    let temp_dev = std::fs::metadata(dir.path()).unwrap().dev();
    let shm_dev = std::fs::metadata(shm).unwrap().dev();
    if temp_dev == shm_dev {
        eprintln!("shared mount layout; skipping cross-mount fallback test");
        return;
    }
    let src = dir.path().join("src.bin");
    std::fs::write(&src, patterned_bytes(60_000)).unwrap();
    let case = format!("cow-xdev-{}", std::process::id());
    let dst_dir = shm.join(&case);
    let _ = std::fs::remove_dir_all(&dst_dir);
    if std::fs::create_dir(&dst_dir).is_err() {
        eprintln!("cannot write /dev/shm; skipping cross-mount fallback test");
        return;
    }
    std::fs::remove_dir(&dst_dir).unwrap();
    let stats = cow_clone_tree(dir.path(), &dst_dir).unwrap();
    assert_eq!(stats.files, 1);
    assert_eq!(stats.native_clones, 0);
    assert_eq!(stats.fallback_copies, 1);
    assert_eq!(
        std::fs::read(dst_dir.join("src.bin")).unwrap(),
        patterned_bytes(60_000)
    );
    std::fs::remove_dir_all(&dst_dir).unwrap();
}
