//! OCI layer unpacking: gzip-tar blobs stacked into a rootfs with
//! tar-slip defense, symlink confinement, and OCI whiteout handling.
//! Every write lands inside the rootfs (verified through live
//! symlinks) or fails closed; nothing here trusts archive paths.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::mounts::validate_no_home_mount;

/// Cumulative unpacked-bytes ceiling per stacking run (zip-bomb
/// defense; two orders above realistic images).
pub const MAX_UNPACKED_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Per-run extraction counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnpackStats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
    pub hardlinks: u64,
    pub whiteouts: u64,
}

/// Reject absolute paths and `..` escapes; return the cleaned
/// root-relative path. Component-walking (not string matching) so
/// platform separators and `.` segments resolve correctly — and any
/// `..`, even a normalizable one, fails closed per spec.
fn clean_entry_path(raw: &Path) -> Result<PathBuf, String> {
    if raw.is_absolute() {
        return Err(format!("tar entry is absolute: {}", raw.display()));
    }
    let mut clean = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("tar entry escapes rootfs: {}", raw.display()));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("tar entry is absolute: {}", raw.display()));
            }
        }
    }
    Ok(clean)
}

/// Verify `dest` (built as `root.join(clean)`) cannot escape the
/// canonical root through pre-existing symlinks: every existing
/// lexical ancestor below the root must canonicalize inside it.
/// This is the load-bearing barrier — lexical checks alone cannot
/// see writes routed through earlier links.
fn ensure_within(canonical_root: &Path, dest: &Path) -> Result<(), String> {
    let mut current = dest.parent();
    while let Some(dir) = current {
        if dir == canonical_root {
            break;
        }
        // Only links and existing paths can redirect a write; absent
        // paths are created fresh below.
        if dir.is_symlink() || dir.exists() {
            let canonical = std::fs::canonicalize(dir)
                .map_err(|e| format!("cannot resolve {}: {e}", dir.display()))?;
            if !canonical.starts_with(canonical_root) {
                return Err(format!("tar entry escapes rootfs: {}", dest.display()));
            }
            validate_no_home_mount(&[&canonical])?;
        }
        current = dir.parent();
    }
    Ok(())
}

/// Resolve one symlink/hardlink target against the link's clean
/// parent directory, returning a rootfs-relative link body.
/// Container-absolute targets (ubiquitous in real images, e.g.
/// `/etc/alternatives/*`) rewrite to rootfs-relative — identical
/// resolution inside the container, since absolute links mean
/// container-root-relative there. Anything escaping the rootfs floor
/// fails closed. Separators are always `/` so layer content is
/// identical on every host.
fn resolve_link_target(link_parent_rel: &Path, target: &Path) -> Result<PathBuf, String> {
    let escape = || format!("link target escapes rootfs: {}", target.display());
    // Absolute targets resolve from the container root, relative
    // ones from the link's (clean) parent directory.
    let absolute = target.is_absolute();
    let mut stack: Vec<std::ffi::OsString> = if absolute {
        Vec::new()
    } else {
        link_parent_rel
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part.to_os_string()),
                _ => None,
            })
            .collect()
    };
    let mut components = target.components().peekable();
    if absolute {
        // Skip the single leading root marker (already accounted);
        // anything else leading (drive prefixes) is garbage.
        match components.peek() {
            Some(Component::RootDir) => {
                components.next();
            }
            _ => return Err(escape()),
        }
    }
    for component in components {
        match component {
            Component::Normal(part) => stack.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(escape());
                }
            }
            // Absolute markers mid-target (`//x`): garbage.
            Component::RootDir | Component::Prefix(_) => return Err(escape()),
        }
    }
    // Relativize the resolved stack against the parent.
    let from: Vec<std::ffi::OsString> = link_parent_rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            _ => None,
        })
        .collect();
    let common = from
        .iter()
        .zip(stack.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = std::ffi::OsString::new();
    let mut first = true;
    for _ in common..from.len() {
        if !first {
            out.push("/");
        }
        out.push("..");
        first = false;
    }
    for part in &stack[common..] {
        if !first {
            out.push("/");
        }
        out.push(part);
        first = false;
    }
    if out.is_empty() {
        out.push(".");
    }
    Ok(PathBuf::from(out))
}

/// Remove whatever exists at `dest` (file/symlink/dir tree) so upper
/// layers replace lower entries of any kind. Missing paths are fine.
fn clear_dest(dest: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dest) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot stat {}: {e}", dest.display())),
        Ok(meta) => {
            if meta.is_dir() && !meta.file_type().is_symlink() {
                std::fs::remove_dir_all(dest)
                    .map_err(|e| format!("cannot clear {}: {e}", dest.display()))
            } else {
                std::fs::remove_file(dest)
                    .map_err(|e| format!("cannot clear {}: {e}", dest.display()))
            }
        }
    }
}

/// Apply one OCI file whiteout: remove the victim, emit nothing.
fn apply_file_whiteout(dir: &Path, victim: &str) -> Result<(), String> {
    clear_dest(&dir.join(victim))
}

/// Apply one OCI opaque marker: clear the directory's inherited
/// children (the directory itself survives).
fn apply_opaque(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        clear_dest(&entry.path())?;
    }
    Ok(())
}

/// Create one symlink (platform split: Windows distinguishes file
/// and directory links; unix does not).
fn create_symlink(target: &Path, dest: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, dest)
            .map_err(|e| format!("cannot link {}: {e}", dest.display()))
    }
    #[cfg(not(unix))]
    {
        std::os::windows::fs::symlink_file(target, dest)
            .or_else(|_| std::os::windows::fs::symlink_dir(target, dest))
            .map_err(|e| format!("cannot link {}: {e}", dest.display()))
    }
}

/// Unpack one layer stream (gzip sniffed by magic, else raw tar) into
/// an already-validated canonical root, enforcing the byte budget.
fn unpack_archive<R: Read>(
    reader: R,
    canonical_root: &Path,
    budget: &mut u64,
    stats: &mut UnpackStats,
) -> Result<(), String> {
    use std::io::{BufRead, BufReader};
    let mut peek = BufReader::new(reader);
    let gzipped =
        matches!(peek.fill_buf(), Ok(buf) if buf.len() >= 2 && buf[0] == 0x1f && buf[1] == 0x8b);
    let decoded: Box<dyn Read> = if gzipped {
        Box::new(flate2::read::GzDecoder::new(peek))
    } else {
        Box::new(peek)
    };
    let mut archive = tar::Archive::new(decoded);
    let entries = archive
        .entries()
        .map_err(|e| format!("cannot read layer stream: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("cannot read layer entry: {e}"))?;
        let raw = entry
            .path()
            .map_err(|e| format!("cannot decode entry path: {e}"))?
            .into_owned();
        let clean = clean_entry_path(&raw)?;
        if clean.as_os_str().is_empty() {
            continue; // Lone "." entry: the root itself.
        }
        // Whiteouts first: name-matched, never emitted.
        if let Some(name) = clean.file_name().and_then(|name| name.to_str()) {
            if name == ".wh..wh..opq" {
                let dir = clean
                    .parent()
                    .map(|p| canonical_root.join(p))
                    .unwrap_or_else(|| canonical_root.to_path_buf());
                apply_opaque(&dir)?;
                stats.whiteouts += 1;
                continue;
            }
            if let Some(victim) = name.strip_prefix(".wh.") {
                if !victim.is_empty() {
                    let dir = clean
                        .parent()
                        .map(|p| canonical_root.join(p))
                        .unwrap_or_else(|| canonical_root.to_path_buf());
                    apply_file_whiteout(&dir, victim)?;
                    stats.whiteouts += 1;
                    continue;
                }
            }
        }
        let dest = canonical_root.join(&clean);
        ensure_within(canonical_root, &dest)?;
        validate_no_home_mount(&[&dest])?;
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            clear_dest(&dest)?;
            std::fs::create_dir_all(&dest)
                .map_err(|e| format!("cannot create {}: {e}", dest.display()))?;
            stats.dirs += 1;
        } else if kind.is_file() {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            clear_dest(&dest)?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&dest)
                .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
            // Budget-bounded copy: Take caps the read side so an
            // over-budget file fails before filling the disk.
            let mut limited = (&mut entry).take(*budget);
            let wrote = {
                use std::io::Write;
                let mut file = file;
                let wrote = std::io::copy(&mut limited, &mut file)
                    .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
                file.flush()
                    .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
                wrote
            };
            *budget = budget.saturating_sub(wrote);
            // Anything left unread means the budget cut the stream:
            // scrub the partial file, never leave it behind.
            let mut probe = [0u8; 1];
            if entry
                .read(&mut probe)
                .map_err(|e| format!("cannot read layer: {e}"))?
                != 0
            {
                let _ = std::fs::remove_file(&dest);
                return Err("layer exceeds the unpack byte budget".to_string());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mode) = entry.header().mode() {
                    // Honor rwx bits, strip setuid/setgid/sticky.
                    let _ = std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(mode & 0o777),
                    );
                }
            }
            stats.files += 1;
        } else if kind.is_symlink() {
            let target = entry
                .link_name()
                .map_err(|e| format!("cannot decode link target: {e}"))?
                .ok_or_else(|| format!("symlink without target: {}", dest.display()))?
                .into_owned();
            let parent_rel = clean
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            let resolved = resolve_link_target(&parent_rel, &target)?;
            clear_dest(&dest)?;
            create_symlink(&resolved, &dest)?;
            stats.symlinks += 1;
        } else if kind.is_hard_link() {
            let target = entry
                .link_name()
                .map_err(|e| format!("cannot decode link target: {e}"))?
                .ok_or_else(|| format!("hardlink without target: {}", dest.display()))?
                .into_owned();
            // Hardlink targets resolve from the archive root.
            let clean_target = clean_entry_path(&target)?;
            let source = canonical_root.join(&clean_target);
            ensure_within(canonical_root, &source)?;
            if !source.exists() {
                return Err(format!("hardlink target missing: {}", target.display()));
            }
            clear_dest(&dest)?;
            std::fs::hard_link(&source, &dest)
                .map_err(|e| format!("cannot link {}: {e}", dest.display()))?;
            stats.hardlinks += 1;
        } else {
            return Err(format!(
                "unsupported tar entry {:?}: {}",
                kind,
                dest.display()
            ));
        }
    }
    Ok(())
}

/// Stack layer blobs sequentially (`L0 → L1 → …`) into `rootfs`,
/// enforcing the [`MAX_UNPACKED_BYTES`] budget.
pub fn unpack_layers(layer_files: &[PathBuf], rootfs: &Path) -> Result<UnpackStats, String> {
    unpack_layers_with_budget(layer_files, rootfs, MAX_UNPACKED_BYTES)
}

/// [`unpack_layers`] with an explicit byte budget (tests pin small
/// budgets; production uses [`MAX_UNPACKED_BYTES`]).
pub fn unpack_layers_with_budget(
    layer_files: &[PathBuf],
    rootfs: &Path,
    budget: u64,
) -> Result<UnpackStats, String> {
    validate_no_home_mount(&[rootfs])?;
    std::fs::create_dir_all(rootfs)
        .map_err(|e| format!("cannot create {}: {e}", rootfs.display()))?;
    let canonical_root = std::fs::canonicalize(rootfs)
        .map_err(|e| format!("cannot resolve {}: {e}", rootfs.display()))?;
    validate_no_home_mount(&[&canonical_root])?;
    let mut remaining = budget;
    let mut stats = UnpackStats::default();
    for layer in layer_files {
        let file = std::fs::File::open(layer)
            .map_err(|e| format!("cannot open layer {}: {e}", layer.display()))?;
        unpack_archive(file, &canonical_root, &mut remaining, &mut stats)?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one layer blob in memory: files, dirs, symlinks, and raw
    /// entries, optionally gzipped.
    struct LayerRecipe {
        files: Vec<(String, Vec<u8>)>,
        dirs: Vec<String>,
        symlinks: Vec<(String, String)>,
        gzip: bool,
    }

    fn cook_layer(recipe: &LayerRecipe) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for dir in &recipe.dirs {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header
                    .set_path(dir)
                    .map_err(|e| format!("bad dir: {e}"))
                    .unwrap();
                header.set_size(0);
                header.set_cksum();
                builder
                    .append(&header, std::io::empty())
                    .map_err(|e| format!("append dir: {e}"))
                    .unwrap();
            }
            for (path, link) in &recipe.symlinks {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header
                    .set_path(path)
                    .map_err(|e| format!("bad link: {e}"))
                    .unwrap();
                header
                    .set_link_name(link)
                    .map_err(|e| format!("bad link target: {e}"))
                    .unwrap();
                header.set_size(0);
                header.set_cksum();
                builder
                    .append(&header, std::io::empty())
                    .map_err(|e| format!("append link: {e}"))
                    .unwrap();
            }
            for (path, bytes) in &recipe.files {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o755);
                header
                    .set_path(path)
                    .map_err(|e| format!("bad path: {e}"))
                    .unwrap();
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                builder
                    .append(&header, bytes.as_slice())
                    .map_err(|e| format!("append file: {e}"))
                    .unwrap();
            }
            builder.into_inner().unwrap();
        }
        if !recipe.gzip {
            return tar_bytes;
        }
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn write_layer(dir: &Path, name: &str, recipe: &LayerRecipe) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, cook_layer(recipe)).unwrap();
        path
    }

    #[test]
    fn link_targets_rewrite_and_reject() {
        let parent = Path::new("a/b");
        // Relative passthrough + normalization.
        assert_eq!(
            resolve_link_target(parent, Path::new("c")).unwrap(),
            PathBuf::from("c")
        );
        assert_eq!(
            resolve_link_target(parent, Path::new("../x")).unwrap(),
            PathBuf::from("../x")
        );
        // Absolute rewrites to rootfs-relative.
        assert_eq!(
            resolve_link_target(parent, Path::new("/x/y")).unwrap(),
            PathBuf::from("../../x/y")
        );
        assert_eq!(
            resolve_link_target(Path::new(""), Path::new("/x")).unwrap(),
            PathBuf::from("x")
        );
        // Escapes fail closed (".." alone stays inside: a/b/.. = a/).
        assert_eq!(
            resolve_link_target(parent, Path::new("..")).unwrap(),
            PathBuf::from("..")
        );
        // From depth 2, two `..` land exactly at the root (legal);
        // three escape.
        assert_eq!(
            resolve_link_target(parent, Path::new("../../x")).unwrap(),
            PathBuf::from("../../x")
        );
        for bad in ["../../../x", "/../x", "/.."] {
            assert!(
                resolve_link_target(parent, Path::new(bad)).is_err(),
                "{bad}"
            );
        }
        // Self-parent resolves to ".".
        assert_eq!(
            resolve_link_target(Path::new("a"), Path::new(".")).unwrap(),
            PathBuf::from(".")
        );
    }

    #[test]
    fn entry_paths_reject_absolutes_and_parents() {
        assert!(clean_entry_path(Path::new("/etc/passwd")).is_err());
        assert!(clean_entry_path(Path::new("a/../../x")).is_err());
        assert!(clean_entry_path(Path::new("../x")).is_err());
        assert_eq!(
            clean_entry_path(Path::new("./a/./b")).unwrap(),
            PathBuf::from("a/b")
        );
        assert_eq!(
            clean_entry_path(Path::new("a/b")).unwrap(),
            PathBuf::from("a/b")
        );
    }

    #[test]
    fn single_layer_extracts_with_modes() {
        let dir = runner_core::test_support::TempDir::new("unpack-one").unwrap();
        let layer = write_layer(
            dir.path(),
            "l0.tgz",
            &LayerRecipe {
                files: vec![
                    ("bin/run.sh".to_string(), b"#!/bin/sh\necho hi\n".to_vec()),
                    ("etc/motd".to_string(), b"hello\n".to_vec()),
                ],
                dirs: vec!["bin".to_string(), "etc".to_string()],
                symlinks: vec![],
                gzip: true,
            },
        );
        let rootfs = dir.path().join("rootfs");
        let stats = unpack_layers(std::slice::from_ref(&layer), &rootfs).unwrap();
        assert_eq!(stats.files, 2);
        assert_eq!(stats.dirs, 2);
        assert_eq!(
            std::fs::read(rootfs.join("bin/run.sh")).unwrap(),
            b"#!/bin/sh\necho hi\n"
        );
        assert_eq!(std::fs::read(rootfs.join("etc/motd")).unwrap(), b"hello\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(rootfs.join("bin/run.sh"))
                .unwrap()
                .permissions()
                .mode();
            assert_ne!(mode & 0o111, 0, "exec bit must survive");
            assert_eq!(mode & 0o7000, 0, "no setuid bits");
        }
    }

    #[test]
    fn layers_stack_with_overwrites_and_whiteouts() {
        let dir = runner_core::test_support::TempDir::new("unpack-stack").unwrap();
        let lower = write_layer(
            dir.path(),
            "l0.tgz",
            &LayerRecipe {
                files: vec![
                    ("keep.txt".to_string(), b"lower\n".to_vec()),
                    ("gone.txt".to_string(), b"doomed\n".to_vec()),
                    ("swap.txt".to_string(), b"v1\n".to_vec()),
                    ("old/a.txt".to_string(), b"a\n".to_vec()),
                    ("old/b.txt".to_string(), b"b\n".to_vec()),
                ],
                dirs: vec!["old".to_string()],
                symlinks: vec![],
                gzip: true,
            },
        );
        let upper = write_layer(
            dir.path(),
            "l1.tgz",
            &LayerRecipe {
                files: vec![
                    ("swap.txt".to_string(), b"v2\n".to_vec()),
                    (".wh.gone.txt".to_string(), b"".to_vec()),
                    ("old/.wh..wh..opq".to_string(), b"".to_vec()),
                    ("old/c.txt".to_string(), b"c\n".to_vec()),
                ],
                dirs: vec![],
                symlinks: vec![],
                gzip: false,
            },
        );
        let rootfs = dir.path().join("rootfs");
        let stats = unpack_layers(&[lower, upper], &rootfs).unwrap();
        assert_eq!(stats.whiteouts, 2);
        // Untouched lower file survives; overwrite wins.
        assert_eq!(std::fs::read(rootfs.join("keep.txt")).unwrap(), b"lower\n");
        assert_eq!(std::fs::read(rootfs.join("swap.txt")).unwrap(), b"v2\n");
        // File whiteout removed its victim and left no marker.
        assert!(!rootfs.join("gone.txt").exists());
        assert!(!rootfs.join(".wh.gone.txt").exists());
        // Opaque dir cleared its inheritance, then gained the new file.
        assert!(!rootfs.join("old/a.txt").exists());
        assert!(!rootfs.join("old/b.txt").exists());
        assert_eq!(std::fs::read(rootfs.join("old/c.txt")).unwrap(), b"c\n");
        assert!(!rootfs.join("old/.wh..wh..opq").exists());
    }

    /// Hand-rolled USTAR entry: the tar builder refuses hostile
    /// paths itself, but real attackers write raw bytes.
    fn raw_entry(name: &str, body: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", body.len());
        header[124..136].copy_from_slice(size.as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut out = header.to_vec();
        out.extend_from_slice(body);
        while out.len() % 512 != 0 {
            out.push(0);
        }
        out
    }

    fn raw_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, body) in entries {
            tar.extend_from_slice(&raw_entry(name, body));
        }
        tar.extend_from_slice(&[0u8; 1024]);
        tar
    }

    #[test]
    fn tar_slip_entries_fail_closed() {
        let dir = runner_core::test_support::TempDir::new("unpack-slip").unwrap();
        // Absolute path and parent escape, as raw hostile bytes.
        for (name, entry) in [("abs", "/tmp/evil"), ("dotdot", "a/../../evil")] {
            let path = dir.path().join(format!("{name}.tar"));
            std::fs::write(&path, raw_tar(&[(entry, b"x")])).unwrap();
            let rootfs = dir.path().join(format!("rootfs-{name}"));
            let err = unpack_layers(std::slice::from_ref(&path), &rootfs).unwrap_err();
            assert!(err.contains("absolute") || err.contains("escapes"), "{err}");
        }
        // Symlink-mediated escape: link first, hostile write through it.
        // (The absolute target rewrites rootfs-relative, so the write
        // dies on the dangling link — either way nothing leaves.)
        let evil = write_layer(
            dir.path(),
            "evil.tgz",
            &LayerRecipe {
                files: vec![("sub/evil".to_string(), b"x".to_vec())],
                dirs: vec![],
                symlinks: vec![("sub".to_string(), "/tmp".to_string())],
                gzip: true,
            },
        );
        let rootfs = dir.path().join("rootfs-evil");
        assert!(unpack_layers(std::slice::from_ref(&evil), &rootfs).is_err());
        assert!(!Path::new("/tmp/evil").exists());
        // Host /home is never a valid target root.
        let home = PathBuf::from("/home/nobody/rootfs");
        assert!(unpack_layers(&[], &home).is_err());
        // Missing layer blobs fail closed (corrupt pull, never skip).
        let rootfs = dir.path().join("rootfs-missing");
        let err = unpack_layers(&[dir.path().join("nope.tgz")], &rootfs).unwrap_err();
        assert!(err.contains("cannot open layer"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_within_sees_through_live_symlinks() {
        let dir = runner_core::test_support::TempDir::new("unpack-confine").unwrap();
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("real")).unwrap();
        let canonical_root = std::fs::canonicalize(&rootfs).unwrap();
        // A live link to the outside poisons writes beneath it.
        std::os::unix::fs::symlink("/tmp", rootfs.join("out")).unwrap();
        let err = ensure_within(&canonical_root, &canonical_root.join("out/evil")).unwrap_err();
        assert!(err.contains("escapes"), "{err}");
        // A live link staying inside passes.
        std::os::unix::fs::symlink("real", rootfs.join("in")).unwrap();
        assert!(ensure_within(&canonical_root, &canonical_root.join("in/ok")).is_ok());
        // Plain paths pass.
        assert!(ensure_within(&canonical_root, &canonical_root.join("a/b")).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn relative_symlinks_land_and_absolute_rewrite() {
        let dir = runner_core::test_support::TempDir::new("unpack-links").unwrap();
        let layer = write_layer(
            dir.path(),
            "l0.tgz",
            &LayerRecipe {
                files: vec![("real.txt".to_string(), b"data\n".to_vec())],
                dirs: vec![],
                symlinks: vec![
                    ("rel.txt".to_string(), "real.txt".to_string()),
                    ("abs.txt".to_string(), "/real.txt".to_string()),
                ],
                gzip: true,
            },
        );
        let rootfs = dir.path().join("rootfs");
        let stats = unpack_layers(std::slice::from_ref(&layer), &rootfs).unwrap();
        assert_eq!(stats.symlinks, 2);
        // Both resolve to the same content (absolute rewritten relative).
        assert_eq!(std::fs::read(rootfs.join("rel.txt")).unwrap(), b"data\n");
        assert_eq!(std::fs::read(rootfs.join("abs.txt")).unwrap(), b"data\n");
        assert_eq!(
            std::fs::read_link(rootfs.join("abs.txt")).unwrap(),
            PathBuf::from("real.txt")
        );
    }

    #[test]
    fn byte_budget_aborts_before_disk_fill() {
        let dir = runner_core::test_support::TempDir::new("unpack-budget").unwrap();
        let layer = write_layer(
            dir.path(),
            "l0.tgz",
            &LayerRecipe {
                files: vec![("big.bin".to_string(), vec![0u8; 1024])],
                dirs: vec![],
                symlinks: vec![],
                gzip: true,
            },
        );
        let rootfs = dir.path().join("rootfs");
        let err =
            unpack_layers_with_budget(std::slice::from_ref(&layer), &rootfs, 100).unwrap_err();
        assert!(err.contains("budget"), "{err}");
        // Partial file removed, not left behind.
        assert!(!rootfs.join("big.bin").exists());
    }
}
