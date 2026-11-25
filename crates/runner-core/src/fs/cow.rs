//! Hardware copy-on-write cloning: instant, space-efficient file
//! and tree duplication on filesystems with native block cloning
//! (APFS, Btrfs/XFS with reflink, ReFS), degrading cleanly to
//! `std::fs::copy` everywhere else. Detection is empirical — a real
//! micro-clone is attempted — never an fstype allowlist (XFS without
//! `reflink=1` reports XFS but cannot clone).
//!
//! [`probe_cow_capability`] answers whether a directory supports
//! native cloning; [`cow_clone_file`] duplicates one file;
//! [`cow_clone_tree`] duplicates whole trees with modes, symlinks,
//! and measured statistics.

use std::path::{Path, PathBuf};

/// Native-clone support for one directory, as proven by an actual
/// micro-clone (not by filesystem-name matching).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CowCapability {
    /// A test clone inside the directory shared blocks natively.
    Native,
    /// Native cloning failed here; clones fall back to plain copies.
    Unsupported {
        /// Short human reason (the underlying OS error text).
        reason: String,
    },
}

/// How one file clone was performed (measured, never inferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloneMechanism {
    Native,
    Fallback,
}

/// Outcome of one [`cow_clone_tree`]: content and structure counts
/// plus the measured native/fallback split (`native_clones +
/// fallback_copies` always equals `files`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CowTreeStats {
    /// Regular files duplicated.
    pub files: u64,
    /// Sum of duplicated file sizes in bytes.
    pub bytes: u64,
    /// Directories created (including the root).
    pub dirs: u64,
    /// Symlinks mirrored.
    pub symlinks: u64,
    /// Files that shared blocks natively.
    pub native_clones: u64,
    /// Files that fell back to plain copies.
    pub fallback_copies: u64,
}

/// Probe native-clone support by cloning 64 KiB of patterned bytes
/// between two temp files inside `dir` (same filesystem
/// guaranteed), verifying the bytes, and removing both. Returns
/// [`CowCapability::Unsupported`] when the clone attempt fails for
/// any reason; returns `Err` only when the probe itself cannot run
/// (missing or unwritable directory).
pub fn probe_cow_capability(dir: &Path) -> std::io::Result<CowCapability> {
    if !dir.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("clone probe directory is missing: {}", dir.display()),
        ));
    }
    let tag = format!(
        "cow-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0)
    );
    let src = dir.join(format!("{tag}.src"));
    let dst = dir.join(format!("{tag}.dst"));
    let outcome = probe_inner(&src, &dst);
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    outcome
}

/// Write patterned bytes, attempt a native clone, and verify the
/// copy byte-for-byte. Any failure degrades to `Unsupported`.
fn probe_inner(src: &Path, dst: &Path) -> std::io::Result<CowCapability> {
    let pattern: Vec<u8> = (0..65536u32)
        .map(|i| (i.wrapping_mul(31) >> 8) as u8)
        .collect();
    std::fs::write(src, &pattern).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("clone probe cannot write {}: {e}", src.display()),
        )
    })?;
    match cow_clone_file_native(src, dst) {
        Ok(()) => match std::fs::read(dst) {
            Ok(back) if back == pattern => Ok(CowCapability::Native),
            Ok(_) => Ok(CowCapability::Unsupported {
                reason: "probe clone bytes differ".to_string(),
            }),
            Err(e) => Ok(CowCapability::Unsupported {
                reason: format!("probe clone unreadable: {e}"),
            }),
        },
        Err(e) => Ok(CowCapability::Unsupported {
            reason: e.to_string(),
        }),
    }
}

/// Best-effort filesystem type label for a path (for
/// diagnostics; never fails — every error degrades to `"unknown"`,
/// and unlisted Linux magic numbers render as `unknown(0x…)`).
pub fn filesystem_type(path: &Path) -> String {
    filesystem_type_inner(path).unwrap_or_else(|_| "unknown".to_string())
}

/// Linux filesystem label from `statfs` `f_type` (magic values per
/// statfs(2); unlisted values stay honest hex, never invented).
#[cfg(target_os = "linux")]
fn filesystem_type_inner(path: &Path) -> std::io::Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path holds NUL for statfs",
        )
    })?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid path pointer, valid out-struct.
    if unsafe { libc::statfs(path_c.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(match stat.f_type as u64 {
        0x9123_683e => "btrfs".to_string(),
        0x5846_5342 => "xfs".to_string(),
        0xef53 => "ext".to_string(),
        0x0102_1994 => "tmpfs".to_string(),
        0x794c_7630 => "overlayfs".to_string(),
        0x6969 => "nfs".to_string(),
        0x4d44 => "vfat".to_string(),
        0x6573_5546 => "fuse".to_string(),
        other => format!("unknown(0x{other:x})"),
    })
}

/// macOS filesystem label from `statfs` `f_fstypename` (`apfs`,
/// `hfs`, `nfs`, …). The field is NUL-padded, not NUL-guaranteed,
/// so the length is measured, never assumed.
#[cfg(target_os = "macos")]
fn filesystem_type_inner(path: &Path) -> std::io::Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path holds NUL for statfs",
        )
    })?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid path pointer, valid out-struct.
    if unsafe { libc::statfs(path_c.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = stat
        .f_fstypename
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(stat.f_fstypename.len());
    let bytes: Vec<u8> = stat.f_fstypename[..len].iter().map(|&c| c as u8).collect();
    String::from_utf8(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "filesystem name is not UTF-8",
        )
    })
}

/// Windows filesystem label (`NTFS`, `ReFS`, …) via
/// `GetVolumeInformationW` on the canonical volume root. Unneeded
/// outputs stay NULL; any failure degrades to `"unknown"`.
#[cfg(target_os = "windows")]
fn filesystem_type_inner(path: &Path) -> std::io::Result<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;

    let root = volume_root(&std::fs::canonicalize(path)?).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cannot determine volume root",
        )
    })?;
    let root_w: Vec<u16> = root.encode_wide().chain(std::iter::once(0)).collect();
    let mut name = [0u16; 64];
    // SAFETY: valid root + sized out-buffer; unneeded outputs NULL.
    let ok = unsafe {
        GetVolumeInformationW(
            root_w.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    String::from_utf16(&name[..len]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "filesystem name is not UTF-16",
        )
    })
}

/// Volume root with trailing backslash (`C:\`, `\\server\share\`)
/// from a canonical Windows path (verbatim and plain forms).
#[cfg(target_os = "windows")]
fn volume_root(canonical: &Path) -> Option<std::ffi::OsString> {
    use std::path::{Component, Prefix};

    let prefix = match canonical.components().next()? {
        Component::Prefix(prefix) => prefix,
        _ => return None,
    };
    match prefix.kind() {
        Prefix::Disk(disk) | Prefix::VerbatimDisk(disk) => {
            Some(std::ffi::OsString::from(format!("{}:\\", disk as char)))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut root = std::ffi::OsString::from(r"\\");
            root.push(server);
            root.push(r"\");
            root.push(share);
            root.push(r"\");
            Some(root)
        }
        _ => None,
    }
}

/// Filesystem labels are unimplemented off the big three (the
/// public wrapper degrades to `"unknown"`).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn filesystem_type_inner(_path: &Path) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "filesystem type unavailable on this platform",
    ))
}

/// Clone one file's bytes natively or report the OS error (no
/// fallback here — the caller decides). Both paths must live on the
/// same filesystem; `dst` must not exist.
fn cow_clone_file_native(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        clonefile_copy(src, dst)
    }
    #[cfg(target_os = "linux")]
    {
        ficlone_copy(src, dst)
    }
    #[cfg(target_os = "windows")]
    {
        duplicate_extents_copy(src, dst)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (src, dst);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native cloning unavailable on this platform",
        ))
    }
}

/// macOS block clone via `clonefile(2)` (APFS shares extents;
/// anything else fails and the caller falls back).
#[cfg(target_os = "macos")]
fn clonefile_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let src_c = std::ffi::CString::new(src.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("clone source holds NUL: {}", src.display()),
        )
    })?;
    let dst_c = std::ffi::CString::new(dst.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("clone destination holds NUL: {}", dst.display()),
        )
    })?;
    // SAFETY: both pointers reference live NUL-terminated paths;
    // flags 0 requests a plain data clone (symlinks followed).
    let ret = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Linux block clone via `FICLONE` ioctl (Btrfs, XFS-with-reflink).
/// The destination fd carries the source mode so inodes agree even
/// on filesystems that clone metadata sparsely.
#[cfg(target_os = "linux")]
fn ficlone_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    let src_file = std::fs::File::open(src)?;
    let mode = src_file.metadata()?.permissions().mode();
    let dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode & 0o7777)
        .open(dst)?;
    // SAFETY: both fds are live open files; FICLONE takes the source
    // fd by value and touches nothing else.
    let ret = unsafe { libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Linux content copy via looped `copy_file_range` (still shares
/// extents where the filesystem allows, and succeeds on plain
/// filesystems where `FICLONE` refuses). Returns the bytes moved.
#[cfg(target_os = "linux")]
fn copy_file_range_loop(
    src: &std::fs::File,
    dst: &std::fs::File,
    len: u64,
) -> std::io::Result<u64> {
    use std::os::unix::io::AsRawFd;

    let mut remaining = len;
    let mut moved = 0u64;
    while remaining > 0 {
        // SAFETY: fds are live; NULL offsets advance the file
        // positions; flags 0. Short returns are normal (loop on).
        let n = unsafe {
            libc::copy_file_range(
                src.as_raw_fd(),
                std::ptr::null_mut(),
                dst.as_raw_fd(),
                std::ptr::null_mut(),
                remaining.min(1 << 30) as usize,
                0,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        remaining -= n as u64;
        moved += n as u64;
    }
    Ok(moved)
}

/// Windows block clone via `FSCTL_DUPLICATE_EXTENTS_TO_FILE`
/// (ReFS shares extents; NTFS fails and the caller falls back).
#[cfg(target_os = "windows")]
fn duplicate_extents_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, SetEndOfFile, SetFilePointerEx, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
        FILE_BEGIN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        DUPLICATE_EXTENTS_DATA, FSCTL_DUPLICATE_EXTENTS_TO_FILE,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    /// RAII handle (cleanup must survive every early return below).
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: owned live handle, closed exactly once.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    // SAFETY: NUL-terminated UTF-16 paths; default security/dflags.
    let src_w = wide(src);
    let src_handle = HandleGuard(unsafe {
        CreateFileW(
            src_w.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    });
    if src_handle.0 == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let len = std::fs::metadata(src).map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        std::fs::write(dst, [])?;
        return Ok(());
    }
    let dst_w = wide(dst);
    let dst_handle = HandleGuard(unsafe {
        CreateFileW(
            dst_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    });
    if dst_handle.0 == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    // The extent call requires room: pre-size the destination to the
    // full length first (failures here fall through to the plain
    // copy like any other native error).
    // SAFETY: live handle; move method is a valid constant.
    let positioned =
        unsafe { SetFilePointerEx(dst_handle.0, len as i64, std::ptr::null_mut(), FILE_BEGIN) };
    // SAFETY: live handle.
    let sized = unsafe { SetEndOfFile(dst_handle.0) };
    if positioned == 0 || sized == 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let extents = DUPLICATE_EXTENTS_DATA {
        FileHandle: src_handle.0,
        SourceFileOffset: 0,
        TargetFileOffset: 0,
        ByteCount: len as i64,
    };
    let mut returned = 0u32;
    // SAFETY: live handles, valid input struct, no output buffer,
    // synchronous (NULL overlapped).
    let ok = unsafe {
        DeviceIoControl(
            dst_handle.0,
            FSCTL_DUPLICATE_EXTENTS_TO_FILE,
            &extents as *const DUPLICATE_EXTENTS_DATA as *const core::ffi::c_void,
            std::mem::size_of::<DUPLICATE_EXTENTS_DATA>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ))
    }
}

/// Clone one regular file, sharing blocks natively where the
/// filesystem allows and falling back to a plain copy everywhere
/// else (unsupported filesystems, cross-device boundaries, exotic
/// errors — only the final fallback's error surfaces). Symlinks are
/// followed (the destination is always a real file); an existing
/// destination file is replaced, a destination directory errors.
/// Permission bits mirror the source on completion.
pub fn cow_clone_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    cow_clone_file_inner(src, dst).map(|_| ())
}

/// File identity for endpoint comparison: `(device, inode)` on
/// unix, `(volume, file index)` on Windows. Never follows the final
/// link (reparse-point handles on Windows), so replacing a symlink
/// with a real file stays legitimate while hardlink and path
/// aliases compare equal. Errors when the path cannot be stated.
#[cfg(unix)]
fn file_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

/// File identity for endpoint comparison on Windows (see the unix
/// twin for semantics).
#[cfg(target_os = "windows")]
fn file_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, GENERIC_READ, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: NUL-terminated path; backup semantics open
    // directories too; reparse-point handles never follow links.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: live handle, valid out-struct.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    // SAFETY: owned live handle, closed exactly once.
    unsafe {
        CloseHandle(handle);
    }
    if ok == 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Ok((info.dwVolumeSerialNumber as u64, index))
}

/// Endpoint identity on other platforms: unstated (aliases proceed
/// to the normal path; tier-3 without link-semantics coverage).
#[cfg(not(any(unix, target_os = "windows")))]
fn file_identity(_path: &Path) -> std::io::Result<(u64, u64)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file identity unavailable on this platform",
    ))
}

/// Clone one file, reporting which mechanism performed the copy
/// (drives [`CowTreeStats`]; the public wrapper discards it).
fn cow_clone_file_inner(src: &Path, dst: &Path) -> std::io::Result<CloneMechanism> {
    // Endpoint identity first: cloning a file onto itself (same
    // path, hardlink, or alias) is a complete no-op — deleting `dst`
    // first would destroy the source. A fully shared file counts as
    // native; unstatable endpoints simply proceed.
    if let (Ok(src_id), Ok(dst_id)) = (file_identity(src), file_identity(dst)) {
        if src_id == dst_id {
            return Ok(CloneMechanism::Native);
        }
    }
    match std::fs::symlink_metadata(dst) {
        Ok(meta) if meta.file_type().is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("clone destination is a directory: {}", dst.display()),
            ));
        }
        Ok(_) => remove_file_or_symlink(dst)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // No zero-length short-circuit: pseudo-files (`/proc/*`)
    // report `len == 0` while holding readable data, so every path
    // below must actually move bytes (or fail loudly trying).
    // Length feeds only the Linux middle fallback below.
    #[cfg(target_os = "linux")]
    let src_len = std::fs::metadata(src).map(|meta| meta.len()).unwrap_or(0);
    if cow_clone_file_native(src, dst).is_ok() {
        mirror_mode(src, dst)?;
        return Ok(CloneMechanism::Native);
    }
    // Native refused: Linux retries via copy_file_range before the
    // plain copy. This path moves bytes rather than sharing extents
    // on non-reflink filesystems, so it counts as a fallback even
    // when it succeeds (statistics stay honest everywhere).
    #[cfg(target_os = "linux")]
    {
        if copy_file_range_fallback(src, dst, src_len).is_ok() {
            mirror_mode(src, dst)?;
            return Ok(CloneMechanism::Fallback);
        }
    }
    // Last resort: clean up any half-written native attempt, then a
    // plain copy whose error (if any) is the one that surfaces.
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "clone fallback copy {} -> {} failed: {e}",
                src.display(),
                dst.display()
            ),
        )
    })?;
    mirror_mode(src, dst)?;
    Ok(CloneMechanism::Fallback)
}

/// Linux middle fallback: fresh destination plus a looped
/// `copy_file_range` (extent-sharing where allowed, plain bytes
/// elsewhere). Reports success only when every byte moved. A zero
/// length refuses outright: pseudo-files report `len == 0` while
/// holding data, and a zero-length loop would "succeed" copying
/// nothing — the read-based plain copy below is the correct path.
#[cfg(target_os = "linux")]
fn copy_file_range_fallback(src: &Path, dst: &Path, len: u64) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "copy_file_range cannot size this source; plain copy required",
        ));
    }
    let _ = std::fs::remove_file(dst);
    let src_file = std::fs::File::open(src)?;
    let mode = src_file.metadata()?.permissions().mode();
    let dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode & 0o7777)
        .open(dst)?;
    let moved = copy_file_range_loop(&src_file, &dst_file, len)?;
    if moved == len {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            format!("copy_file_range stalled at {moved}/{len} bytes"),
        ))
    }
}

/// Remove a file or symlink (never a directory — checked upstream).
/// Windows symlinks-to-directories need `remove_dir`, so both are
/// attempted there in order. Shared with the snapshot store for
/// worktree entry replacement during restore.
pub(crate) fn remove_file_or_symlink(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(first) => {
            #[cfg(target_os = "windows")]
            {
                std::fs::remove_dir(path).map_err(|_| first)
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err(first)
            }
        }
    }
}

/// Mirror the source permission bits onto the destination (unix
/// modes; Windows files carry no POSIX mode to mirror). Shared
/// with the snapshot store for post-order directory modes.
pub(crate) fn mirror_mode(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(src)?.permissions().mode();
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode & 0o7777))?;
    }
    let _ = (src, dst);
    Ok(())
}

/// Clone a directory tree: directories recreated with mirrored
/// modes, regular files via [`cow_clone_file`], symlinks mirrored
/// as symlinks. The destination must not exist (snapshot semantics —
/// no merging); FIFOs, sockets, devices, and other exotics fail
/// loud instead of silently dropping data. Hardlinks materialize as
/// independent files; modification times are not preserved.
pub fn cow_clone_tree(src: &Path, dst: &Path) -> std::io::Result<CowTreeStats> {
    cow_clone_tree_inner(src, dst, &[])
}

/// Clone a directory tree while skipping entries whose file name
/// appears in `exclude_names` (matched at every depth). Shares the
/// walker with [`cow_clone_tree`]; nesting under an excluded
/// top-level entry is safe because the walker never descends there.
pub fn cow_clone_tree_excluding(
    src: &Path,
    dst: &Path,
    exclude_names: &[&str],
) -> std::io::Result<CowTreeStats> {
    cow_clone_tree_inner(src, dst, exclude_names)
}

fn cow_clone_tree_inner(
    src: &Path,
    dst: &Path,
    exclude_names: &[&str],
) -> std::io::Result<CowTreeStats> {
    if !std::fs::symlink_metadata(src)
        .map(|meta| meta.file_type().is_dir())
        .unwrap_or(false)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("clone source is not a directory: {}", src.display()),
        ));
    }
    if std::fs::symlink_metadata(dst).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("clone destination exists: {}", dst.display()),
        ));
    }
    if dst_nests_unexcluded(src, dst, exclude_names)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "clone destination resides inside the source: {}",
                dst.display()
            ),
        ));
    }
    let mut stats = CowTreeStats {
        files: 0,
        bytes: 0,
        dirs: 0,
        symlinks: 0,
        native_clones: 0,
        fallback_copies: 0,
    };
    clone_dir_into(src, dst, &mut stats, exclude_names)?;
    Ok(stats)
}

/// True when a file name matches the exclusion list, compared
/// case-insensitively: `.GIT`/`.Git` on case-insensitive volumes
/// (NTFS, default APFS) must exclude exactly like `.git`, or
/// captures would swallow (and restores destroy) VCS metadata.
/// On case-sensitive filesystems this over-excludes pathological
/// lookalike names — accepted, since the dangerous direction is
/// under-exclusion. Shared with the snapshot store and the
/// nesting check below (one rule, every call site).
pub(crate) fn name_is_excluded(name: &std::ffi::OsStr, exclude_names: &[&str]) -> bool {
    let Some(text) = name.to_str() else {
        return false;
    };
    exclude_names
        .iter()
        .any(|excluded| text.eq_ignore_ascii_case(excluded))
}

/// True when `dst` nests inside `src` (directly or via symlinked
/// parents) through a path the walker will actually descend:
/// nesting whose top-level entry is excluded is safe (the walker
/// skips that whole subtree, so `dst` is never reached during
/// traversal). `dst` itself must not exist (checked upstream), so
/// the nearest existing ancestor is canonicalized and the remainder
/// rejoined before comparing. Permission-masked ancestors compare
/// lexically (traversal would fail there first anyway, so no
/// infinite descent can result).
fn dst_nests_unexcluded(src: &Path, dst: &Path, exclude: &[&str]) -> std::io::Result<bool> {
    let canonical_src = std::fs::canonicalize(src)?;
    let mut ancestor = dst;
    let mut rest = PathBuf::new();
    let full = loop {
        if let Ok(canonical) = std::fs::canonicalize(ancestor) {
            break rest.components().fold(canonical, |path, component| {
                path.join(component.as_os_str())
            });
        }
        match (ancestor.parent(), ancestor.file_name()) {
            (Some(parent), Some(name)) => {
                rest = Path::new(name).join(&rest);
                ancestor = parent;
            }
            // No existing ancestor (only roots and prefixes reach
            // here, and those canonicalize): cannot be inside `src`.
            _ => return Ok(false),
        }
    };
    let Ok(rel) = full.strip_prefix(&canonical_src) else {
        return Ok(false);
    };
    match rel.components().next() {
        None => Ok(true),
        // Same folded rule as the walker, or `.RUNNER`-style
        // nesting reads forbidden while the walker would skip it.
        Some(first) => Ok(!name_is_excluded(first.as_os_str(), exclude)),
    }
}

/// Recursive tree worker: `src` is a directory, `dst` is created.
/// Every entry is classified by symlink-blind metadata so links are
/// never followed into.
fn clone_dir_into(
    src: &Path,
    dst: &Path,
    stats: &mut CowTreeStats,
    exclude_names: &[&str],
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("clone cannot create {}: {e}", dst.display()),
        )
    })?;
    stats.dirs += 1;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(src)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("clone cannot list {}: {e}", src.display()),
            )
        })?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for src_path in &entries {
        let name = src_path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("clone entry has no name: {}", src_path.display()),
            )
        })?;
        if name_is_excluded(name, exclude_names) {
            continue;
        }
        let dst_path = dst.join(name);
        let file_type = std::fs::symlink_metadata(src_path)?.file_type();
        if file_type.is_dir() && !file_type.is_symlink() {
            clone_dir_into(src_path, &dst_path, stats, exclude_names)?;
        } else if file_type.is_symlink() {
            mirror_symlink(src_path, &dst_path)?;
            stats.symlinks += 1;
        } else if file_type.is_file() {
            let size = std::fs::metadata(src_path)
                .map(|meta| meta.len())
                .unwrap_or(0);
            match cow_clone_file_inner(src_path, &dst_path)? {
                CloneMechanism::Native => stats.native_clones += 1,
                CloneMechanism::Fallback => stats.fallback_copies += 1,
            }
            stats.files += 1;
            stats.bytes += size;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "clone refuses special file (fifo/socket/device): {}",
                    src_path.display()
                ),
            ));
        }
    }
    // Directory modes apply post-order: chmodding first would lock
    // out child creation inside read-only sources.
    mirror_mode(src, dst)?;
    Ok(())
}

/// Recreate one symlink at its mirror path (target copied verbatim,
/// never resolved). Windows needs the link flavor upfront, read
/// from the source link itself (`is_symlink_dir`, never the
/// target) so dangling directory links keep their flavor. Shared
/// with the snapshot store for verbatim link restoration.
pub(crate) fn mirror_symlink(src: &Path, dst: &Path) -> std::io::Result<()> {
    let target = std::fs::read_link(src)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, dst)?;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::FileTypeExt;
        if std::fs::symlink_metadata(src)?.file_type().is_symlink_dir() {
            std::os::windows::fs::symlink_dir(&target, dst)?;
        } else {
            std::os::windows::fs::symlink_file(&target, dst)?;
        }
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (&target, dst);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlink mirroring unavailable on this platform",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn containment_spots_nested_and_sibling_destinations() {
        let dir = crate::test_support::TempDir::new("cow-contained").unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("a")).unwrap();
        assert!(dst_nests_unexcluded(&src, &src.join("snapshots"), &[]).unwrap());
        assert!(
            dst_nests_unexcluded(&src, &src.join("a").join("b").join("snapshots"), &[]).unwrap()
        );
        assert!(!dst_nests_unexcluded(&src, &dir.path().join("sibling"), &[]).unwrap());
        assert!(!dst_nests_unexcluded(&src, &src.join("..").join("sibling"), &[]).unwrap());
        // Nesting under an excluded top-level entry is safe: the
        // walker never descends there.
        assert!(
            !dst_nests_unexcluded(&src, &src.join(".runner").join("snapshots"), &[".runner"])
                .unwrap()
        );
        // Case-folded too: `.RUNNER` excludes like `.runner`.
        assert!(
            !dst_nests_unexcluded(&src, &src.join(".RUNNER").join("snapshots"), &[".runner"])
                .unwrap()
        );
    }

    #[test]
    fn exclusion_matching_folds_ascii_case() {
        use std::ffi::OsStr;

        let excludes = [".git", ".runner"];
        for name in [".git", ".GIT", ".Git", ".RUNNER", ".Runner"] {
            assert!(name_is_excluded(OsStr::new(name), &excludes), "{name}");
        }
        for name in ["src", ".github", "git", "runner", ""] {
            assert!(!name_is_excluded(OsStr::new(name), &excludes), "{name}");
        }
    }

    #[test]
    fn filesystem_type_labels_known_volumes() {
        // Deterministic on every Linux box: shared memory is tmpfs
        // by kernel definition, and proc renders honest hex.
        #[cfg(target_os = "linux")]
        {
            assert_eq!(filesystem_type(Path::new("/dev/shm")), "tmpfs");
            assert_eq!(filesystem_type(Path::new("/proc")), "unknown(0x9fa0)");
            assert_eq!(
                filesystem_type(Path::new("/missing-no-such-dir-xyz")),
                "unknown"
            );
        }
        // Elsewhere: labels never fail, even for missing paths.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!filesystem_type(Path::new("/tmp")).is_empty());
            assert_eq!(
                filesystem_type(Path::new("/missing-no-such-dir-xyz")),
                "unknown"
            );
        }
    }
}
