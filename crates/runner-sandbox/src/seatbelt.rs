//! macOS Seatbelt FFI: Tier-2 filesystem isolation via `sandbox_init`.
//!
//! The child-side half of Tier-2 on macOS. The parent never enters a
//! sandbox; the `pre_exec` hook ([`crate::driver`] through
//! `install_child_hook`) applies a profile to each job child after
//! fork and before exec, so every job process is confined while the
//! coordinator stays free.
//!
//! Two libc-level facts shape this module (both verified against
//! current production users, not just the man pages):
//!
//! * `sandbox_init` takes a full profile *string* with flags `0`
//!   (Chromium passes `0` with profile strings; the header's
//!   SANDBOX_NAMED-only note covers the canned `kSBXProfile*`
//!   constants instead). If the process is already sandboxed the new
//!   profile is ignored and `sandbox_init` returns an error —
//!   hence the [`is_sandboxed`] guard before every apply.
//! * `sandbox_check` itself is *not* deprecated. The canonical
//!   nesting probe is `sandbox_check(getpid(), NULL,
//!   SANDBOX_FILTER_NONE)` which returns 1 when sandboxed
//!   (Chromium's documented pattern, mirrored by Homebrew's
//!   `nested_sandbox?`).
//!
//! No `<sandbox.h>` is included anywhere: the declarations below are
//! hand-rolled Rust FFI, which also sidesteps the C compiler's
//! deprecation warning on `sandbox_init`/`sandbox_free_error`.
//! Deprecation is a documented future-removal risk (see
//! `docs/macos.md`), not a blocker: Seatbelt remains the sandbox
//! backend for Homebrew, Claude Code, Codex CLI, and Cursor.
//!
//! Gating split: every FFI item is `#[cfg(target_os = "macos")]` so
//! no Apple symbol leaks onto other platforms, while the module
//! itself (and the pure profile builder) stays ungated so the
//! builder logic is unit-testable without a Mac.

#[cfg(target_os = "macos")]
use std::ffi::{c_char, c_int, CStr, CString};

#[cfg(target_os = "macos")]
#[link(name = "sandbox", kind = "dylib")]
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
    fn sandbox_check(pid: i32, operation: *const c_char, type_: c_int, ...) -> c_int;
}

/// Flags for `sandbox_init` with a full profile string: 0.
/// (The header reserves every value except SANDBOX_NAMED, but 0 with
/// a profile string is the established production usage.)
#[cfg(target_os = "macos")]
const SANDBOX_PROFILE_STRING: u64 = 0;

/// `SANDBOX_FILTER_NONE` for [`is_sandboxed`]: the filter argument is
/// currently unused by the kernel for a NULL operation probe.
#[cfg(target_os = "macos")]
const SANDBOX_FILTER_NONE: c_int = 0;

/// Build the Tier-2 job profile as an in-memory string (never
/// written to disk). Permissive base with targeted denies:
///
/// * `~/.ssh`, `~/.gnupg`, `~/.config/runner`, `~/.runner`: no
///   read, no write (credentials and runner state stay private).
/// * writes anywhere outside `workspace`: denied.
/// * `workspace`: full read/write.
/// * `/usr`, `/System`, `/Library`, `/private/tmp`: explicit read
///   allows (documents the allow-default base).
/// * network: untouched by any rule, so outbound stays open (CI jobs
///   fetch dependencies; egress filtering arrives in v1.10.0).
///
/// `home` is a parameter (not read here) so the builder stays pure
/// and deterministic; pass `None` when HOME is unavailable and the
/// home-relative rules are omitted. Paths are Seatbelt-escaped
/// (`"`/`\`); callers should canonicalize `workspace` first so
/// `/tmp`-style symlinks match the kernel's resolved-path checks.
pub fn build_profile(workspace: &std::path::Path, home: Option<&std::path::Path>) -> String {
    fn esc(path: &std::path::Path) -> String {
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    }

    let mut profile = String::from("(version 1)\n(allow default)\n");
    if let Some(home) = home {
        for leaf in [".ssh", ".gnupg", ".config/runner", ".runner"] {
            let dir = esc(&home.join(leaf));
            profile.push_str(&format!("(deny file-read* (subpath \"{dir}\"))\n"));
            profile.push_str(&format!("(deny file-write* (subpath \"{dir}\"))\n"));
        }
    }
    let ws = esc(workspace);
    profile.push_str(&format!(
        "(deny file-write* (require-not (subpath \"{ws}\")))\n"
    ));
    for dir in ["/usr", "/System", "/Library", "/private/tmp"] {
        profile.push_str(&format!("(allow file-read* (subpath \"{dir}\"))\n"));
    }
    profile
}

/// True when the current process is already inside a Seatbelt sandbox.
/// Never fails; a NULL operation probe only inspects, never confines.
#[cfg(target_os = "macos")]
pub fn is_sandboxed() -> bool {
    // SAFETY: canonical probe — NULL operation with FILTER_NONE
    // performs no dereference; the pid is our own.
    unsafe {
        sandbox_check(
            std::process::id() as i32,
            std::ptr::null(),
            SANDBOX_FILTER_NONE,
        ) == 1
    }
}

/// Apply a Seatbelt profile string to the current process.
/// Irreversible: success confines this process (and its future
/// children) until exit, so callers apply it only to job children in
/// `pre_exec`, never to the coordinator. On failure returns the
/// system's own diagnostic message.
#[cfg(target_os = "macos")]
pub fn apply_profile(profile: &str) -> Result<(), String> {
    let c_profile =
        CString::new(profile).map_err(|e| format!("seatbelt profile contains NUL: {e}"))?;
    let mut errorbuf: *mut c_char = std::ptr::null_mut();
    // SAFETY: NUL-terminated profile; `errorbuf` is a valid out-pointer.
    let rc = unsafe { sandbox_init(c_profile.as_ptr(), SANDBOX_PROFILE_STRING, &mut errorbuf) };
    if rc == 0 {
        // The header promises NULL on success; free defensively if a
        // future OS ever populates it, so success never leaks.
        if !errorbuf.is_null() {
            // SAFETY: non-null buffer came from `sandbox_init`.
            unsafe { sandbox_free_error(errorbuf) };
        }
        return Ok(());
    }
    if errorbuf.is_null() {
        return Err("sandbox_init failed without diagnostics".to_string());
    }
    // SAFETY: the header guarantees a NUL-terminated buffer on failure.
    let message = unsafe { CStr::from_ptr(errorbuf) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: buffer came from `sandbox_init`; exactly one free.
    unsafe { sandbox_free_error(errorbuf) };
    Err(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_builder_embeds_workspace_and_home_rules() {
        let ws = std::path::Path::new("/private/tmp/ws-1");
        let home = std::path::Path::new("/Users/test");
        let profile = build_profile(ws, Some(home));
        assert!(!profile.is_empty());
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(allow default)"));
        assert!(profile.contains("/private/tmp/ws-1"));
        for leaf in [".ssh", ".gnupg", ".config/runner", ".runner"] {
            assert!(
                profile.contains(&format!("/Users/test/{leaf}")),
                "missing home rule for {leaf}:\n{profile}"
            );
        }
        // Paths with quotes stay syntactically intact.
        let quoted = build_profile(
            std::path::Path::new("/tmp/we\"ird"),
            Some(std::path::Path::new("/Users/q\"x")),
        );
        assert!(quoted.contains("/tmp/we\\\"ird"));
        assert!(quoted.contains("/Users/q\\\"x/.ssh"));
    }

    #[test]
    fn profile_builder_omits_home_rules_without_home() {
        let profile = build_profile(std::path::Path::new("/private/tmp/ws-2"), None);
        assert!(!profile.is_empty());
        assert!(profile.contains("/private/tmp/ws-2"));
        assert!(!profile.contains(".ssh"));
    }

    // The test runner itself is never sandboxed.
    #[cfg(target_os = "macos")]
    #[test]
    fn nesting_detection_false_in_unsandboxed_test_process() {
        assert!(!is_sandboxed());
    }

    // Live FFI through a real child: `sandbox_init` is irreversible
    // per-process, so the apply runs in a forked child (never in the
    // test process, which would pollute every other test here).
    #[cfg(target_os = "macos")]
    #[test]
    fn permissive_profile_applies_in_child_process() {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new("/usr/bin/true");
        // SAFETY: the closure only applies a profile and inspects.
        unsafe {
            cmd.pre_exec(|| {
                apply_profile("(version 1)\n(allow default)\n").map_err(std::io::Error::other)?;
                assert!(is_sandboxed(), "profile applied but probe disagrees");
                Ok(())
            });
        }
        assert!(cmd.status().expect("spawn /usr/bin/true").success());
    }

    // The REAL builder output must compile on the real kernel and
    // actually enforce: writes land inside the workspace, writes
    // outside and credential reads fail, plain reads pass.
    #[cfg(target_os = "macos")]
    #[test]
    fn real_profile_compiles_and_enforces_via_sandbox_exec() {
        let ws_dir = runner_core::test_support::TempDir::new("seatbelt-ws").unwrap();
        let ws = std::fs::canonicalize(ws_dir.path()).unwrap();
        let outside_dir = runner_core::test_support::TempDir::new("seatbelt-out").unwrap();
        let outside = std::fs::canonicalize(outside_dir.path()).unwrap();
        let home_dir = runner_core::test_support::TempDir::new("seatbelt-home").unwrap();
        let home = std::fs::canonicalize(home_dir.path()).unwrap();
        let ssh_dir = home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("sentinel"), "secret").unwrap();
        std::fs::write(outside.join("sentinel"), "public").unwrap();

        let profile = build_profile(&ws, Some(&home));
        let run = |argv: &[&str]| {
            std::process::Command::new("/usr/bin/sandbox-exec")
                .arg("-p")
                .arg(&profile)
                .args(argv)
                .output()
                .expect("spawn sandbox-exec")
        };

        // Write inside the workspace: allowed.
        let out = run(&["/usr/bin/touch", ws.join("ok").to_str().unwrap()]);
        assert!(out.status.success(), "workspace write denied: {out:?}");
        assert!(ws.join("ok").exists());

        // Write outside the workspace: denied.
        let out = run(&["/usr/bin/touch", outside.join("nope").to_str().unwrap()]);
        assert!(!out.status.success(), "outside write allowed: {out:?}");
        assert!(!outside.join("nope").exists());

        // Credential read: denied.
        let out = run(&["/bin/cat", ssh_dir.join("sentinel").to_str().unwrap()]);
        assert!(!out.status.success(), "credential read allowed: {out:?}");

        // Plain read outside the workspace: allowed (permissive base).
        let out = run(&["/bin/cat", outside.join("sentinel").to_str().unwrap()]);
        assert!(out.status.success(), "plain read denied: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "public");
    }
}
