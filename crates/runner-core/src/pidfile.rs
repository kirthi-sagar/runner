//! Daemon PID file tracking (`runner stop`).
//!
//! Records the supervisor PID in `/run/runner.pid`, falling back to
//! `~/.runner/runner.pid` when unprivileged (on Windows:
//! `%LOCALAPPDATA%\runner\runner.pid`, falling back to the temp dir).

use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;

/// Privileged PID file path.
pub const PID_PATH: &str = "/run/runner.pid";

/// Unprivileged fallback PID file path.
pub fn fallback_pid_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".runner").join("runner.pid"))
}

/// Pick the privileged path when its parent is writable, else the fallback.
#[cfg(not(windows))]
pub fn resolve_pid_path() -> PathBuf {
    let primary = PathBuf::from(PID_PATH);
    if let Some(parent) = primary.parent() {
        let probe = parent.join(".runner-write-probe");
        if std::fs::create_dir_all(parent).is_ok() && std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            return primary;
        }
    }
    fallback_pid_path().unwrap_or(primary)
}

/// Windows PID file: `%LOCALAPPDATA%\runner\runner.pid` (always
/// writable), falling back to the temp dir only if unset.
#[cfg(windows)]
pub fn resolve_pid_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(|dir| PathBuf::from(dir).join("runner").join("runner.pid"))
        .unwrap_or_else(|| std::env::temp_dir().join("runner.pid"))
}

/// Write the current process id.
pub fn write_current_pid(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, std::process::id().to_string())
}

/// Read a PID file.
pub fn read_pid(path: &Path) -> io::Result<u32> {
    let text = std::fs::read_to_string(path)?;
    text.trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// True if the process exists (signal 0 probe; EPERM counts as alive).
#[cfg(unix)]
pub fn process_alive(pid: u32) -> bool {
    match kill(Pid::from_raw(pid as i32), None) {
        Ok(()) => true,
        Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// True if the process exists: open with query rights and check for
/// `STILL_ACTIVE`. Access-denied counts as alive (exists but
/// unqueryable), mirroring the unix EPERM rule. (A foreign process
/// that exited with code 259 would misread as alive; our own kills
/// use exit code 1, and daemon exits are 0/1, so this never bites.)
#[cfg(windows)]
pub fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let handle =
        match crate::governor::windows::open_process_with(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(handle) => handle,
            // Access-denied means the pid exists but is unqueryable
            // (same rule as the unix EPERM branch).
            Err(e) => return e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32),
        };
    let mut code = 0u32;
    use std::os::windows::io::AsRawHandle;
    // SAFETY: live handle plus a valid out-word.
    let ok = unsafe { GetExitCodeProcess(handle.as_raw_handle() as _, &mut code) };
    ok != 0 && code == STILL_ACTIVE as u32
}

/// Send SIGTERM (or SIGKILL when `force`) to the recorded daemon.
#[cfg(unix)]
pub fn signal_daemon(pid: u32, force: bool) -> Result<(), String> {
    let signal = if force {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };
    kill(Pid::from_raw(pid as i32), signal)
        .map_err(|e| format!("failed to signal daemon pid {pid}: {e}"))
}

/// Terminate the recorded daemon. Windows has no TERM/KILL
/// distinction, so `force` is accepted and ignored: every stop is an
/// unconditional terminate with exit code 1.
#[cfg(windows)]
pub fn signal_daemon(pid: u32, _force: bool) -> Result<(), String> {
    use windows_sys::Win32::System::Threading::{TerminateProcess, PROCESS_TERMINATE};
    let handle = crate::governor::windows::open_process_with(pid, PROCESS_TERMINATE)
        .map_err(|e| format!("failed to open daemon pid {pid}: {e}"))?;
    use std::os::windows::io::AsRawHandle;
    // SAFETY: live handle; exit code 1 (never STILL_ACTIVE, so the
    // alive probe can never misread our own kills).
    let ok = unsafe { TerminateProcess(handle.as_raw_handle() as _, 1) };
    if ok == 0 {
        return Err(format!("failed to terminate daemon pid {pid}"));
    }
    Ok(())
}

/// Wait up to `timeout` for the process to exit.
pub fn wait_for_exit(pid: u32, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while process_alive(pid) {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    true
}

/// Remove a PID file, ignoring missing files.
pub fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_roundtrip_and_self_alive() {
        let dir = crate::test_support::TempDir::new("pid").unwrap();
        let path = dir.path().join("runner.pid");
        write_current_pid(&path).unwrap();
        let pid = read_pid(&path).unwrap();
        assert_eq!(pid, std::process::id());
        assert!(process_alive(pid));
        assert!(!process_alive(u32::MAX - 100));
    }

    // Windows stop path end to end: a live sleeper reports alive,
    // terminates on signal, and the exit poll observes it.
    #[cfg(windows)]
    #[test]
    fn signal_daemon_terminates_and_wait_observes_exit() {
        let mut child = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
            .spawn()
            .expect("spawn sleeper");
        let pid = child.id();
        assert!(process_alive(pid));
        signal_daemon(pid, false).expect("terminate sleeper");
        assert!(wait_for_exit(pid, std::time::Duration::from_secs(10)));
        let _ = child.wait();
    }
}
