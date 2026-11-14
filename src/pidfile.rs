//! Daemon PID file tracking (`runner stop`).
//!
//! Records the supervisor PID in `/run/runner.pid`, falling back to
//! `~/.runner/runner.pid` when unprivileged.

use std::io;
use std::path::{Path, PathBuf};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// Privileged PID file path.
pub const PID_PATH: &str = "/run/runner.pid";

/// Unprivileged fallback PID file path.
pub fn fallback_pid_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".runner").join("runner.pid"))
}

/// Pick the privileged path when its parent is writable, else the fallback.
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
pub fn process_alive(pid: u32) -> bool {
    match kill(Pid::from_raw(pid as i32), None) {
        Ok(()) => true,
        Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

/// Send SIGTERM (or SIGKILL when `force`) to the recorded daemon.
pub fn signal_daemon(pid: u32, force: bool) -> Result<(), String> {
    let signal = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    kill(Pid::from_raw(pid as i32), signal)
        .map_err(|e| format!("failed to signal daemon pid {pid}: {e}"))
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
}
