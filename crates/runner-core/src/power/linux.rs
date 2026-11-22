//! Linux power backend: systemd-logind delay inhibitor plus
//! `PrepareForSleep` signals over D-Bus, with lid state polled from
//! sysfs. Shells out to `systemd-inhibit`/`gdbus` (the same tools an
//! operator would use) instead of pulling a D-Bus client crate.

use std::path::{Path, PathBuf};

/// Grace window behind `PreparingSleep`: logind waits up to
/// `InhibitDelayMaxSec` (5 s default) for delay locks to release,
/// and ours stays held, so consumers get the full window minus
/// scheduling slack. Assumes the distro default; an admin-tuned max
/// shortens it (documented, not probed).
pub const LINUX_SLEEP_DELAY_MS: u64 = 5000;

/// Lid poll cadence: transitions are human-scale, the read is tiny.
#[cfg(target_os = "linux")]
const LID_POLL_SECS: u64 = 2;

/// Parse one `gdbus monitor` line: `Some(true)` entering sleep,
/// `Some(false)` resuming, `None` for any other traffic.
pub fn parse_gdbus_prepare(line: &str) -> Option<bool> {
    if !line.contains("PrepareForSleep") {
        return None;
    }
    if line.contains("(false") {
        Some(false)
    } else if line.contains("(true") {
        Some(true)
    } else {
        None
    }
}

/// Parse `/proc/acpi/button/lid/*/state` (`Some(true)` = open).
pub fn parse_lid_state(text: &str) -> Option<bool> {
    let value = text.trim().strip_prefix("state:")?.trim();
    match value {
        "open" => Some(true),
        "closed" => Some(false),
        _ => None,
    }
}

/// Lid transition edge: the first sample only seeds (no event).
pub fn lid_transition(prev_open: Option<bool>, open: bool) -> Option<crate::power::PowerEvent> {
    match prev_open {
        None => None,
        Some(prev) if prev == open => None,
        Some(true) => Some(crate::power::PowerEvent::LidClosed),
        Some(false) => Some(crate::power::PowerEvent::LidOpened),
    }
}

/// First readable lid `state` file under `root`
/// (`/proc/acpi/button/lid` in production).
pub fn find_lid_state_file_under(root: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let candidate = entry.path().join("state");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// RAII sleep veto: a `systemd-inhibit` block lock over idle and
/// sleep, held by a reaped `sleep infinity` child. Drop kills and
/// reaps (no orphans, no zombies). Block (not delay): `idle` has no
/// delay mode, and a hold-while-busy veto must not time out.
#[cfg(target_os = "linux")]
pub struct WakeLockGuard {
    child: std::process::Child,
}

#[cfg(target_os = "linux")]
impl WakeLockGuard {
    /// Acquire the veto; `None` when logind is unreachable.
    pub fn acquire() -> Option<Self> {
        let child = std::process::Command::new("systemd-inhibit")
            .args([
                "--what=idle:sleep",
                "--mode=block",
                "--who=runner",
                "--why=Runner active compilation",
                "sleep",
                "infinity",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(Self { child })
    }
}

#[cfg(target_os = "linux")]
impl Drop for WakeLockGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the backend: hold a logind sleep-delay lock, stream D-Bus
/// sleep signals, poll lid state. Returns false (with a loud note)
/// when the systemd tools are missing — containers and headless VMs
/// disable cleanly instead of failing boot.
#[cfg(target_os = "linux")]
pub fn spawn(tx: tokio::sync::broadcast::Sender<crate::power::PowerEvent>) -> bool {
    for helper in ["systemd-inhibit", "gdbus"] {
        let ok = std::process::Command::new(helper)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("[runner] power watcher disabled: {helper} not available");
            return false;
        }
    }
    tokio::spawn(async move {
        monitor_loop(tx).await;
    });
    true
}

/// Monitor loop: D-Bus sleep signals plus lid polling. Never returns
/// in production; any fatal spawn error ends the task with a note
/// (the daemon keeps running unobserved).
#[cfg(target_os = "linux")]
async fn monitor_loop(tx: tokio::sync::broadcast::Sender<crate::power::PowerEvent>) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    // Delay lock first: logind now waits out our window on sleep.
    // `sleep infinity` holds it until we die; kill_on_drop reaps it
    // with the daemon (SIGKILL orphans are visible in
    // `systemd-inhibit --list`, same as any crashed inhibitor).
    let holder = tokio::process::Command::new("systemd-inhibit")
        .args([
            "--what=sleep",
            "--mode=delay",
            "--who=runner",
            "--why=runner pre-sleep handover",
            "sleep",
            "infinity",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let inhibited = holder.is_ok();
    if !inhibited {
        eprintln!("[runner] power watcher: inhibitor unlockable; sleep events carry no delay");
    }
    let mut monitor = match tokio::process::Command::new("gdbus")
        .args([
            "monitor",
            "--system",
            "--dest",
            "org.freedesktop.login1",
            "--object-path",
            "/org/freedesktop/login1",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("[runner] power watcher: gdbus monitor failed ({e}); disabled");
            return;
        }
    };
    let stdout = match monitor.stdout.take() {
        Some(stdout) => stdout,
        None => {
            eprintln!("[runner] power watcher: gdbus stdout missing; disabled");
            return;
        }
    };
    let mut lines = BufReader::new(stdout).lines();
    let mut lid_tick = tokio::time::interval(std::time::Duration::from_secs(LID_POLL_SECS));
    let lid_file = find_lid_state_file_under(Path::new("/proc/acpi/button/lid"));
    let mut lid_open: Option<bool> = None;
    let delay_ms = if inhibited { LINUX_SLEEP_DELAY_MS } else { 0 };
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let line = match line {
                    Ok(Some(line)) => line,
                    // Monitor died or errored: nothing left to observe.
                    _ => {
                        eprintln!("[runner] power watcher: gdbus monitor ended; disabled");
                        return;
                    }
                };
                match parse_gdbus_prepare(&line) {
                    Some(true) => {
                        let _ = tx.send(crate::power::PowerEvent::PreparingSleep { delay_ms });
                    }
                    Some(false) => {
                        let _ = tx.send(crate::power::PowerEvent::Resumed);
                    }
                    None => {}
                }
            }
            _ = lid_tick.tick() => {
                let Some(path) = lid_file.as_ref() else { continue };
                let Ok(text) = std::fs::read_to_string(path) else { continue };
                let Some(open) = parse_lid_state(&text) else { continue };
                if let Some(event) = lid_transition(lid_open, open) {
                    let _ = tx.send(event);
                }
                lid_open = Some(open);
            }
        }
    }
    // `holder` is intentionally never touched again: it lives until
    // this task ends so the delay lock stays held for the daemon's
    // whole lifetime (kill_on_drop reaps it on shutdown).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdbus_prepare_parses_both_edges() {
        assert_eq!(
            parse_gdbus_prepare(
                "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (true,)"
            ),
            Some(true)
        );
        assert_eq!(
            parse_gdbus_prepare(
                "/org/freedesktop/login1: org.freedesktop.login1.Manager.PrepareForSleep (false,)"
            ),
            Some(false)
        );
        assert_eq!(parse_gdbus_prepare("NameAcquired"), None);
        assert_eq!(parse_gdbus_prepare("PrepareForSleep (maybe,)"), None);
        assert_eq!(parse_gdbus_prepare(""), None);
    }

    #[test]
    fn lid_state_parses_open_closed_and_garbage() {
        assert_eq!(parse_lid_state("state:      open\n"), Some(true));
        assert_eq!(parse_lid_state("state: closed"), Some(false));
        assert_eq!(parse_lid_state(""), None);
        assert_eq!(parse_lid_state("state: ajar"), None);
        assert_eq!(parse_lid_state("open"), None);
    }

    #[test]
    fn lid_edges_fire_once_per_transition() {
        use crate::power::PowerEvent;
        assert_eq!(lid_transition(None, true), None);
        assert_eq!(lid_transition(Some(true), true), None);
        assert_eq!(
            lid_transition(Some(true), false),
            Some(PowerEvent::LidClosed)
        );
        assert_eq!(
            lid_transition(Some(false), true),
            Some(PowerEvent::LidOpened)
        );
    }

    // Full lifecycle against the real inhibitor: acquire holds a
    // live lock, drop releases it, and re-acquire works (systemd is
    // guaranteed on the Linux CI runners; containers take the None
    // path in spawn(), not here).
    #[cfg(target_os = "linux")]
    #[test]
    fn wake_lock_acquires_and_releases() {
        let guard = WakeLockGuard::acquire().expect("inhibitor lock");
        assert!(systemd_inhibit_lists_runner());
        drop(guard);
        let guard = WakeLockGuard::acquire().expect("re-acquire after release");
        drop(guard);
    }

    #[cfg(target_os = "linux")]
    fn systemd_inhibit_lists_runner() -> bool {
        // Registration races the spawn: poll briefly for the lock.
        for _ in 0..20 {
            let listed = std::process::Command::new("systemd-inhibit")
                .arg("--list")
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).contains("runner"))
                .unwrap_or(false);
            if listed {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }

    #[test]
    fn lid_file_lookup_finds_nested_state() {
        let dir = crate::test_support::TempDir::new("lid").unwrap();
        assert_eq!(find_lid_state_file_under(dir.path()), None);
        let liddir = dir.path().join("LID0");
        std::fs::create_dir(&liddir).unwrap();
        std::fs::write(liddir.join("state"), "state: open\n").unwrap();
        assert_eq!(
            find_lid_state_file_under(dir.path()),
            Some(liddir.join("state"))
        );
    }
}
