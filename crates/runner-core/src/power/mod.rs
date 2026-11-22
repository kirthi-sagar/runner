//! Cross-platform power and lid interception: pre-sleep handover
//! events so the daemon can checkpoint before the host suspends.
//!
//! Each platform module owns its OS mechanism (logind inhibit on
//! Linux, IOKit callbacks on macOS, a message pump on Windows) and
//! publishes onto one broadcast channel. Platforms without support
//! (containers, headless VMs, unknown OSes) disable cleanly: [`start`]
//! returns `None` and boot proceeds normally.

pub mod linux;
pub mod macos;
pub mod windows;

use serde::{Deserialize, Serialize};

/// Unified power transition observed on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerEvent {
    /// Sleep is imminent; `delay_ms` is the grace window the watcher
    /// holds the transition for consumer handover (platform-specific,
    /// documented per backend; 0 means notify-only).
    PreparingSleep { delay_ms: u64 },
    /// The host resumed from sleep.
    Resumed,
    /// Laptop lid closed.
    LidClosed,
    /// Laptop lid opened.
    LidOpened,
}

/// Live power watcher: subscribe for transitions. The platform
/// backend runs until process exit; dropping the watcher does not
/// stop it (daemons never unsubscribe).
pub struct PowerWatcher {
    tx: tokio::sync::broadcast::Sender<PowerEvent>,
}

impl PowerWatcher {
    /// Observe power transitions (lagging receivers skip to live).
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<PowerEvent> {
        self.tx.subscribe()
    }
}

/// Start the platform backend. Returns `None` (with a loud note)
/// when power management is unavailable — containers, headless VMs,
/// or unknown platforms — so daemon boot never blocks on it. Must be
/// called from async context (the Linux backend spawns tasks).
pub fn start() -> Option<PowerWatcher> {
    let (tx, _) = tokio::sync::broadcast::channel(16);
    #[cfg(target_os = "linux")]
    let ok = linux::spawn(tx.clone());
    #[cfg(target_os = "macos")]
    let ok = macos::spawn(tx.clone());
    #[cfg(windows)]
    let ok = windows::spawn(tx.clone());
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let ok = {
        let _ = tx;
        eprintln!("[runner] power watcher disabled: unsupported platform");
        false
    };
    if ok {
        Some(PowerWatcher { tx })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_round_trip_through_json() {
        for event in [
            PowerEvent::PreparingSleep { delay_ms: 4000 },
            PowerEvent::Resumed,
            PowerEvent::LidClosed,
            PowerEvent::LidOpened,
        ] {
            let text = serde_json::to_string(&event).unwrap();
            assert_eq!(serde_json::from_str::<PowerEvent>(&text).unwrap(), event);
        }
    }

    #[tokio::test]
    async fn broadcast_fans_out_to_every_subscriber() {
        let (tx, _) = tokio::sync::broadcast::channel::<PowerEvent>(16);
        let watcher = PowerWatcher { tx: tx.clone() };
        let mut first = watcher.subscribe();
        let mut second = watcher.subscribe();
        tx.send(PowerEvent::LidClosed).unwrap();
        assert_eq!(first.recv().await.unwrap(), PowerEvent::LidClosed);
        assert_eq!(second.recv().await.unwrap(), PowerEvent::LidClosed);
    }
}
