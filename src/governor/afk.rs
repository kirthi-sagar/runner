//! AFK Boost Mode: collapse reserved headroom when the desktop is idle.
//!
//! Phase 1 provides the idle state machine and thresholds. Phase 2 wires
//! the listeners: Wayland `ext-idle-notify-v1` and the
//! `org.freedesktop.ScreenSaver` D-Bus API (`IdleTime`).

/// Idle duration before boost engages (spec section 3.4).
pub const IDLE_THRESHOLD_SECS: u64 = 300;
/// Deadline to restore reserved headroom on first input.
pub const RESTORE_DEADLINE_MS: u64 = 50;

/// Desktop activity state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdleState {
    /// User present: full reserved headroom.
    #[default]
    Active,
    /// Idle past threshold: headroom collapsed, max slots.
    Idle,
}

/// AFK boost controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AfkBoost {
    state: IdleState,
}

impl AfkBoost {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> IdleState {
        self.state
    }

    pub fn boosted(&self) -> bool {
        self.state == IdleState::Idle
    }

    /// Enter boost after the idle threshold elapses.
    pub fn on_idle_timeout(&mut self) {
        self.state = IdleState::Idle;
    }

    /// Restore headroom on first user input (<50ms path: no I/O here;
    /// the governor applies weights synchronously after this returns).
    pub fn on_user_input(&mut self) {
        self.state = IdleState::Active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boost_engages_and_restores() {
        let mut afk = AfkBoost::new();
        assert!(!afk.boosted());
        afk.on_idle_timeout();
        assert!(afk.boosted());
        afk.on_user_input();
        assert!(!afk.boosted());
    }
}
