//! AFK Boost Mode: collapse reserved headroom when the desktop is idle.
//!
//! Idle state comes from `loginctl` session properties (zero new
//! dependencies): a graphical session (`x11`/`wayland`/`mir`) counts as
//! idle when logind reports `IdleHint=yes` past the threshold, or when
//! the screen is locked (`LockedHint=yes`). Any probe failure, and any
//! host without a graphical session, reads as Active (fail-safe keeps
//! headroom). Desktops that never publish idle hints simply never
//! boost; a locked screen always does.

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

/// AFK operating mode (config `afk_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AfkMode {
    /// Follow desktop idle state; headless hosts stay Active.
    #[default]
    Auto,
    /// Boost permanently (headless CI servers).
    Always,
    /// Never boost.
    Never,
}

impl AfkMode {
    /// Lenient parse: unknown values fall back to Auto.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "always" => Self::Always,
            "never" => Self::Never,
            _ => Self::Auto,
        }
    }

    /// Canonical lowercase name for status output.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

/// Idle probe cadence: the 250ms tick evaluates AFK state, but the
/// `loginctl` subprocess runs at most this often.
pub const PROBE_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// `loginctl` binary, overridable for tests via `RUNNER_LOGINCTL`.
fn loginctl_bin() -> std::path::PathBuf {
    std::env::var_os("RUNNER_LOGINCTL")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/bin/loginctl"))
}

/// Session ids from `loginctl list-sessions --no-legend` output.
pub fn parse_sessions_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .collect()
}

/// `KEY=value` map from `loginctl show-session` output.
pub fn parse_session_props(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// True when the props describe a graphical session.
pub fn is_graphical_session(props: &std::collections::HashMap<String, String>) -> bool {
    matches!(
        props.get("Type").map(String::as_str),
        Some("x11") | Some("wayland") | Some("mir")
    )
}

/// True when an idle graphical session passed the threshold, or the
/// screen is locked. `now_monotonic_us` is µs since boot.
pub fn session_is_idle(
    props: &std::collections::HashMap<String, String>,
    idle_secs: u64,
    now_monotonic_us: u64,
) -> bool {
    if !is_graphical_session(props) {
        return false;
    }
    if props.get("LockedHint").is_some_and(|v| v == "yes") {
        return true;
    }
    if props.get("IdleHint").is_some_and(|v| v == "yes") {
        if let Some(since) = props
            .get("IdleSinceHintMonotonic")
            .and_then(|v| v.parse::<u64>().ok())
        {
            return now_monotonic_us.saturating_sub(since) >= idle_secs.saturating_mul(1_000_000);
        }
    }
    false
}

/// Monotonic clock in µs since boot, via `/proc/uptime`.
pub fn monotonic_us() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = text.split_whitespace().next()?.parse().ok()?;
    Some((secs * 1_000_000.0) as u64)
}

/// Probe desktop idle state. Idle when any graphical session idled
/// past `idle_secs` (or is locked); Active otherwise — including all
/// errors and headless hosts (fail-safe keeps headroom).
pub fn poll_desktop_idle(idle_secs: u64) -> IdleState {
    fn run(args: &[&str]) -> Option<String> {
        let out = std::process::Command::new(loginctl_bin())
            .args(args)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout).ok()
    }
    let text = match run(&["list-sessions", "--no-legend"]) {
        Some(text) => text,
        None => return IdleState::Active,
    };
    let now = monotonic_us().unwrap_or(0);
    for id in parse_sessions_list(&text).iter().take(16) {
        let props = match run(&[
            "show-session",
            id,
            "-p",
            "Type,IdleHint,IdleSinceHintMonotonic,LockedHint",
        ]) {
            Some(text) => parse_session_props(&text),
            None => continue,
        };
        if session_is_idle(&props, idle_secs, now) {
            return IdleState::Idle;
        }
    }
    IdleState::Active
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

    #[test]
    fn mode_parses_leniently() {
        assert_eq!(AfkMode::parse("auto"), AfkMode::Auto);
        assert_eq!(AfkMode::parse("ALWAYS"), AfkMode::Always);
        assert_eq!(AfkMode::parse(" never "), AfkMode::Never);
        assert_eq!(AfkMode::parse("bogus"), AfkMode::Auto);
        assert_eq!(AfkMode::parse(""), AfkMode::Auto);
    }

    #[test]
    fn session_list_parses_first_column() {
        let text = "1 1000 linux - 426 manager - no -\n2 1000 linux seat0 tty2\n";
        assert_eq!(parse_sessions_list(text), vec!["1", "2"]);
        assert!(parse_sessions_list("").is_empty());
    }

    fn props(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn idle_rules_cover_graphical_lock_and_threshold() {
        let now = 10_000_000_000u64; // ~2.7h after boot
                                     // Non-graphical sessions never count, even when idle.
        let manager = props(&[("Type", "unspecified"), ("IdleHint", "yes")]);
        assert!(!session_is_idle(&manager, 300, now));
        // Active desktop: hint set but threshold unmet.
        let fresh = props(&[
            ("Type", "wayland"),
            ("IdleHint", "yes"),
            ("IdleSinceHintMonotonic", "9999900000"),
        ]);
        assert!(!session_is_idle(&fresh, 300, now));
        // Long idle desktop counts.
        let stale = props(&[
            ("Type", "x11"),
            ("IdleHint", "yes"),
            ("IdleSinceHintMonotonic", "1000000"),
        ]);
        assert!(session_is_idle(&stale, 300, now));
        // Locked screen counts regardless of hints.
        let locked = props(&[("Type", "wayland"), ("LockedHint", "yes")]);
        assert!(session_is_idle(&locked, 300, now));
        // Malformed timestamps fail safe.
        let broken = props(&[
            ("Type", "wayland"),
            ("IdleHint", "yes"),
            ("IdleSinceHintMonotonic", "soon"),
        ]);
        assert!(!session_is_idle(&broken, 300, now));
    }

    #[test]
    fn probe_uses_stub_binary_and_fails_safe() {
        // Stub loginctl: one idle graphical session.
        let dir = crate::test_support::TempDir::new("afk-stub").unwrap();
        let stub = dir.path().join("loginctl");
        std::fs::write(
            &stub,
            "#!/bin/sh\nif [ \"$1\" = \"list-sessions\" ]; then echo '3 1000 u seat0 -'; else printf 'Type=wayland\\nIdleHint=yes\\nIdleSinceHintMonotonic=1000\\nLockedHint=no\\n'; fi\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::env::set_var("RUNNER_LOGINCTL", &stub);
        // Threshold 0: the stub idles since boot, so any host uptime
        // (even a fresh CI VM under the 300s default) reads Idle.
        assert_eq!(poll_desktop_idle(0), IdleState::Idle);
        // Missing binary fails safe to Active.
        std::env::set_var("RUNNER_LOGINCTL", "/nonexistent/loginctl-stub");
        assert_eq!(poll_desktop_idle(300), IdleState::Active);
        std::env::remove_var("RUNNER_LOGINCTL");
    }
}
