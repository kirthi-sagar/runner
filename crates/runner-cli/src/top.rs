//! Live terminal monitor (`runner top`): PSI gauges, governor weight,
//! slots, in-flight jobs, and fleet summary. Rendering is pure (and
//! unit-tested); only [`run`] touches the terminal.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use runner_core::governor::psi::PressureLevel;
use runner_core::governor::psi::{cpu_level_with, CPU_CRIT, CPU_WARN};
use runner_core::ipc::ipc_call;
use runner_core::status::status_report;

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn paint(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// One in-flight job row.
#[derive(Debug, Clone, Default)]
pub struct JobRow {
    pub id: String,
    pub provider: String,
    pub name: String,
    pub started_unix_ms: u64,
}

/// Everything one frame renders.
#[derive(Debug, Clone)]
pub struct TopData {
    pub cpu_some: f64,
    pub mem_some: f64,
    pub io_full: f64,
    pub warn: f64,
    pub crit: f64,
    pub weight: Option<u32>,
    pub slots: u32,
    pub jobs: Vec<JobRow>,
    pub queue_depth: u32,
    pub local_cores: u32,
    pub peers: usize,
    pub cloud_nodes: usize,
    pub drained: usize,
    pub afk_boosted: bool,
    pub daemon_online: bool,
    pub now_unix_ms: u64,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `45s`, `1m23s`, `2h05m`.
pub fn format_duration(started_unix_ms: u64, now_unix_ms: u64) -> String {
    let secs = now_unix_ms.saturating_sub(started_unix_ms) / 1000;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// `[####------]` bar, colored by warn/crit bands.
pub fn pressure_bar(value: f64, warn: f64, crit: f64, color: bool) -> String {
    const WIDTH: usize = 24;
    let frac = (value / 100.0).clamp(0.0, 1.0);
    let filled = (frac * WIDTH as f64).round() as usize;
    let bar: String = "#".repeat(filled) + &"-".repeat(WIDTH - filled);
    let level = cpu_level_with(value, warn, crit);
    let code = match level {
        PressureLevel::Normal => GREEN,
        PressureLevel::Warning => YELLOW,
        PressureLevel::Critical => RED,
    };
    paint(&format!("[{bar}]"), code, color)
}

fn weight_label(weight: Option<u32>, color: bool) -> String {
    match weight {
        Some(100) => paint("100 (normal)", GREEN, color),
        Some(25) => paint("25 (warning)", YELLOW, color),
        Some(1) => paint("1 (critical trickle)", RED, color),
        Some(w) => format!("{w}"),
        None => paint("n/a (offline)", DIM, color),
    }
}

/// Render one full frame (pure: no I/O, deterministic).
pub fn render(data: &TopData, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "runner top v{}  (q quit, {} cadence)\n",
        env!("CARGO_PKG_VERSION"),
        if data.daemon_online {
            "live"
        } else {
            "LOCAL ONLY"
        },
    ));
    if !data.daemon_online {
        out.push_str(&paint(
            "daemon offline — local view only (start with `runner start`)\n",
            YELLOW,
            color,
        ));
    }
    out.push_str(&format!(
        "CPU  {} {:5.1}% some avg10\n",
        pressure_bar(data.cpu_some, data.warn, data.crit, color),
        data.cpu_some
    ));
    out.push_str(&format!(
        "MEM  {} {:5.1}% some avg10\n",
        pressure_bar(data.mem_some, 5.0, 15.0, color),
        data.mem_some
    ));
    out.push_str(&format!(
        "IO   {} {:5.1}% full avg10\n",
        pressure_bar(data.io_full, 3.0, 10.0, color),
        data.io_full
    ));
    out.push_str(&format!(
        "governor weight {} | slots {}{}\n",
        weight_label(data.weight, color),
        data.slots,
        if data.afk_boosted { " | AFK BOOST" } else { "" }
    ));
    out.push_str(&format!(
        "jobs: {} in-flight, {} queued\n",
        data.jobs.len(),
        data.queue_depth
    ));
    for job in data.jobs.iter().take(10) {
        out.push_str(&format!(
            "  #{} [{}] {}  {}\n",
            job.id,
            job.provider,
            truncate(&job.name, 40),
            format_duration(job.started_unix_ms, data.now_unix_ms)
        ));
    }
    if data.jobs.len() > 10 {
        out.push_str(&format!("  …and {} more\n", data.jobs.len() - 10));
    }
    out.push_str(&format!(
        "fleet: {} local cores | {} WAN peers | {} cloud nodes | {} drained\n",
        data.local_cores, data.peers, data.cloud_nodes, data.drained
    ));
    out
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}…", &text[..max - 1])
    }
}

fn json_str(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string()
}

fn json_u64(value: &serde_json::Value, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

/// Gather one frame: live local PSI plus best-effort daemon snapshot.
pub async fn fetch(sock_path: &Path) -> TopData {
    let report = status_report();
    let mut data = TopData {
        cpu_some: report.host.psi_pressure.cpu_some_avg10,
        mem_some: report.host.psi_pressure.memory_some_avg10,
        io_full: report.host.psi_pressure.io_full_avg10,
        warn: CPU_WARN,
        crit: CPU_CRIT,
        weight: report.host.cgroup_weight,
        slots: 1,
        jobs: Vec::new(),
        queue_depth: 0,
        local_cores: report.host.total_cores,
        peers: 0,
        cloud_nodes: 0,
        drained: 0,
        afk_boosted: false,
        daemon_online: false,
        now_unix_ms: now_unix_ms(),
    };
    let snapshot = match ipc_call(sock_path, "snapshot").await {
        Ok(reply) => reply
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        Err(_) => return data,
    };
    if snapshot.is_null() {
        return data;
    }
    data.daemon_online = true;
    data.weight = snapshot
        .get("weight")
        .and_then(|v| v.as_u64())
        .map(|w| w as u32)
        .or(data.weight);
    data.slots = snapshot.get("slots").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
    data.queue_depth = json_u64(&snapshot, "queue_depth") as u32;
    data.warn = snapshot
        .get("psi_warn")
        .and_then(|v| v.as_f64())
        .unwrap_or(CPU_WARN);
    data.crit = snapshot
        .get("psi_crit")
        .and_then(|v| v.as_f64())
        .unwrap_or(CPU_CRIT);
    data.afk_boosted = snapshot
        .get("afk_boosted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    data.peers = snapshot
        .get("wan_peers")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    data.cloud_nodes = snapshot
        .get("cloud_nodes")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    data.drained = snapshot
        .get("drained_nodes")
        .and_then(|v| v.as_object())
        .map(|o| o.len())
        .unwrap_or(0);
    if let Some(jobs) = snapshot.get("jobs").and_then(|v| v.as_array()) {
        data.jobs = jobs
            .iter()
            .map(|j| JobRow {
                id: json_str(j, "id"),
                provider: json_str(j, "provider"),
                name: json_str(j, "name"),
                started_unix_ms: json_u64(j, "started_unix_ms"),
            })
            .collect();
    }
    data
}

/// Terminal raw-mode guard (libc termios): restores on drop.
struct RawGuard {
    fd: i32,
    orig: libc::termios,
}

impl RawGuard {
    /// Enter raw mode; `None` when stdin is not a TTY (piped use).
    fn enter() -> Option<Self> {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        if unsafe { libc::isatty(fd) } != 1 {
            return None;
        }
        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return None;
        }
        let mut raw = orig;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { fd, orig })
    }

    /// Non-blocking key poll; true on `q`/`Q`/Ctrl-C byte.
    fn quit_pressed(&self) -> bool {
        use std::io::Read;
        let mut buf = [0u8; 1];
        match std::io::stdin().read(&mut buf) {
            Ok(1) => matches!(buf[0], b'q' | b'Q' | 0x03),
            _ => false,
        }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
        }
    }
}

fn stdout_is_tty() -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe { libc::isatty(std::io::stdout().as_raw_fd()) == 1 }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    // Registration can fail in restricted containers; degrade to
    // "no signal handling" (the monitor keeps redrawing; SIGKILL
    // still works) instead of aborting.
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("runner: SIGINT handler unavailable ({e}); signals ignored");
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("runner: SIGTERM handler unavailable ({e}); signals ignored");
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
    };
    tokio::select! {
        _ = sigint.recv() => {},
        _ = sigterm.recv() => {},
    }
}

/// Run the monitor: redraw every `interval_ms` until `q`/signal.
/// `--once` prints a single frame (scripts/CI).
pub async fn run(sock_path: &Path, interval_ms: u64, once: bool) -> anyhow::Result<()> {
    let color = stdout_is_tty() && std::env::var_os("NO_COLOR").is_none();
    let data = fetch(sock_path).await;
    if once {
        print!("{}", render(&data, color));
        std::io::stdout().flush()?;
        return Ok(());
    }
    let interval = Duration::from_millis(interval_ms.clamp(100, 60_000));
    let mut stdout = std::io::stdout();
    write!(stdout, "\x1b[?25l\x1b[2J")?;
    let result = top_loop(sock_path, interval, color).await;
    writeln!(stdout, "\x1b[?25h")?;
    stdout.flush()?;
    result
}

async fn top_loop(sock_path: &Path, interval: Duration, color: bool) -> anyhow::Result<()> {
    // Single raw-mode owner: restores termios on drop (all exit paths).
    // None on non-TTY stdin: signals remain the exit path there.
    let guard = RawGuard::enter();
    loop {
        let data = fetch(sock_path).await;
        let mut stdout = std::io::stdout();
        write!(stdout, "\x1b[H{}", render(&data, color))?;
        stdout.flush()?;
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = shutdown_signal() => break,
        }
        if guard.as_ref().is_some_and(|g| g.quit_pressed()) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TopData {
        TopData {
            cpu_some: 12.5,
            mem_some: 1.0,
            io_full: 0.5,
            warn: 20.0,
            crit: 40.0,
            weight: Some(100),
            slots: 4,
            jobs: vec![JobRow {
                id: "42".to_string(),
                provider: "github".to_string(),
                name: "ci / test".to_string(),
                started_unix_ms: 1_000_000,
            }],
            queue_depth: 2,
            local_cores: 8,
            peers: 1,
            cloud_nodes: 0,
            drained: 0,
            afk_boosted: false,
            daemon_online: true,
            now_unix_ms: 1_000_000 + 95_000,
        }
    }

    #[test]
    fn frame_contains_all_sections() {
        let frame = render(&sample(), false);
        for needle in [
            "runner top v",
            "CPU",
            "MEM",
            "IO",
            "12.5%",
            "governor weight 100 (normal)",
            "slots 4",
            "1 in-flight, 2 queued",
            "#42 [github] ci / test",
            "1m35s",
            "8 local cores",
            "1 WAN peers",
            "0 cloud nodes",
            "0 drained",
        ] {
            assert!(frame.contains(needle), "missing {needle}:\n{frame}");
        }
        assert!(!frame.contains("\x1b["), "plain mode must not emit ANSI");
    }

    #[test]
    fn offline_banner_and_color_codes() {
        let mut data = sample();
        data.daemon_online = false;
        data.weight = None;
        let frame = render(&data, true);
        assert!(frame.contains("daemon offline"));
        assert!(frame.contains("n/a (offline)"));
        assert!(frame.contains("\x1b[32m"), "expected green codes");
    }

    #[test]
    fn critical_pressure_paints_red() {
        let bar = pressure_bar(90.0, 20.0, 40.0, true);
        assert!(bar.starts_with("\x1b[31m"));
        assert!(bar.contains('#'));
        let plain = pressure_bar(90.0, 20.0, 40.0, false);
        assert!(!plain.contains('\x1b'));
    }

    #[test]
    fn durations_format_across_scales() {
        assert_eq!(format_duration(1000, 46_000), "45s");
        assert_eq!(format_duration(0, 3_600_000), "1h00m");
        assert_eq!(format_duration(5000, 1000), "0s");
    }

    #[test]
    fn job_list_truncates_at_ten_rows() {
        let mut data = sample();
        data.jobs = (0..12)
            .map(|i| JobRow {
                id: i.to_string(),
                provider: "github".to_string(),
                name: format!("job-{i}"),
                started_unix_ms: 0,
            })
            .collect();
        let frame = render(&data, false);
        assert!(frame.contains("…and 2 more"));
        assert!(!frame.contains("job-11"));
    }
}
