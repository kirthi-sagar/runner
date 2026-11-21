//! Pressure Stall Information (PSI) poller.
//!
//! Polls `/proc/pressure/{cpu,memory,io}` every [`POLL_INTERVAL_MS`].
//!
//! # CPU refinement (verified research)
//!
//! CPU `full` is **undefined at system level** (reported as zero since
//! Linux 5.13), so the CPU governor keys strictly off **`some avg10`**.
//! Memory uses `some avg10`; I/O uses `full avg10` per the spec table.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Poll interval for `/proc/pressure/*` (spec section 3.2).
pub const POLL_INTERVAL_MS: u64 = 250;

/// CPU `some avg10` thresholds: normal < 20, warning 20-40, critical > 40.
pub const CPU_WARN: f64 = 20.0;
pub const CPU_CRIT: f64 = 40.0;
/// Memory `some avg10` thresholds.
pub const MEM_WARN: f64 = 5.0;
pub const MEM_CRIT: f64 = 15.0;
/// I/O `full avg10` thresholds.
pub const IO_WARN: f64 = 3.0;
pub const IO_CRIT: f64 = 10.0;
/// Windows `%`-scale thresholds (CPU busy %, memory load %): PSI
/// stall bands would misread percentages (a typical load % sits
/// permanently "critical" on stall bands), so Windows classifies
/// against its own defaults. Operator config overrides both.
pub const WIN_CPU_WARN: f64 = 75.0;
pub const WIN_CPU_CRIT: f64 = 90.0;
pub const WIN_MEM_WARN: f64 = 80.0;
pub const WIN_MEM_CRIT: f64 = 95.0;

/// Pressure severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PressureLevel {
    Normal,
    Warning,
    Critical,
}

/// Classify CPU pressure from `some avg10`.
pub fn cpu_level(some_avg10: f64) -> PressureLevel {
    level(some_avg10, CPU_WARN, CPU_CRIT)
}

/// Classify CPU pressure with operator-configured thresholds
/// (`runner.toml` governor section; same band semantics as [`cpu_level`]).
pub fn cpu_level_with(some_avg10: f64, warn: f64, crit: f64) -> PressureLevel {
    level(some_avg10, warn, crit)
}

/// Classify memory pressure from `some avg10`.
pub fn mem_level(some_avg10: f64) -> PressureLevel {
    level(some_avg10, MEM_WARN, MEM_CRIT)
}

/// Classify memory pressure against explicit bands (Windows load %
/// via [`WIN_MEM_WARN`]/[`WIN_MEM_CRIT`]).
pub fn mem_level_with(value: f64, warn: f64, crit: f64) -> PressureLevel {
    level(value, warn, crit)
}

/// CPU busy % between two `GetSystemTimes` samples (`(idle, kernel,
/// user)` 100ns ticks). Kernel time includes idle per the API docs,
/// so busy ticks = (kernel − idle) + user over total ticks. Yields
/// 0.0 when nothing elapsed; saturating throughout (counter
/// wrap/race safety).
pub fn busy_percent_from_ticks(prev: (u64, u64, u64), next: (u64, u64, u64)) -> f64 {
    let idle = next.0.saturating_sub(prev.0);
    let kernel = next.1.saturating_sub(prev.1);
    let user = next.2.saturating_sub(prev.2);
    let total = kernel.saturating_add(user);
    if total == 0 {
        return 0.0;
    }
    let busy = kernel.saturating_sub(idle).saturating_add(user);
    busy as f64 / total as f64 * 100.0
}

/// Classify I/O pressure from `full avg10`.
pub fn io_level(full_avg10: f64) -> PressureLevel {
    level(full_avg10, IO_WARN, IO_CRIT)
}

fn level(value: f64, warn: f64, crit: f64) -> PressureLevel {
    if value > crit {
        PressureLevel::Critical
    } else if value >= warn {
        PressureLevel::Warning
    } else {
        PressureLevel::Normal
    }
}

/// One PSI stall line (`some` or `full`).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total: u64,
}

/// Parsed `/proc/pressure/<resource>` file.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiFile {
    pub some: PsiLine,
    pub full: PsiLine,
}

/// Parse one PSI line, e.g. `some avg10=1.26 avg60=1.00 avg300=1.27 total=1962437453`.
pub fn parse_psi_line(line: &str) -> Result<PsiLine, String> {
    let mut avg10 = None;
    let mut avg60 = None;
    let mut avg300 = None;
    let mut total = None;
    for token in line.split_whitespace().skip(1) {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| format!("malformed PSI token: {token}"))?;
        match key {
            "avg10" => avg10 = value.parse::<f64>().ok(),
            "avg60" => avg60 = value.parse::<f64>().ok(),
            "avg300" => avg300 = value.parse::<f64>().ok(),
            "total" => total = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    Ok(PsiLine {
        avg10: avg10.ok_or("missing avg10")?,
        avg60: avg60.ok_or("missing avg60")?,
        avg300: avg300.ok_or("missing avg300")?,
        total: total.ok_or("missing total")?,
    })
}

/// Parse a full `/proc/pressure/<resource>` file body.
pub fn parse_psi_file(text: &str) -> Result<PsiFile, String> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        if line.starts_with("some ") {
            some = Some(parse_psi_line(line)?);
        } else if line.starts_with("full ") {
            full = Some(parse_psi_line(line)?);
        }
    }
    Ok(PsiFile {
        some: some.ok_or("missing some line")?,
        full: full.ok_or("missing full line")?,
    })
}

/// Point-in-time pressure snapshot across all three resources.
/// Units are platform-defined: PSI stall % on Linux, Win32 load/busy
/// % on Windows (I/O stays zero there — no unprivileged disk-pressure
/// sensor). Classification bands follow the platform; raw values
/// stay honest per platform.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiSnapshot {
    pub cpu: PsiFile,
    pub memory: PsiFile,
    pub io: PsiFile,
}

impl PsiSnapshot {
    /// CPU `some avg10` — the sole CPU governor input.
    pub fn cpu_some_avg10(&self) -> f64 {
        self.cpu.some.avg10
    }

    /// Classify the CPU reading. Snapshot units are platform-defined
    /// (PSI stall % on Linux, busy % on Windows), so the bands follow
    /// the platform; every consumer stays correct with no call-site
    /// changes.
    pub fn cpu_pressure(&self) -> PressureLevel {
        #[cfg(windows)]
        {
            cpu_level_with(self.cpu_some_avg10(), WIN_CPU_WARN, WIN_CPU_CRIT)
        }
        #[cfg(not(windows))]
        {
            cpu_level(self.cpu_some_avg10())
        }
    }

    /// Classify the memory reading (PSI stall % on Linux, load % on
    /// Windows — see [`Self::cpu_pressure`]).
    pub fn mem_pressure(&self) -> PressureLevel {
        #[cfg(windows)]
        {
            mem_level_with(self.memory.some.avg10, WIN_MEM_WARN, WIN_MEM_CRIT)
        }
        #[cfg(not(windows))]
        {
            mem_level(self.memory.some.avg10)
        }
    }

    pub fn io_pressure(&self) -> PressureLevel {
        io_level(self.io.full.avg10)
    }
}

/// Read one pressure file from a `/proc/pressure`-shaped directory.
pub fn read_psi_file(dir: &Path, resource: &str) -> io::Result<PsiFile> {
    let text = fs::read_to_string(dir.join(resource))?;
    parse_psi_file(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Read a live snapshot from `/proc/pressure`.
#[cfg(unix)]
pub fn read_snapshot() -> io::Result<PsiSnapshot> {
    read_snapshot_from(Path::new("/proc/pressure"))
}

/// Windows has no PSI; callers already degrade on `Err`
/// (`unwrap_or_default` / `.ok()` yield zero snapshots).
#[cfg(windows)]
pub fn read_snapshot() -> io::Result<PsiSnapshot> {
    eprintln!("PSI unavailable on Windows");
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "PSI unavailable on Windows",
    ))
}

/// Read a snapshot from an alternate pressure directory (tests).
pub fn read_snapshot_from(dir: &Path) -> io::Result<PsiSnapshot> {
    Ok(PsiSnapshot {
        cpu: read_psi_file(dir, "cpu")?,
        memory: read_psi_file(dir, "memory")?,
        io: read_psi_file(dir, "io")?,
    })
}

/// Background tokio poller publishing the latest snapshot.
pub struct PsiPoller {
    handle: JoinHandle<()>,
    rx: watch::Receiver<PsiSnapshot>,
}

impl PsiPoller {
    /// Spawn the 250ms poll loop. The first read happens immediately.
    pub fn spawn() -> Self {
        let initial = read_snapshot().unwrap_or_default();
        let (tx, rx) = watch::channel(initial);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(POLL_INTERVAL_MS));
            loop {
                interval.tick().await;
                match read_snapshot() {
                    Ok(snapshot) => {
                        if tx.send(snapshot).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("runner: PSI read failed: {e}");
                    }
                }
            }
        });
        Self { handle, rx }
    }

    /// Latest snapshot without waiting.
    pub fn latest(&self) -> PsiSnapshot {
        *self.rx.borrow()
    }

    /// Subscribe to snapshot updates.
    pub fn subscribe(&self) -> watch::Receiver<PsiSnapshot> {
        self.rx.clone()
    }

    /// Stop the background task.
    pub fn stop(self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU_SAMPLE: &str = "some avg10=1.26 avg60=1.00 avg300=1.27 total=1962437453\n\
         full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";

    #[test]
    fn parses_pressure_file() {
        let file = parse_psi_file(CPU_SAMPLE).unwrap();
        assert_eq!(file.some.avg10, 1.26);
        assert_eq!(file.some.total, 1_962_437_453);
        assert_eq!(file.full.avg10, 0.0);
    }

    #[test]
    fn cpu_thresholds_match_spec() {
        assert_eq!(cpu_level(0.0), PressureLevel::Normal);
        assert_eq!(cpu_level(19.99), PressureLevel::Normal);
        assert_eq!(cpu_level(20.0), PressureLevel::Warning);
        assert_eq!(cpu_level(40.0), PressureLevel::Warning);
        assert_eq!(cpu_level(40.01), PressureLevel::Critical);
    }

    #[test]
    fn mem_and_io_thresholds_match_spec() {
        assert_eq!(mem_level(4.99), PressureLevel::Normal);
        assert_eq!(mem_level(5.0), PressureLevel::Warning);
        assert_eq!(mem_level(15.01), PressureLevel::Critical);
        assert_eq!(io_level(2.99), PressureLevel::Normal);
        assert_eq!(io_level(3.0), PressureLevel::Warning);
        assert_eq!(io_level(10.01), PressureLevel::Critical);
    }

    #[test]
    fn mem_level_with_honors_explicit_bands() {
        assert_eq!(
            mem_level_with(79.9, WIN_MEM_WARN, WIN_MEM_CRIT),
            PressureLevel::Normal
        );
        assert_eq!(
            mem_level_with(80.0, WIN_MEM_WARN, WIN_MEM_CRIT),
            PressureLevel::Warning
        );
        assert_eq!(
            mem_level_with(95.01, WIN_MEM_WARN, WIN_MEM_CRIT),
            PressureLevel::Critical
        );
    }

    #[test]
    fn busy_percent_from_ticks_matches_documented_math() {
        // Half the non-idle ticks busy: (200 + 200) / 800 = 50%.
        // (idle, kernel incl. idle, user) deltas.
        assert_eq!(busy_percent_from_ticks((0, 0, 0), (400, 600, 200)), 50.0);
        // All idle: 0%.
        assert_eq!(busy_percent_from_ticks((0, 0, 0), (800, 800, 0)), 0.0);
        // Nothing elapsed: 0%, never NaN.
        assert_eq!(busy_percent_from_ticks((7, 9, 3), (7, 9, 3)), 0.0);
        // Fully busy: 100%.
        assert_eq!(busy_percent_from_ticks((0, 0, 0), (0, 500, 500)), 100.0);
    }

    #[test]
    fn snapshot_keys_cpu_off_some_only() {
        let snapshot = PsiSnapshot {
            cpu: PsiFile {
                some: PsiLine {
                    avg10: 50.0,
                    ..Default::default()
                },
                full: PsiLine {
                    avg10: 0.0,
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        assert_eq!(snapshot.cpu_some_avg10(), 50.0);
        assert_eq!(snapshot.cpu_pressure(), PressureLevel::Critical);
    }

    #[tokio::test]
    async fn poller_publishes_live_snapshot() {
        let poller = PsiPoller::spawn();
        // Live /proc read; only assert the channel works.
        let snapshot = poller.latest();
        let _ = snapshot.cpu_some_avg10();
        poller.stop();
    }
}
