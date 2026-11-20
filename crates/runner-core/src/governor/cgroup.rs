//! cgroups v2 slice management for `runner` workloads.
//!
//! Slice: `/sys/fs/cgroup/runner.slice/` with baseline `cpu.weight = 100`
//! against the interactive `user.slice` default of `1000`.
//!
//! # Timer safety
//!
//! This module deliberately exposes **no** freeze/thaw API. `cgroup.freeze`
//! suspends processes while `CLOCK_MONOTONIC` keeps advancing, which kills
//! database keepalives and test timers. Under pressure the governor drops
//! `cpu.weight` to [`WEIGHT_TRICKLE`] instead, keeping tasks runnable on
//! ~0.5% CPU while yielding >99% throughput to foreground apps.

use std::env;
#[cfg(unix)]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::psi::{cpu_level, cpu_level_with, PressureLevel};

/// cgroup slice name for all runner workloads.
pub const SLICE_NAME: &str = "runner.slice";
/// Baseline weight: interactive `user.slice` (1000) gets 10x our share.
pub const WEIGHT_NORMAL: u32 = 100;
/// Warning weight under moderate CPU pressure (PSI 20-40%).
pub const WEIGHT_WARNING: u32 = 25;
/// Minimum CFS weight: trickle throttle under critical pressure (>40%).
pub const WEIGHT_TRICKLE: u32 = 1;
/// Kernel-valid `cpu.weight` range.
pub const WEIGHT_MIN: u32 = 1;
pub const WEIGHT_MAX: u32 = 10_000;

/// Env override for the cgroup root (used by tests to avoid touching the host).
pub const CGROUP_ROOT_ENV: &str = "RUNNER_CGROUP_ROOT";
/// Default cgroups v2 mount point.
pub const CGROUP_ROOT_DEFAULT: &str = "/sys/fs/cgroup";

/// Map a CPU pressure level to its CFS weight.
pub fn weight_for_level(level: PressureLevel) -> u32 {
    match level {
        PressureLevel::Normal => WEIGHT_NORMAL,
        PressureLevel::Warning => WEIGHT_WARNING,
        PressureLevel::Critical => WEIGHT_TRICKLE,
    }
}

/// Map a CPU PSI `some avg10` percentage directly to its CFS weight.
pub fn weight_for_cpu_psi(some_avg10: f64) -> u32 {
    weight_for_level(cpu_level(some_avg10))
}

/// Pressure-driven weight with operator-configured thresholds.
pub fn weight_for_cpu_psi_with(some_avg10: f64, warn: f64, crit: f64) -> u32 {
    weight_for_level(cpu_level_with(some_avg10, warn, crit))
}

/// Handle to the `runner.slice` cgroup.
#[derive(Debug, Clone)]
pub struct CgroupSlice {
    path: PathBuf,
}

impl CgroupSlice {
    /// Open the system slice (`$RUNNER_CGROUP_ROOT/runner.slice`,
    /// default `/sys/fs/cgroup/runner.slice`).
    pub fn system_default() -> Self {
        let root = env::var(CGROUP_ROOT_ENV).unwrap_or_else(|_| CGROUP_ROOT_DEFAULT.to_string());
        Self::new(Path::new(&root).join(SLICE_NAME))
    }

    /// Open a slice at an explicit path (tests, custom roots).
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Slice directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create the slice if missing. Does not touch weights.
    #[cfg(unix)]
    pub fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(&self.path)
    }

    /// Windows has no cgroups; every mutating/querying method fails
    /// loudly and callers degrade (best-effort `.ok()` / fallbacks).
    #[cfg(windows)]
    pub fn ensure(&self) -> io::Result<()> {
        eprintln!("cgroups unavailable on Windows");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroups unavailable on Windows",
        ))
    }

    /// Read the current `cpu.weight` value.
    #[cfg(unix)]
    pub fn weight(&self) -> io::Result<u32> {
        let raw = fs::read_to_string(self.path.join("cpu.weight"))?;
        raw.trim()
            .parse::<u32>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    #[cfg(windows)]
    pub fn weight(&self) -> io::Result<u32> {
        eprintln!("cgroups unavailable on Windows");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroups unavailable on Windows",
        ))
    }

    /// Write a `cpu.weight` value (kernel range 1-10000).
    #[cfg(unix)]
    pub fn set_weight(&self, weight: u32) -> io::Result<()> {
        if !(WEIGHT_MIN..=WEIGHT_MAX).contains(&weight) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cpu.weight {weight} outside [{WEIGHT_MIN},{WEIGHT_MAX}]"),
            ));
        }
        fs::write(self.path.join("cpu.weight"), weight.to_string())
    }

    #[cfg(windows)]
    pub fn set_weight(&self, _weight: u32) -> io::Result<()> {
        eprintln!("cgroups unavailable on Windows");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroups unavailable on Windows",
        ))
    }

    /// Ensure the slice exists and reset it to the baseline weight.
    #[cfg(unix)]
    pub fn ensure_baseline(&self) -> io::Result<()> {
        self.ensure()?;
        self.set_weight(WEIGHT_NORMAL)
    }

    #[cfg(windows)]
    pub fn ensure_baseline(&self) -> io::Result<()> {
        eprintln!("cgroups unavailable on Windows");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroups unavailable on Windows",
        ))
    }

    /// Apply the pressure-driven weight for a CPU PSI `some avg10` reading.
    /// Returns the weight that was written.
    #[cfg(unix)]
    pub fn apply_pressure(&self, cpu_some_avg10: f64) -> io::Result<u32> {
        let weight = weight_for_cpu_psi(cpu_some_avg10);
        self.set_weight(weight)?;
        Ok(weight)
    }

    #[cfg(windows)]
    pub fn apply_pressure(&self, _cpu_some_avg10: f64) -> io::Result<u32> {
        eprintln!("cgroups unavailable on Windows");
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cgroups unavailable on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn weight_ladder_matches_spec() {
        assert_eq!(weight_for_cpu_psi(0.0), 100);
        assert_eq!(weight_for_cpu_psi(19.9), 100);
        assert_eq!(weight_for_cpu_psi(20.0), 25);
        assert_eq!(weight_for_cpu_psi(40.0), 25);
        assert_eq!(weight_for_cpu_psi(40.1), 1);
        assert_eq!(weight_for_cpu_psi(100.0), 1);
    }

    #[test]
    fn slice_roundtrip_in_tempdir() {
        let dir = crate::test_support::TempDir::new("cgroup").unwrap();
        let slice = CgroupSlice::new(dir.path().join(SLICE_NAME));
        // Simulate a cgroupfs weight file.
        slice.ensure().unwrap();
        fs::write(slice.path().join("cpu.weight"), "100").unwrap();
        assert_eq!(slice.weight().unwrap(), 100);
        assert_eq!(slice.apply_pressure(50.0).unwrap(), 1);
        assert_eq!(slice.weight().unwrap(), 1);
        assert_eq!(slice.apply_pressure(10.0).unwrap(), 100);
    }

    #[test]
    fn rejects_out_of_range_weights() {
        let dir = crate::test_support::TempDir::new("cgroup-range").unwrap();
        let slice = CgroupSlice::new(dir.path().join(SLICE_NAME));
        slice.ensure().unwrap();
        assert!(slice.set_weight(0).is_err());
        assert!(slice.set_weight(10_001).is_err());
    }
}
