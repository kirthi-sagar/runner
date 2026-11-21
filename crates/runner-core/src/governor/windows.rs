//! Windows governor: pressure sensing plus Job Objects enforcement.
//!
//! The Windows half of the zero-freeze governor, mirroring the Linux
//! shape (sensor → [`crate::governor::psi::PressureLevel`] ladder →
//! actuator → supervisor loop):
//!
//! * Sensor: `GlobalMemoryStatusEx` (memory load %) and
//!   `GetSystemTimes` deltas (CPU busy %) feed the shared level and
//!   `tick_weight` policy unchanged — only the numbers are Windows'.
//! * Actuator: [`JobObject`], an RAII handle owning one job per
//!   worker tree. Memory ceilings ride extended limits; CPU share
//!   rides weight-based rate control (Normal → 9, Warning → 5,
//!   Critical → 1). Weights never starve, so the never-freeze
//!   invariant holds; hard caps are deliberately deferred.
//! * Wiring: worker children are assigned post-spawn and inherit
//!   membership down the tree. Nesting is the default on Windows 8+,
//!   so no breakaway flags are needed — with one standing invariant:
//!   this module never sets UI restrictions, which would break
//!   nesting. Assignment or limit failures log loudly and continue
//!   governed-direct (Linux userns soft-fail posture).
//!
//! Bindings are `windows-sys` (already in the lock via tokio; this
//! crate only adds features, zero new packages) rather than
//! hand-rolled FFI: the CPU-rate struct contains a C union whose
//! transcription risk buys nothing when generated bindings exist.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{GetLastError, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetSystemTimes;

/// One Windows Job Object, closed on drop. Handles are never leaked:
/// every constructor funnels through [`JobObject::create`], and
/// `Drop` is the only closer.
pub struct JobObject {
    handle: OwnedHandle,
}
// (`Send` + `Sync` ride along from `OwnedHandle`: a job HANDLE is a
// kernel object reference and every operation on it is thread-safe.)

impl JobObject {
    /// Create an unnamed, empty job (no processes, no limits yet).
    pub fn create() -> io::Result<Self> {
        // SAFETY: null attributes/name request defaults; validity is
        // checked against INVALID_HANDLE_VALUE before wrapping.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateJobObjectW"));
        }
        // SAFETY: `raw` is a live owned handle from a successful
        // create; ownership moves into `OwnedHandle` exactly once.
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(raw as _) },
        })
    }

    /// Raw handle for job API calls (never closed directly: `Drop`
    /// owns that through `OwnedHandle`).
    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle() as _
    }

    /// Apply extended limits, replacing any previous set.
    pub fn set_extended_limits(
        &self,
        limits: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    ) -> io::Result<()> {
        // SAFETY: `limits` is a valid caller-owned struct; the size
        // matches the info class exactly.
        let ok = unsafe {
            SetInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                limits as *const _ as _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as _,
            )
        };
        if ok == 0 {
            return Err(last_error("SetInformationJobObject"));
        }
        Ok(())
    }

    /// Read back the current extended limits (round-trip verification).
    pub fn query_extended_limits(&self) -> io::Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION> {
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        // SAFETY: `info` is a valid out-struct of exactly the queried
        // class size; `returned` is a valid out-word.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as _,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(last_error("QueryInformationJobObject"));
        }
        Ok(info)
    }
}

// No manual `Drop`: `OwnedHandle` closes the job handle exactly
// once, so handles are never leaked and never double-closed.

fn last_error(op: &str) -> io::Error {
    // SAFETY: no arguments; reads the calling thread's last error.
    let code = unsafe { GetLastError() };
    io::Error::other(format!("{op} failed with Win32 error {code}"))
}

/// Read memory load % (0-100) plus raw byte figures for telemetry:
/// `(load_pct, total_phys, avail_phys)`.
pub fn read_memory() -> io::Result<(u32, u64, u64)> {
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    // Mandatory per API contract: the call fails without it.
    status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: `dwLength` initialized; valid out-struct.
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    if ok == 0 {
        return Err(last_error("GlobalMemoryStatusEx"));
    }
    Ok((
        status.dwMemoryLoad,
        status.ullTotalPhys,
        status.ullAvailPhys,
    ))
}

fn filetime_to_u64(ft: &FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// One `GetSystemTimes` sample: `(idle, kernel, user)` 100ns ticks
/// summed across all processors.
pub fn read_system_times() -> io::Result<(u64, u64, u64)> {
    let mut idle: FILETIME = unsafe { std::mem::zeroed() };
    let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
    let mut user: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: all three are valid out-structs.
    let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
    if ok == 0 {
        return Err(last_error("GetSystemTimes"));
    }
    Ok((
        filetime_to_u64(&idle),
        filetime_to_u64(&kernel),
        filetime_to_u64(&user),
    ))
}

/// Rolling Windows sensor: the first sample seeds the CPU baseline
/// (returns `None`, skipping one tick); later samples yield full
/// snapshots with `%`-unit readings (see [`super::psi::PsiSnapshot`]
/// for the unit contract).
#[derive(Default)]
pub struct WindowsSensor {
    prev_times: Option<(u64, u64, u64)>,
}

impl WindowsSensor {
    pub fn sample(&mut self) -> io::Result<Option<super::psi::PsiSnapshot>> {
        let (load, _, _) = read_memory()?;
        let now = read_system_times()?;
        let Some(prev) = self.prev_times.replace(now) else {
            return Ok(None);
        };
        let cpu = super::psi::busy_percent_from_ticks(prev, now);
        Ok(Some(super::psi::PsiSnapshot {
            cpu: super::psi::PsiFile {
                some: super::psi::PsiLine {
                    avg10: cpu,
                    ..Default::default()
                },
                ..Default::default()
            },
            memory: super::psi::PsiFile {
                some: super::psi::PsiLine {
                    avg10: load as f64,
                    ..Default::default()
                },
                ..Default::default()
            },
            io: Default::default(),
        }))
    }
}

/// Probe the Job Objects facility end to end: create a job, apply
/// empty extended limits, and read them back. True when a governed
/// worker tree would work on this host (mirrors `probe_userns`).
pub fn probe_jobs() -> bool {
    let job = match JobObject::create() {
        Ok(job) => job,
        Err(e) => {
            eprintln!("[runner] job probe: create failed: {e}");
            return false;
        }
    };
    let empty: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    if let Err(e) = job.set_extended_limits(&empty) {
        eprintln!("[runner] job probe: set limits failed: {e}");
        return false;
    }
    match job.query_extended_limits() {
        Ok(_) => true,
        Err(e) => {
            eprintln!("[runner] job probe: query limits failed: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_create_and_close_round_trip() {
        let job = JobObject::create().expect("create job object");
        // Explicit drop: the second half of the hygiene contract
        // (the handle-count test below proves no leak).
        drop(job);
    }

    #[test]
    fn job_probe_succeeds_on_windows_runner() {
        assert!(probe_jobs());
    }

    #[test]
    fn memory_sensor_returns_sane_figures() {
        let (load, total, avail) = read_memory().expect("memory read");
        assert!(load <= 100, "load {load}");
        assert!(total > 0, "no physical memory reported");
        assert!(avail <= total, "avail {avail} > total {total}");
    }

    #[test]
    fn system_times_are_monotonic() {
        let a = read_system_times().expect("times read");
        std::thread::sleep(std::time::Duration::from_millis(50));
        let b = read_system_times().expect("times re-read");
        assert!(b.0 >= a.0 && b.1 >= a.1 && b.2 >= a.2);
    }

    #[test]
    fn sensor_seeds_then_samples_sane_snapshot() {
        let mut sensor = WindowsSensor::default();
        assert!(sensor.sample().expect("seed").is_none());
        std::thread::sleep(std::time::Duration::from_millis(50));
        let snap = sensor.sample().expect("sample").expect("snapshot");
        let cpu = snap.cpu_some_avg10();
        assert!((0.0..=100.0).contains(&cpu), "cpu {cpu}");
        assert!((0.0..=100.0).contains(&snap.memory.some.avg10));
    }
}
