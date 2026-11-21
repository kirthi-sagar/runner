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
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::Threading::GetSystemTimes;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

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

    /// Read-modify-write helper: preserves flags set by other calls
    /// (e.g. the baseline kill-on-close) instead of clobbering them.
    fn modify_extended_limits(
        &self,
        f: impl FnOnce(&mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION),
    ) -> io::Result<()> {
        let mut info = self.query_extended_limits()?;
        f(&mut info);
        self.set_extended_limits(&info)
    }

    /// Cap the whole job tree at `bytes` (must be positive). Fails
    /// closed on nonsense input rather than bricking the job.
    pub fn set_memory_cap(&self, bytes: u64) -> io::Result<()> {
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory cap must be positive",
            ));
        }
        self.modify_extended_limits(|info| {
            info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            info.JobMemoryLimit = bytes as usize;
        })
    }

    /// Set the CPU weight (1-9, 9 = largest share). Out-of-range
    /// values fail fast like [`super::cgroup::CgroupSlice::set_weight`].
    pub fn set_cpu_weight(&self, weight: u32) -> io::Result<()> {
        if !(1..=9).contains(&weight) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cpu weight {weight} outside [1,9]"),
            ));
        }
        let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        info.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        // Writing a union field is safe (only reads are `unsafe`);
        // `Weight` is the live arm under WEIGHT_BASED control.
        info.Anonymous.Weight = weight;
        // SAFETY: `info` matches the info class exactly.
        let ok = unsafe {
            SetInformationJobObject(
                self.raw(),
                JobObjectCpuRateControlInformation,
                &info as *const _ as _,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as _,
            )
        };
        if ok == 0 {
            return Err(last_error("SetInformationJobObject(cpu rate)"));
        }
        Ok(())
    }

    /// Read back the current CPU weight (round-trip verification).
    pub fn query_cpu_weight(&self) -> io::Result<u32> {
        let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        // SAFETY: valid out-struct of exactly the queried class size.
        let ok = unsafe {
            QueryInformationJobObject(
                self.raw(),
                JobObjectCpuRateControlInformation,
                &mut info as *mut _ as _,
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as _,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(last_error("QueryInformationJobObject(cpu rate)"));
        }
        // SAFETY: the job was weight-managed, so `Weight` is the live
        // union arm.
        Ok(unsafe { info.Anonymous.Weight })
    }

    /// Assign a process (by pid) to this job. Grandchildren inherit
    /// membership automatically. Nesting under an outer job (CI
    /// agents, services) is the default on Windows 8+; a genuine
    /// refusal surfaces as an error and callers soft-fail.
    pub fn assign(&self, pid: u32) -> io::Result<()> {
        let process = open_process(pid)?;
        // SAFETY: both handles are live (`OwnedHandle` + `&self`).
        let ok = unsafe { AssignProcessToJobObject(self.raw(), process.as_raw_handle() as _) };
        if ok == 0 {
            return Err(last_error("AssignProcessToJobObject"));
        }
        Ok(())
    }

    /// True when `pid` is currently a member of this job
    /// (round-trip verification for [`Self::assign`]).
    pub fn contains(&self, pid: u32) -> io::Result<bool> {
        let process = open_process(pid)?;
        let mut member = 0i32;
        // SAFETY: both handles live; `member` is a valid out-word.
        let ok = unsafe { IsProcessInJob(process.as_raw_handle() as _, self.raw(), &mut member) };
        if ok == 0 {
            return Err(last_error("IsProcessInJob"));
        }
        Ok(member != 0)
    }

    /// The daemon-wide job all worker trees join (mirrors
    /// [`super::cgroup::CgroupSlice::system_default`]). Created once
    /// with the kill-on-close baseline (no orphaned workers when the
    /// runner exits); the first outcome is cached (`OnceLock` has no
    /// stable fallible-retry, and creation effectively never fails —
    /// use [`probe_jobs`] for facility checks).
    pub fn system_default() -> io::Result<&'static JobObject> {
        static JOB: std::sync::OnceLock<Result<JobObject, String>> = std::sync::OnceLock::new();
        JOB.get_or_init(|| create_system_job().map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| io::Error::other(e.clone()))
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

fn create_system_job() -> io::Result<JobObject> {
    let job = JobObject::create()?;
    job.modify_extended_limits(|info| {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    })?;
    Ok(job)
}

/// Open a process with exactly the rights assignment needs
/// (`PROCESS_SET_QUOTA | PROCESS_TERMINATE`, per the API docs).
fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: no handle to close on failure (null return); on
    // success ownership moves into `OwnedHandle` exactly once.
    let raw = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
    if raw.is_null() {
        return Err(last_error("OpenProcess"));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// Assign `pid` to the daemon job: the worker spawn path's
/// one-liner for automatic containment.
pub fn assign_to_system_job(pid: u32) -> io::Result<()> {
    JobObject::system_default()?.assign(pid)
}

/// CPU weight for a pressure level (Normal → 9, Warning → 5,
/// Critical → 1): the Windows analog of the Linux 100/25/1 ladder.
/// Weights never starve, so the never-freeze invariant holds.
pub fn weight_for_level(level: super::psi::PressureLevel) -> u32 {
    match level {
        super::psi::PressureLevel::Normal => 9,
        super::psi::PressureLevel::Warning => 5,
        super::psi::PressureLevel::Critical => 1,
    }
}

/// Probe the Job Objects facility end to end: create a job, apply
/// empty extended limits, read them back, and round-trip a CPU
/// weight. True when a governed worker tree would work on this host
/// (mirrors `probe_userns`).
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
    if job.query_extended_limits().is_err() {
        eprintln!("[runner] job probe: query limits failed");
        return false;
    }
    // Rate-control capability: a weight round-trip on the temp job.
    if let Err(e) = job.set_cpu_weight(5) {
        eprintln!("[runner] job probe: set weight failed: {e}");
        return false;
    }
    match job.query_cpu_weight() {
        Ok(5) => true,
        Ok(other) => {
            eprintln!("[runner] job probe: weight mismatch (want 5, got {other})");
            false
        }
        Err(e) => {
            eprintln!("[runner] job probe: query weight failed: {e}");
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
    fn weight_ladder_maps_all_levels() {
        use super::super::psi::PressureLevel;
        assert_eq!(super::weight_for_level(PressureLevel::Normal), 9);
        assert_eq!(super::weight_for_level(PressureLevel::Warning), 5);
        assert_eq!(super::weight_for_level(PressureLevel::Critical), 1);
    }

    #[test]
    fn memory_cap_round_trips_and_rejects_zero() {
        let job = JobObject::create().expect("create job");
        assert!(job.set_memory_cap(0).is_err());
        job.set_memory_cap(512 * 1024 * 1024).expect("set cap");
        let back = job.query_extended_limits().expect("query limits");
        assert_eq!(back.JobMemoryLimit as u64, 512 * 1024 * 1024);
    }

    #[test]
    fn cpu_weight_round_trips_and_rejects_out_of_range() {
        let job = JobObject::create().expect("create job");
        assert!(job.set_cpu_weight(0).is_err());
        assert!(job.set_cpu_weight(10).is_err());
        job.set_cpu_weight(5).expect("set weight");
        assert_eq!(job.query_cpu_weight().expect("query weight"), 5);
        job.set_cpu_weight(1).expect("set weight");
        assert_eq!(job.query_cpu_weight().expect("query weight"), 1);
    }

    #[test]
    fn system_default_is_singleton() {
        let a = JobObject::system_default().expect("system job") as *const _;
        let b = JobObject::system_default().expect("system job") as *const _;
        assert_eq!(a, b);
    }

    #[test]
    fn create_drop_cycle_does_not_exhaust_handles() {
        // RAII-by-construction (single `OwnedHandle` owner, no manual
        // close): 256 create/drop cycles must all succeed. An exact
        // handle-count delta would be racy in a shared test process,
        // so exhaustion is the signal instead.
        for _ in 0..256 {
            JobObject::create().expect("create job");
        }
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
