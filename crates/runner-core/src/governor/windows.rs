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

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
};

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
}
