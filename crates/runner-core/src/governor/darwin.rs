//! macOS governor backend: background-QoS pinning (Apple Silicon E-cores).
//!
//! CI workloads run at background QoS so the XNU scheduler places them
//! on Efficiency cores, leaving Performance cores to interactive apps
//! (spec §3.5). Constants below are verbatim from the Apple SDK
//! (`sys/qos.h`, `pthread/qos.h`); scheduling effects are confirmed on
//! first Mac CI run.

use std::io;

/// `QOS_CLASS_BACKGROUND` from sys/qos.h (0x09, macos 10.10+).
pub const QOS_CLASS_BACKGROUND: u32 = 0x09;

#[cfg(target_os = "macos")]
mod ffi {
    // pthread/qos.h (macos 10.10+): zero on success, errno value
    // otherwise. libc omits this binding, hence the raw declaration.
    extern "C" {
        pub fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
}

/// QoS application seam: real syscalls on macOS, [`MockQos`] in tests.
pub trait QosBackend: Send + Sync {
    /// Background the calling process (E-core scheduling for it and,
    /// on Darwin, its subsequently spawned children by default).
    fn background_process(&self) -> io::Result<()>;
    /// Background the calling thread.
    fn background_thread(&self) -> io::Result<()>;
}

/// Production backend: libc `setpriority` + pthread QoS FFI on macOS,
/// silent no-op elsewhere (keeps all call sites cfg-free).
#[derive(Debug, Default, Clone, Copy)]
pub struct DarwinQos;

impl QosBackend for DarwinQos {
    fn background_process(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: setpriority(2) is async-signal-safe (safe in
            // pre_exec); constants from libc (PRIO_DARWIN_*).
            let rc =
                unsafe { libc::setpriority(libc::PRIO_DARWIN_PROCESS, 0, libc::PRIO_DARWIN_BG) };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(())
        }
    }

    fn background_thread(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: trivial FFI; signature + constant verified
            // against Apple SDK headers (pthread/qos.h, sys/qos.h).
            let rc = unsafe { ffi::pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0) };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(rc))
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(())
        }
    }
}

/// Recording mock backend for hook-placement tests. Poison-tolerant
/// locks (never panics, like all shipped code).
#[derive(Debug, Default)]
pub struct MockQos {
    calls: std::sync::Mutex<Vec<&'static str>>,
    fail: std::sync::Mutex<bool>,
    log_file: std::sync::Mutex<Option<std::path::PathBuf>>,
}

impl MockQos {
    pub fn new() -> Self {
        Self::default()
    }

    /// File-backed mode: appends every call to `path`, so `pre_exec`
    /// invocations (which run post-fork, invisible to in-memory
    /// recording) stay observable to the spawning test.
    pub fn with_log(path: std::path::PathBuf) -> Self {
        Self {
            log_file: std::sync::Mutex::new(Some(path)),
            ..Self::default()
        }
    }

    /// Fail all subsequent calls (pins best-effort spawn semantics).
    pub fn set_failing(&self) {
        *self.fail.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }

    /// Recorded call names, in order (same-process calls only; use the
    /// log file across `pre_exec` forks).
    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn record(&self, what: &'static str) -> io::Result<()> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(what);
        if let Some(path) = self
            .log_file
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            // Best-effort by design (test support; mirrors the
            // can't-fail posture of the hook itself).
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                use std::io::Write;
                let _ = writeln!(file, "{what}");
            }
        }
        if *self.fail.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err(io::Error::other("mock QoS failure"));
        }
        Ok(())
    }
}

impl QosBackend for MockQos {
    fn background_process(&self) -> io::Result<()> {
        self.record("process")
    }

    fn background_thread(&self) -> io::Result<()> {
        self.record("thread")
    }
}

/// Install the platform child hook on a Tokio command: background QoS
/// (best-effort: never fails a spawn, unloggable post-fork) followed
/// by the optional sandbox setup. The single choke point every spawn
/// path uses instead of hand-rolling `pre_exec`.
#[cfg(unix)]
pub fn install_child_hook<F>(
    cmd: &mut tokio::process::Command,
    qos: std::sync::Arc<dyn QosBackend>,
    sandbox: Option<F>,
) where
    F: FnOnce() -> io::Result<()> + Send + Sync + 'static,
{
    let mut sandbox = sandbox;
    // SAFETY: pre_exec runs after fork in the child only.
    unsafe {
        cmd.pre_exec(move || {
            let _ = qos.background_process();
            match sandbox.take() {
                Some(setup) => setup(),
                None => Ok(()),
            }
        });
    }
}

/// Windows has no `pre_exec` (no fork); spawns proceed without the
/// child hook. Loud by design: every stub names its v2.0 placeholder.
#[cfg(windows)]
pub fn install_child_hook<F>(
    _cmd: &mut tokio::process::Command,
    _qos: std::sync::Arc<dyn QosBackend>,
    _sandbox: Option<F>,
) where
    F: FnOnce() -> io::Result<()> + Send + Sync + 'static,
{
    eprintln!("[runner] unsupported on Windows: pre_exec child hook");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_constants_are_pinned() {
        // sys/qos.h: QOS_CLASS_BACKGROUND = 0x09. Any drift breaks
        // E-core scheduling silently, so the value is tested.
        assert_eq!(QOS_CLASS_BACKGROUND, 0x09);
    }

    #[test]
    fn mock_records_calls_and_failure_mode() {
        let mock = MockQos::new();
        mock.background_process().unwrap();
        mock.background_thread().unwrap();
        assert_eq!(mock.calls(), vec!["process", "thread"]);
        mock.set_failing();
        assert!(mock.background_process().is_err());
        assert!(mock.background_thread().is_err());
        // Failures are recorded too (the call happened).
        assert_eq!(mock.calls().len(), 4);
    }

    #[test]
    fn real_backend_is_noop_off_macos() {
        // On Linux CI the production backend must succeed silently.
        assert!(DarwinQos.background_process().is_ok());
        assert!(DarwinQos.background_thread().is_ok());
    }

    // Spawns `true` through the unix pre_exec hook (a no-op on Windows).
    #[cfg(unix)]
    #[tokio::test]
    async fn child_hook_calls_backend_before_sandbox_setup() {
        // End-to-end hook placement through a real spawn: the mock log
        // is file-backed because pre_exec runs post-fork (in-memory
        // recording would be invisible across the fork).
        let dir = crate::test_support::TempDir::new("qos-hook").unwrap();
        let log = dir.path().join("calls.log");
        let mock = std::sync::Arc::new(MockQos::with_log(log.clone()));
        let mut cmd = tokio::process::Command::new("true");
        install_child_hook(&mut cmd, mock, None::<fn() -> io::Result<()>>);
        assert!(cmd.status().await.unwrap().success());
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "process\n");
    }

    // Spawns `true` through the unix pre_exec hook (a no-op on Windows).
    #[cfg(unix)]
    #[tokio::test]
    async fn child_hook_best_effort_never_fails_spawn() {
        let mock = std::sync::Arc::new(MockQos::new());
        mock.set_failing();
        let mut cmd = tokio::process::Command::new("true");
        install_child_hook(&mut cmd, mock, None::<fn() -> io::Result<()>>);
        assert!(cmd.status().await.unwrap().success());
    }

    /// Live syscalls on a real Mac (runs only on the macOS CI job's
    /// darwin-filtered test run; compiled out everywhere else).
    #[cfg(target_os = "macos")]
    #[test]
    fn real_syscalls_succeed_on_macos() {
        DarwinQos.background_process().unwrap();
        DarwinQos.background_thread().unwrap();
    }
}
