//! macOS power backend: IOKit system-power interest notifications
//! delivered on a dedicated thread pumping a CFRunLoop. Hand-rolled
//! FFI in the seatbelt.rs tradition (no new crates).
//!
//! Lifecycle: the pump thread runs until process exit (daemons never
//! unsubscribe), so its refcon is intentionally never reclaimed —
//! one small box for the process lifetime.

// IOMessage.h system-power values.
pub const K_IO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xe000_0270;
pub const K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON: u32 = 0xe000_0280;

/// Grace window behind `PreparingSleep`: the callback holds the
/// transition this long before allowing sleep, so handover has a
/// bounded budget without stalling lid-close (IOKit would grant up
/// to 30 s; we deliberately take far less).
pub const MACOS_SLEEP_DELAY_MS: u64 = 2000;

/// Classified system-power message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPowerMessage {
    WillSleep,
    PoweredOn,
    Other,
}

/// Pure message map (unit-tested on every platform; the FFI around
/// it only compiles on macOS).
pub fn map_power_message(message: u32) -> SystemPowerMessage {
    match message {
        K_IO_MESSAGE_SYSTEM_WILL_SLEEP => SystemPowerMessage::WillSleep,
        K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON => SystemPowerMessage::PoweredOn,
        _ => SystemPowerMessage::Other,
    }
}

/// RAII sleep veto: a `PreventUserIdleSystemSleep` power assertion,
/// released on drop.
#[cfg(target_os = "macos")]
pub struct WakeLockGuard {
    id: u32,
}

#[cfg(target_os = "macos")]
impl WakeLockGuard {
    /// Acquire the veto; `None` when power management refuses.
    pub fn acquire() -> Option<Self> {
        // SAFETY: straight-line FFI; every pointer checked, the
        // transient name string released on all paths.
        unsafe {
            let name = ffi::CFStringCreateWithCString(
                std::ptr::null(),
                c"Runner active compilation".as_ptr(),
                ffi::K_CF_STRING_ENCODING_UTF8,
            );
            if name.is_null() {
                return None;
            }
            let mut id = 0u32;
            let status = ffi::IOPMAssertionCreateWithName(
                ffi::kIOPMAssertionTypePreventUserIdleSystemSleep,
                ffi::K_IOPM_ASSERTION_LEVEL_ON,
                name,
                &mut id,
            );
            ffi::CFRelease(name);
            if status != 0 {
                return None;
            }
            Some(Self { id })
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for WakeLockGuard {
    fn drop(&mut self) {
        // SAFETY: id came from a successful create call.
        unsafe {
            ffi::IOPMAssertionRelease(self.id);
        }
    }
}

/// Spawn the pump thread; `false` (with a loud note) when power
/// management is unreachable. Rendezvous-bounded so boot never
/// blocks on a broken backend.
#[cfg(target_os = "macos")]
pub fn spawn(tx: tokio::sync::broadcast::Sender<crate::power::PowerEvent>) -> bool {
    // SAFETY: single FFI call, no out-pointers; zero means unavailable.
    let power = unsafe { ffi::IOPMFindPowerManagement(0) };
    if power == 0 {
        eprintln!("[runner] power watcher disabled: power management unreachable");
        return false;
    }
    let ctx = Box::into_raw(Box::new(CallbackCtx { tx, power }));
    // Raw pointers are not Send: cross the thread boundary as an
    // address and reconstitute inside (the box outlives the thread).
    let ctx_addr = ctx as usize;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
    std::thread::Builder::new()
        .name("runner-power-pump".to_string())
        .spawn(move || pump(ctx_addr as *mut CallbackCtx, ready_tx))
        .ok();
    // Failure to even spawn the thread reads as backend failure.
    ready_rx.recv_timeout(std::time::Duration::from_secs(1)) == Ok(true)
}

#[cfg(target_os = "macos")]
struct CallbackCtx {
    tx: tokio::sync::broadcast::Sender<crate::power::PowerEvent>,
    power: u32,
}

/// Pump thread: register interest, attach to this thread's runloop,
/// signal readiness, then run forever.
#[cfg(target_os = "macos")]
fn pump(ctx: *mut CallbackCtx, ready: std::sync::mpsc::Sender<bool>) {
    use std::ffi::c_void;
    // SAFETY: straight-line FFI; every pointer is checked before use
    // and the refcon outlives this thread by design (never reclaimed).
    unsafe {
        let mut port = ffi::IONotificationPortCreate(0);
        if port.is_null() {
            eprintln!("[runner] power watcher disabled: notification port failed");
            let _ = ready.send(false);
            return;
        }
        let mut notifier: u32 = 0;
        let status = ffi::IORegisterForSystemPower(
            ctx as *mut c_void,
            &mut port as _,
            power_callback,
            &mut notifier,
        );
        if status != 0 || notifier == 0 {
            eprintln!("[runner] power watcher disabled: power registration failed");
            ffi::IONotificationPortDestroy(port);
            let _ = ready.send(false);
            return;
        }
        let source = ffi::IONotificationPortGetRunLoopSource(port);
        if source.is_null() {
            eprintln!("[runner] power watcher disabled: runloop source failed");
            let _ = ready.send(false);
            return;
        }
        let rl = ffi::CFRunLoopGetCurrent();
        ffi::CFRunLoopAddSource(rl, source, ffi::kCFRunLoopDefaultMode as _);
        let _ = ready.send(true);
        ffi::CFRunLoopRun();
    }
}

/// IOKit power callback: emit, then hold briefly before allowing
/// sleep (wake events just emit).
#[cfg(target_os = "macos")]
extern "C" fn power_callback(
    refcon: *mut std::ffi::c_void,
    _service: u32,
    message: u32,
    argument: *mut std::ffi::c_void,
) {
    // SAFETY: refcon is the live CallbackCtx box from spawn().
    let ctx = unsafe { &*(refcon as *const CallbackCtx) };
    match map_power_message(message) {
        SystemPowerMessage::WillSleep => {
            let _ = ctx.tx.send(crate::power::PowerEvent::PreparingSleep {
                delay_ms: MACOS_SLEEP_DELAY_MS,
            });
            std::thread::sleep(std::time::Duration::from_millis(MACOS_SLEEP_DELAY_MS));
            // SAFETY: live power connect from spawn(); the notification
            // id arrives in the message argument.
            unsafe { ffi::IOAllowPowerChange(ctx.power, argument as isize) };
        }
        SystemPowerMessage::PoweredOn => {
            let _ = ctx.tx.send(crate::power::PowerEvent::Resumed);
        }
        SystemPowerMessage::Other => {}
    }
}

/// Minimal IOKit + CoreFoundation surface for system-power interest.
/// Signatures follow IOKit/IOPMLib.h, IONotificationPort.h, and
/// CoreFoundation/CFRunLoop.h. `IOPMFindPowerManagement` is the
/// single-call root-domain connect (stable ABI since 10.0); the
/// registry-walk alternative would triple this surface for no gain.
#[cfg(target_os = "macos")]
mod ffi {
    use std::ffi::c_void;

    pub const K_IOPM_ASSERTION_LEVEL_ON: u32 = 255;
    pub const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        pub fn IOPMFindPowerManagement(master: u32) -> u32;
        pub fn IOPMAssertionCreateWithName(
            assertion_type: *const c_void,
            level: u32,
            name: *const c_void,
            id: *mut u32,
        ) -> i32;
        pub fn IOPMAssertionRelease(id: u32) -> i32;
        pub static kIOPMAssertionTypePreventUserIdleSystemSleep: *const c_void;
        pub fn IONotificationPortCreate(master: u32) -> *mut c_void;
        pub fn IONotificationPortGetRunLoopSource(port: *mut c_void) -> *mut c_void;
        pub fn IONotificationPortDestroy(port: *mut c_void);
        pub fn IORegisterForSystemPower(
            refcon: *mut c_void,
            port: *mut *mut c_void,
            callback: extern "C" fn(*mut c_void, u32, u32, *mut c_void),
            notifier: *mut u32,
        ) -> i32;
        pub fn IOAllowPowerChange(port: u32, notification: isize) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        pub fn CFRunLoopGetCurrent() -> *mut c_void;
        pub fn CFRunLoopAddSource(rl: *mut c_void, src: *mut c_void, mode: *const c_void);
        pub fn CFRunLoopRun();
        pub static kCFRunLoopDefaultMode: *const c_void;
        pub fn CFStringCreateWithCString(
            alloc: *const c_void,
            bytes: *const i8,
            encoding: u32,
        ) -> *mut c_void;
        pub fn CFRelease(obj: *const c_void);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_messages_classify() {
        assert_eq!(
            map_power_message(K_IO_MESSAGE_SYSTEM_WILL_SLEEP),
            SystemPowerMessage::WillSleep
        );
        assert_eq!(
            map_power_message(K_IO_MESSAGE_SYSTEM_HAS_POWERED_ON),
            SystemPowerMessage::PoweredOn
        );
        assert_eq!(map_power_message(0), SystemPowerMessage::Other);
        assert_eq!(map_power_message(0xe000_0271), SystemPowerMessage::Other);
    }

    // Full lifecycle against live power management (macOS runners
    // only; the Linux suite covers the shared contract instead).
    #[cfg(target_os = "macos")]
    #[test]
    fn wake_lock_acquires_and_releases() {
        let guard = WakeLockGuard::acquire().expect("power assertion");
        drop(guard);
        let guard = WakeLockGuard::acquire().expect("re-acquire after release");
        drop(guard);
    }
}
