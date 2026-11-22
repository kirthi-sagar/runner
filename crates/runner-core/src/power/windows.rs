//! Windows power backend: suspend/resume notifications plus lid
//! state, delivered to a hidden message-only window pumping on a
//! dedicated thread (console daemons have no window of their own).

/// `WM_POWERBROADCAST` and friends, mirrored locally (plain `u32`)
///
/// so the mapper below unit-tests on every platform; the
/// `consts_match_windows_sys` test pins them against the vendored
/// values on Windows builds.
pub const WM_POWERBROADCAST: u32 = 536;
pub const PBT_APMSUSPEND: u32 = 4;
pub const PBT_APMRESUMEAUTOMATIC: u32 = 18;
pub const PBT_POWERSETTINGCHANGE: u32 = 32787;

/// Grace window behind `PreparingSleep`: window-message suspend
/// notifications carry no hold mechanism (legacy query-suspend vetoes
/// are ignored on modern Windows), so delivery is notify-only.
pub const WINDOWS_SLEEP_DELAY_MS: u64 = 0;

/// Pure `WM_POWERBROADCAST` wparam map (setting-change payloads are
/// decoded separately once the caller confirms the lid GUID).
pub fn map_wparam(wparam: u32) -> Option<crate::power::PowerEvent> {
    match wparam {
        PBT_APMSUSPEND => Some(crate::power::PowerEvent::PreparingSleep {
            delay_ms: WINDOWS_SLEEP_DELAY_MS,
        }),
        PBT_APMRESUMEAUTOMATIC => Some(crate::power::PowerEvent::Resumed),
        _ => None,
    }
}

/// Pure lid-state byte map: the `PBT_POWERSETTINGCHANGE` payload for
/// `GUID_LIDSWITCH_STATE_CHANGE` carries 0 for closed, nonzero for
/// open (verify on a physical lid if this ever misbehaves).
pub fn map_lid_byte(closed_byte: u8) -> crate::power::PowerEvent {
    if closed_byte == 0 {
        crate::power::PowerEvent::LidClosed
    } else {
        crate::power::PowerEvent::LidOpened
    }
}

/// Spawn the pump thread; `false` (with a loud note) when window
/// creation or registration fails. Rendezvous-bounded so boot never
/// blocks on a broken backend.
/// Process-wide pump channel: set once by `spawn`, read by the
/// window proc. Single-watcher assumption holds (the daemon starts
/// one pump; a second start would reuse the first channel).
#[cfg(windows)]
static TX: std::sync::OnceLock<tokio::sync::broadcast::Sender<crate::power::PowerEvent>> =
    std::sync::OnceLock::new();

#[cfg(windows)]
pub fn spawn(tx: tokio::sync::broadcast::Sender<crate::power::PowerEvent>) -> bool {
    let _ = TX.set(tx);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
    let pump = std::thread::Builder::new()
        .name("runner-power-pump".to_string())
        .spawn(move || pump(ready_tx));
    if pump.is_err() {
        eprintln!("[runner] power watcher disabled: pump thread failed");
        return false;
    }
    ready_rx.recv_timeout(std::time::Duration::from_secs(1)) == Ok(true)
}

/// Pump thread: hidden window, both registrations, then the message
/// loop for process lifetime. Handles intentionally leak: nothing
/// ever unregisters (mirrors the macOS runloop ownership).
#[cfg(windows)]
fn pump(ready: std::sync::mpsc::Sender<bool>) {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::Power::{
        RegisterPowerSettingNotification, RegisterSuspendResumeNotification,
    };
    use windows_sys::Win32::System::SystemServices::GUID_LIDSWITCH_STATE_CHANGE;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DispatchMessageW, GetMessageW, RegisterClassExW,
        DEVICE_NOTIFY_WINDOW_HANDLE, HWND_MESSAGE, WNDCLASSEXW,
    };

    // SAFETY: straight-line Win32 setup; every handle checked before
    // use; the class name outlives registration (leaked statics).
    unsafe {
        let class: Vec<u16> = "RunnerPower\0".encode_utf16().collect();
        let instance = GetModuleHandleW(std::ptr::null());
        let mut cls: WNDCLASSEXW = std::mem::zeroed();
        cls.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        cls.lpfnWndProc = Some(wndproc);
        cls.hInstance = instance;
        cls.lpszClassName = class.as_ptr();
        if RegisterClassExW(&cls) == 0 {
            eprintln!("[runner] power watcher disabled: window class failed");
            let _ = ready.send(false);
            return;
        }
        let title: Vec<u16> = "RunnerPower\0".encode_utf16().collect();
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        // `class`/`title` must outlive CreateWindowExW (copied in).
        std::hint::black_box((&class, &title));
        if hwnd.is_null() {
            eprintln!("[runner] power watcher disabled: window creation failed");
            let _ = ready.send(false);
            return;
        }
        let lid = RegisterPowerSettingNotification(
            hwnd as _,
            &GUID_LIDSWITCH_STATE_CHANGE,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        );
        let suspend = RegisterSuspendResumeNotification(hwnd as _, DEVICE_NOTIFY_WINDOW_HANDLE);
        if lid == 0 || suspend == 0 {
            eprintln!("[runner] power watcher disabled: registration failed");
            let _ = ready.send(false);
            return;
        }
        let _ = ready.send(true);
        let mut message: windows_sys::Win32::UI::WindowsAndMessaging::MSG = std::mem::zeroed();
        while GetMessageW(&mut message, std::ptr::null_mut(), 0, 0) > 0 {
            DispatchMessageW(&message);
        }
    }
}

/// Hidden-window proc: route power messages, default the rest.
#[cfg(windows)]
extern "system" fn wndproc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows_sys::Win32::Foundation::WPARAM,
    lparam: windows_sys::Win32::Foundation::LPARAM,
) -> windows_sys::Win32::Foundation::LRESULT {
    dispatch_window_message(msg, wparam, lparam);
    // Handled power messages return TRUE; everything else falls
    // through to default processing.
    if msg == WM_POWERBROADCAST {
        return 1;
    }
    // SAFETY: valid window + message; default processing.
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

/// Window-message dispatch shared by the pump proc. Separated so the
/// routing (GUID check, payload bounds) stays readable beside the FFI.
#[cfg(windows)]
fn dispatch_window_message(msg: u32, wparam: usize, lparam: isize) {
    use windows_sys::Win32::System::Power::POWERBROADCAST_SETTING;
    use windows_sys::Win32::System::SystemServices::GUID_LIDSWITCH_STATE_CHANGE;

    if msg != WM_POWERBROADCAST {
        return;
    }
    let event = if wparam as u32 == PBT_POWERSETTINGCHANGE {
        // SAFETY: lparam is a live POWERBROADCAST_SETTING for setting
        // notifications; DataLength bounds the payload read.
        let setting = unsafe { &*(lparam as *const POWERBROADCAST_SETTING) };
        if !guid_eq(&setting.PowerSetting, &GUID_LIDSWITCH_STATE_CHANGE) || setting.DataLength < 1 {
            return;
        }
        map_lid_byte(setting.Data[0])
    } else {
        match map_wparam(wparam as u32) {
            Some(event) => event,
            None => return,
        }
    };
    let _ = tx().send(event);
}

/// Pump channel accessor. `spawn` always sets this before the pump
/// can deliver; a missing channel degrades to a dummy rather than
/// panicking in wndproc.
#[cfg(windows)]
fn tx() -> tokio::sync::broadcast::Sender<crate::power::PowerEvent> {
    TX.get_or_init(|| tokio::sync::broadcast::channel(16).0)
        .clone()
}

/// GUID equality (windows-sys `GUID` has no `PartialEq`).
#[cfg(windows)]
fn guid_eq(a: &windows_sys::core::GUID, b: &windows_sys::core::GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wparam_maps_suspend_resume_only() {
        use crate::power::PowerEvent;
        assert_eq!(
            map_wparam(PBT_APMSUSPEND),
            Some(PowerEvent::PreparingSleep {
                delay_ms: WINDOWS_SLEEP_DELAY_MS
            })
        );
        assert_eq!(
            map_wparam(PBT_APMRESUMEAUTOMATIC),
            Some(PowerEvent::Resumed)
        );
        assert_eq!(map_wparam(PBT_POWERSETTINGCHANGE), None);
        assert_eq!(map_wparam(0), None);
    }

    #[test]
    fn lid_byte_maps_closed_open() {
        use crate::power::PowerEvent;
        assert_eq!(map_lid_byte(0), PowerEvent::LidClosed);
        assert_eq!(map_lid_byte(1), PowerEvent::LidOpened);
    }

    // Pin the mirrored constants against the vendored values so the
    // ungated mapper above can never drift from Win32.
    #[cfg(windows)]
    #[test]
    fn consts_match_windows_sys() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            PBT_APMRESUMEAUTOMATIC as SYS_RESUME, PBT_APMSUSPEND as SYS_SUSPEND,
            PBT_POWERSETTINGCHANGE as SYS_SETTING, WM_POWERBROADCAST as SYS_BROADCAST,
        };
        assert_eq!(WM_POWERBROADCAST, SYS_BROADCAST);
        assert_eq!(PBT_APMSUSPEND, SYS_SUSPEND);
        assert_eq!(PBT_APMRESUMEAUTOMATIC, SYS_RESUME);
        assert_eq!(PBT_POWERSETTINGCHANGE, SYS_SETTING);
    }
}
