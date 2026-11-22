//! `#[cfg(windows)]` mappings from the portable contract to real WFP
//! constants, plus the application-id resolver. Pure value mappings
//! and one RAII FFI wrapper — engine calls live in [`super::engine`].
//!
//! NOTE: this module only compiles on Windows (see the `cfg` gate on
//! the `mod api` declaration in `mod.rs`).

use std::io;
use std::ptr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

use super::types::{WfpAction, WfpLayer};

/// ALE authorize layer GUID for a portable [`WfpLayer`].
pub fn layer_guid(layer: WfpLayer) -> GUID {
    match layer {
        WfpLayer::AleAuthConnectV4 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WfpLayer::AleAuthConnectV6 => wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}

/// Session flags for the sandbox egress session: dynamic only,
/// so the kernel reaps every filter if the runner dies.
pub fn session_flags() -> u32 {
    wfp::FWPM_SESSION_FLAG_DYNAMIC
}

/// WFP action code for a portable [`WfpAction`].
pub fn action_type(action: WfpAction) -> wfp::FWP_ACTION_TYPE {
    match action {
        WfpAction::Block => wfp::FWP_ACTION_BLOCK,
        WfpAction::Permit => wfp::FWP_ACTION_PERMIT,
    }
}

/// ALE application-identity condition field
/// (`FWPM_CONDITION_ALE_APP_ID`): matches the connecting process's
/// own image only — see the [`WfpAppId`](super::types::WfpAppId)
/// semantic boundary note.
pub fn app_id_condition() -> GUID {
    wfp::FWPM_CONDITION_ALE_APP_ID
}

/// Nul-terminated UTF-16 buffer (mirrors `winacl` string handling).
pub(crate) fn wide_string(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// RAII-resolved WFP application-id blob: resolves an executable
/// path via `FwpmGetAppIdFromFileName0` and releases it with
/// `FwpmFreeMemory0` on drop, so install errors never leak.
pub struct AppIdBlob {
    blob: *mut wfp::FWP_BYTE_BLOB,
}

impl AppIdBlob {
    /// Resolve `path` to its app-id blob.
    pub fn resolve(path: &str) -> io::Result<Self> {
        let wide = wide_string(path);
        let mut blob: *mut wfp::FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: nul-terminated input; `blob` is a valid out-pointer.
        let code = unsafe { wfp::FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        if blob.is_null() {
            return Err(io::Error::other(
                "FwpmGetAppIdFromFileName0 succeeded with a null blob",
            ));
        }
        Ok(AppIdBlob { blob })
    }

    /// Borrow the resolved blob. Valid until drop; callers keep
    /// `self` alive across the `FwpmFilterAdd0` call.
    pub fn as_blob(&self) -> &wfp::FWP_BYTE_BLOB {
        // SAFETY: non-null from a successful resolve, freed only in Drop.
        unsafe { &*self.blob }
    }

    /// Raw pointer for the `byteBlob` condition union arm.
    pub fn as_mut_ptr(&mut self) -> *mut wfp::FWP_BYTE_BLOB {
        self.blob
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        // SAFETY: exactly-once free of a resolver-owned blob; the API
        // nulls the out-pointer (ignored — never touched again).
        let mut raw = self.blob.cast::<core::ffi::c_void>();
        unsafe {
            wfp::FwpmFreeMemory0(&mut raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_cover_both_layers_and_actions() {
        // GUID has no PartialEq; compare the leading fields.
        let v4 = layer_guid(WfpLayer::AleAuthConnectV4);
        let v6 = layer_guid(WfpLayer::AleAuthConnectV6);
        assert_ne!(v4.data1, 0);
        assert_ne!(v6.data1, 0);
        assert_ne!(v4.data1, v6.data1);
        assert_eq!(session_flags(), wfp::FWPM_SESSION_FLAG_DYNAMIC);
        assert_eq!(action_type(WfpAction::Block), wfp::FWP_ACTION_BLOCK);
        assert_eq!(action_type(WfpAction::Permit), wfp::FWP_ACTION_PERMIT);
        assert_ne!(app_id_condition().data1, 0);
        assert_ne!(app_id_condition().data1, v4.data1);
    }

    /// Live resolver check: the test binary's own image resolves to a
    /// non-empty blob and frees cleanly on drop. Requires
    /// `RUNNER_LIVE_WFP=1` like the other live engine tests.
    #[test]
    fn live_app_id_resolve_roundtrip() {
        if std::env::var("RUNNER_LIVE_WFP").is_err() {
            eprintln!("live app-id harness skipped (needs RUNNER_LIVE_WFP=1)");
            return;
        }
        let exe = std::env::current_exe().expect("own exe path");
        let path = exe.to_str().expect("utf-8 exe path");
        let blob = AppIdBlob::resolve(path).expect("resolve own app id");
        assert!(blob.as_blob().size > 0);
    }
}
