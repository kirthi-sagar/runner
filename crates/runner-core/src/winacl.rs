//! Windows owner-only DACLs: the `0600` equivalent for secret files
//! and the IPC named pipe (Windows-only; unix uses POSIX modes).
//!
//! Both entry points grant full control to exactly two trustees — the
//! current user and SYSTEM — behind a protected (non-inheriting)
//! DACL, so parent-directory grants cannot leak in.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, GENERIC_ALL};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SE_OBJECT_TYPE, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP,
};
#[cfg(test)]
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetLengthSid, ACCESS_ALLOWED_ACE,
    ACL_SIZE_INFORMATION,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetTokenInformation, IsValidSid, TokenUser, WinLocalSystemSid, ACL,
    DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// DACL target for [`read_dacl_sids`].
#[cfg(test)]
pub(crate) enum DaclTarget<'a> {
    File(&'a Path),
    Pipe(&'a str),
}

/// Restrict a secret file to owner + SYSTEM (0600 equivalent).
/// Fails closed: any error leaves the caller's write in place but
/// reports the missing protection.
pub(crate) fn restrict_to_owner(path: &Path) -> io::Result<()> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    apply_owner_system_dacl(&wide, SE_FILE_OBJECT)
}

/// Restrict a named pipe (`\\.\pipe\...`) to owner + SYSTEM.
/// Applied synchronously at bind; the pipe's DACL then covers every
/// instance the accept loop creates.
pub(crate) fn restrict_pipe_dacl(pipe_name: &str) -> io::Result<()> {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    // Named pipes live in NPFS, so the security APIs classify them
    // as file objects; SE_KERNEL_OBJECT rejects the backslashes
    // with ERROR_BAD_PATHNAME (161).
    apply_owner_system_dacl(&wide, SE_FILE_OBJECT)
}

/// Read back the trustee SIDs on a DACL (raw SID bytes per ACE, in
/// order). Used by tests to prove the restriction landed.
#[cfg(test)]
pub(crate) fn read_dacl_sids(target: DaclTarget) -> io::Result<Vec<Vec<u8>>> {
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;

    let (wide, obj_type) = match target {
        DaclTarget::File(path) => (
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>(),
            SE_FILE_OBJECT,
        ),
        DaclTarget::Pipe(name) => (
            name.encode_utf16().chain(std::iter::once(0)).collect(),
            SE_FILE_OBJECT,
        ),
    };
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = std::ptr::null_mut();
    // SAFETY: valid name + out-words; the descriptor is freed below.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            obj_type,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: freed exactly once on every path below.
    struct SdGuard(*mut std::ffi::c_void);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: pointer came from GetNamedSecurityInfoW.
                unsafe { LocalFree(self.0) };
            }
        }
    }
    let _sd = SdGuard(sd);
    if dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "object has no DACL",
        ));
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: live ACL plus a valid info out-struct.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sids = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live ACL, in-range index, valid out-word.
        let ok = unsafe { GetAce(dacl, index, &mut ace) };
        if ok == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // Every ACE our builder emits is an ACCESS_ALLOWED_ACE
        // whose SidStart word is the SID's first four bytes.
        let allowed = ace as *const ACCESS_ALLOWED_ACE;
        // SAFETY: GetAce hands back a live ACE header.
        let sid = unsafe { &(*allowed).SidStart as *const u32 as PSID };
        sids.push(sid_bytes(sid, "DACL holds an invalid SID")?);
    }
    Ok(sids)
}

/// Copy a SID's bytes, validating first. The caller guarantees the
/// SID outlives the copy (ACL buffers, token/system stores).
#[cfg(test)]
fn sid_bytes(sid: PSID, what: &str) -> io::Result<Vec<u8>> {
    // SAFETY: caller-held SID.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, what));
    }
    // SAFETY: same live SID.
    let len = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: GetLengthSid bounds the bytes.
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, len) }.to_vec())
}

/// Build the owner + SYSTEM DACL and stamp it on one named object.
/// The DACL is protected: inherited parent grants do not apply.
fn apply_owner_system_dacl(name: &[u16], obj_type: SE_OBJECT_TYPE) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{SetEntriesInAclW, SetNamedSecurityInfoW};

    let token = current_user_token()?;
    let user_buf = TokenUserBuf::query(&token)?;
    let system_buf = SystemSid::create()?;
    // Buffers outlive the SetEntriesInAclW call below by scope.
    let user = user_buf.sid();
    let system = system_buf.sid();
    // SAFETY: both SIDs point into buffers alive for this call.
    if unsafe { IsValidSid(user) } == 0 || unsafe { IsValidSid(system) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "refusing to build a DACL over an invalid SID",
        ));
    }
    let mut entries: [EXPLICIT_ACCESS_W; 2] = unsafe { std::mem::zeroed() };
    fill_grant(&mut entries[0], user, TRUSTEE_IS_USER);
    fill_grant(&mut entries[1], system, TRUSTEE_IS_WELL_KNOWN_GROUP);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: two valid entries in, one LocalAlloc ACL out.
    let code = unsafe { SetEntriesInAclW(2, entries.as_ptr(), std::ptr::null(), &mut dacl) };
    if code != ERROR_SUCCESS || dacl.is_null() {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    // SAFETY: freed exactly once below.
    struct DaclGuard(*mut ACL);
    impl Drop for DaclGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: pointer came from SetEntriesInAclW.
                unsafe { LocalFree(self.0 as _) };
            }
        }
    }
    let _dacl = DaclGuard(dacl);
    // SAFETY: nul-terminated name, live DACL, null owner/group/SACL
    // (DACL-only stamp; ownership untouched).
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            obj_type,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

fn fill_grant(
    entry: &mut EXPLICIT_ACCESS_W,
    sid: PSID,
    kind: windows_sys::Win32::Security::Authorization::TRUSTEE_TYPE,
) {
    entry.grfAccessPermissions = GENERIC_ALL;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.grfInheritance = NO_INHERITANCE;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = kind;
    entry.Trustee.ptstrName = sid as _;
}

/// Process token with query rights (closed on drop).
struct OwnedToken {
    handle: std::os::windows::io::OwnedHandle,
}

fn current_user_token() -> io::Result<OwnedToken> {
    use std::os::windows::io::FromRawHandle;
    let mut token = std::ptr::null_mut();
    // SAFETY: pseudo-handle needs no close; out-word is valid.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 || token.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ownership moves into OwnedHandle exactly once.
    Ok(OwnedToken {
        handle: unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(token) },
    })
}

/// Token-user buffer. The SID points inside the owned bytes and is
/// re-derived per call, so no stored pointer can dangle.
struct TokenUserBuf(Vec<u8>);

impl TokenUserBuf {
    fn query(token: &OwnedToken) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        let handle = token.handle.as_raw_handle();
        let mut len = 0u32;
        // SAFETY: size probe; the expected failure sets len.
        unsafe { GetTokenInformation(handle as _, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: live token, valid buffer sized by the probe.
        let ok = unsafe {
            GetTokenInformation(handle as _, TokenUser, buf.as_mut_ptr() as _, len, &mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buf))
    }

    fn sid(&self) -> PSID {
        // SAFETY: the buffer holds exactly the TOKEN_USER the
        // successful query above wrote.
        unsafe { (*(self.0.as_ptr() as *const TOKEN_USER)).User.Sid }
    }
}

/// Well-known SYSTEM SID with its backing store.
struct SystemSid([u8; SECURITY_MAX_SID_SIZE as usize]);

impl SystemSid {
    fn create() -> io::Result<Self> {
        let mut buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = buf.len() as u32;
        // SAFETY: valid buffer sized for any SID.
        let ok = unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as PSID,
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buf))
    }

    fn sid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected trustee set: current user + SYSTEM, as SID bytes.
    fn expected_trustees() -> Vec<Vec<u8>> {
        let token = current_user_token().expect("process token");
        let user = TokenUserBuf::query(&token).expect("user sid");
        let system = SystemSid::create().expect("system sid");
        let mut set = vec![
            sid_bytes(user.sid(), "user sid").expect("user bytes"),
            sid_bytes(system.sid(), "system sid").expect("system bytes"),
        ];
        set.sort();
        set
    }

    fn sorted(mut sids: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        sids.sort();
        sids
    }

    // A restricted file carries exactly user + SYSTEM, stays usable
    // by us (no self-lockout), and re-restricting is idempotent.
    #[test]
    fn file_dacl_is_owner_and_system_only() {
        let dir = crate::test_support::TempDir::new("winacl-file").unwrap();
        let path = dir.path().join("secret.env");
        std::fs::write(&path, "RUNNER_GITHUB_TOKEN=x").unwrap();
        restrict_to_owner(&path).expect("restrict file");
        let got = read_dacl_sids(DaclTarget::File(&path)).expect("read file dacl");
        assert_eq!(sorted(got), expected_trustees());
        // Still ours to use afterwards.
        std::fs::write(&path, "RUNNER_GITHUB_TOKEN=y").unwrap();
        restrict_to_owner(&path).expect("re-restrict is idempotent");
        let got = read_dacl_sids(DaclTarget::File(&path)).expect("read file dacl");
        assert_eq!(sorted(got), expected_trustees());
    }

    // Binding a pipe stamps the same DACL: production bind() calls
    // restrict_pipe_dacl, so this pins the wiring too.
    #[tokio::test]
    async fn pipe_dacl_is_owner_and_system_only() {
        use crate::governor::supervisor::new_shared_state;
        use crate::ipc::{pipe_name_for, IpcServer};

        let dir = crate::test_support::TempDir::new("winacl-pipe").unwrap();
        let sock = dir.path().join("dacl.sock");
        let server = std::sync::Arc::new(IpcServer::bind(&sock, new_shared_state()).await.unwrap());
        let task = tokio::spawn(async move { server.serve().await });
        // Reading the DACL opens the pipe, which needs a listening
        // instance: retry while serve() is still starting (same
        // ERROR_PIPE_BUSY shape as the IPC client).
        use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
        let mut got = None;
        for _ in 0..100 {
            match read_dacl_sids(DaclTarget::Pipe(&pipe_name_for(&sock))) {
                Ok(sids) => {
                    got = Some(sids);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("read pipe dacl: {e}"),
            }
        }
        assert_eq!(
            sorted(got.expect("pipe became readable")),
            expected_trustees()
        );
        task.abort();
    }
}
