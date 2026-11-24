//! File-backed credential stores (tokens never logged or echoed).
//!
//! [`TokenStore`] keeps provider tokens in the `0600`
//! `~/.config/runner/env` secrets file (never in shareable
//! `runner.toml`); the daemon auto-loads that file on every
//! (re)start, so `runner auth` followed by `systemctl --user
//! restart runner` rotates credentials with no unit editing.
//!
//! [`AuthStore`] keeps one device-flow login in `~/.runner/auth.json`
//! (also `0600`, owner-only DACL on Windows), written atomically so
//! a failed save can never clobber working credentials.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::config::{
    default_env_path, BITBUCKET_CLIENT_ID_ENV, BITBUCKET_CLIENT_SECRET_ENV, GITHUB_TOKEN_ENV,
    GITLAB_TOKEN_ENV,
};

/// Credential slot for one provider's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSlot {
    Github,
    Gitlab,
    BitbucketClientId,
    BitbucketClientSecret,
}

impl ProviderSlot {
    /// Environment variable carrying this provider's token.
    pub fn env_var(&self) -> &'static str {
        match self {
            Self::Github => GITHUB_TOKEN_ENV,
            Self::Gitlab => GITLAB_TOKEN_ENV,
            Self::BitbucketClientId => BITBUCKET_CLIENT_ID_ENV,
            Self::BitbucketClientSecret => BITBUCKET_CLIENT_SECRET_ENV,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::BitbucketClientId => "bitbucket-client-id",
            Self::BitbucketClientSecret => "bitbucket-client-secret",
        }
    }
}

/// Insert or replace one `KEY=value` line, preserving comments, blanks,
/// ordering, and all other entries. Values are written bare (the env
/// parser also accepts quotes, which are never generated here).
pub fn upsert_env_var(text: &str, key: &str, value: &str) -> String {
    let mut out = Vec::new();
    let mut replaced = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_target = !trimmed.starts_with('#')
            && trimmed
                .strip_prefix("export ")
                .or_else(|| trimmed.strip_prefix("export\t"))
                .unwrap_or(trimmed)
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == key);
        if is_target && !replaced {
            out.push(format!("{key}={value}"));
            replaced = true;
        } else if is_target {
            // Drop stale duplicates so exactly one entry survives.
        } else {
            out.push(line.to_string());
        }
    }
    if !replaced {
        out.push(format!("{key}={value}"));
    }
    let mut rendered = out.join("\n");
    rendered.push('\n');
    rendered
}

/// Mask a secret for display: keep the scheme prefix through the
/// first `_` or `-` (`ghp_`, `glpat-`, `bb_`), else the first two
/// characters, then bullets. The full value never appears in output.
pub fn mask_token(token: &str) -> String {
    let token = token.trim();
    if token.len() < 5 {
        return "••••••".to_string();
    }
    let prefix_len = token
        .find(['_', '-'])
        .map(|i| i + 1)
        .filter(|&n| n >= 3)
        .unwrap_or_else(|| token.chars().take(2).map(char::len_utf8).sum());
    format!("{}••••••", &token[..prefix_len])
}

/// Token store backed by one env file.
#[derive(Debug, Clone)]
pub struct TokenStore {
    path: PathBuf,
}

impl TokenStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default store (`~/.config/runner/env`).
    pub fn default_store() -> Option<Self> {
        default_env_path().map(Self::new)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write or update a provider token, creating parents as needed and
    /// forcing `0600` permissions (owner-only DACL on Windows).
    /// Returns the store path.
    pub fn set_token(&self, slot: ProviderSlot, token: &str) -> std::io::Result<PathBuf> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let current = std::fs::read_to_string(&self.path).unwrap_or_default();
        std::fs::write(
            &self.path,
            upsert_env_var(&current, slot.env_var(), token.trim()),
        )?;
        #[cfg(unix)]
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        #[cfg(windows)]
        crate::winacl::restrict_to_owner(&self.path)?;
        Ok(self.path.clone())
    }

    /// Whether a non-empty token is stored (value never exposed).
    pub fn has_token(&self, slot: ProviderSlot) -> bool {
        self.masked_token(slot).is_some()
    }

    /// Masked token for `auth status` display (`ghp_••••••`), or None
    /// when the slot is empty. The full value never leaves this call.
    pub fn masked_token(&self, slot: ProviderSlot) -> Option<String> {
        let text = std::fs::read_to_string(&self.path).ok()?;
        crate::config::parse_env_file(&text)
            .iter()
            .find(|(k, v)| k == slot.env_var() && !v.trim().is_empty())
            .map(|(_, v)| mask_token(v))
    }
}

/// Default device-login store path (`~/.runner/auth.json`).
pub fn default_auth_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".runner").join("auth.json"))
}

/// One device-flow login: forge identity plus the bearer token. The
/// token value is never logged, echoed, or included in `Debug`
/// output anywhere in this codebase.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceCredential {
    pub forge: String,
    /// Storage key: forge host authority (`github.com`,
    /// `git.example.com:8443`), lowercased. Defaults empty so Phase
    /// 1 files (no host field) still parse for migration.
    #[serde(default)]
    pub host: String,
    pub username: String,
    pub scopes: Vec<String>,
    pub access_token: String,
}

impl std::fmt::Debug for DeviceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredential")
            .field("forge", &self.forge)
            .field("host", &self.host)
            .field("username", &self.username)
            .field("scopes", &self.scopes)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// Device-login store backed by one JSON file mapping forge host
/// to credential (`{ "github.com": {...}, "git.example.com": ...
/// }`). Saves are atomic (unique temp file plus rename) and private
/// from creation (`0600` at open on Unix, owner-only DACL on
/// Windows), so a failed or concurrent save can never expose or
/// clobber working credentials. Phase 1 single-credential files
/// migrate on first read (see [`load_all`](Self::load_all)).
#[derive(Debug, Clone)]
pub struct AuthStore {
    path: PathBuf,
}

/// Storage key for a legacy single credential: its own host when
/// present, else the well-known host for its forge name.
fn legacy_host_key(credential: &DeviceCredential) -> String {
    if !credential.host.trim().is_empty() {
        return credential.host.clone();
    }
    match credential.forge.trim().to_ascii_lowercase().as_str() {
        "github" => "github.com".to_string(),
        "gitlab" => "gitlab.com".to_string(),
        other => other.to_string(),
    }
}

/// Raw store read: absent files seed fresh maps, while I/O
/// failures and undecodable bytes are distinct errors (writers
/// fail closed on both; readers treat both as signed-out).
enum StoreRead {
    Missing,
    Bytes(Vec<u8>),
    Unreadable(String),
}

/// Lock acquisition budget: 50ms polls, ~2s total, then a loud
/// timeout (the critical section is milliseconds; anything longer
/// is a wedged peer, never silent waiting).
const LOCK_RETRIES: u32 = 40;
const LOCK_RETRY_WAIT: std::time::Duration = std::time::Duration::from_millis(50);

/// Cross-process exclusive lock guarding store read-modify-write.
/// Unix holds a POSIX `flock`; Windows holds the lock file open
/// with zero sharing. Both release on process death, so a crashed
/// login can never wedge later ones.
struct StoreLock {
    _held: std::fs::File,
}

impl StoreLock {
    fn acquire(lock_path: &Path) -> std::io::Result<Self> {
        for _ in 0..LOCK_RETRIES {
            match Self::try_acquire(lock_path) {
                Ok(file) => return Ok(Self { _held: file }),
                Err(None) => std::thread::sleep(LOCK_RETRY_WAIT),
                Err(Some(e)) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "another login is saving credentials; please retry",
        ))
    }

    /// Attempt once: `Ok` on acquisition, `None` when a peer holds
    /// it (retry), `Some(err)` on fatal errors.
    #[cfg(unix)]
    fn try_acquire(lock_path: &Path) -> Result<std::fs::File, Option<std::io::Error>> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path)
            .map_err(Some)?;
        // SAFETY: flock on a live fd; return code checked.
        let rc = unsafe {
            libc::flock(
                std::os::unix::io::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        if rc == 0 {
            return Ok(file);
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(None);
        }
        Err(Some(e))
    }

    #[cfg(not(unix))]
    fn try_acquire(lock_path: &Path) -> Result<std::fs::File, Option<std::io::Error>> {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(lock_path)
        {
            Ok(file) => Ok(file),
            // ERROR_SHARING_VIOLATION: a peer holds the lock.
            Err(e) if e.raw_os_error() == Some(32) => Err(None),
            Err(e) => Err(Some(e)),
        }
    }
}

impl AuthStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Default store (`~/.runner/auth.json`, `None` without a home).
    pub fn default_store() -> Option<Self> {
        default_auth_path().map(Self::new)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_store(&self) -> StoreRead {
        match std::fs::read(&self.path) {
            Ok(bytes) => StoreRead::Bytes(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreRead::Missing,
            Err(e) => StoreRead::Unreadable(e.to_string()),
        }
    }

    /// Parse store bytes: the keyed shape, else a legacy single
    /// credential re-keyed by host (with the host field populated so
    /// round-trips stay canonical). The flag reports migrations so
    /// readers persist the upgrade exactly once.
    fn parse_store_bytes(
        bytes: &[u8],
    ) -> Result<(std::collections::HashMap<String, DeviceCredential>, bool), String> {
        if let Ok(map) =
            serde_json::from_slice::<std::collections::HashMap<String, DeviceCredential>>(bytes)
        {
            return Ok((map, false));
        }
        let mut legacy = serde_json::from_slice::<DeviceCredential>(bytes)
            .map_err(|_| "credentials file is not valid JSON".to_string())?;
        legacy.host = legacy_host_key(&legacy);
        let mut map = std::collections::HashMap::new();
        map.insert(legacy.host.clone(), legacy);
        Ok((map, true))
    }

    fn lock_path(&self) -> PathBuf {
        self.path.with_extension("lock")
    }

    /// Read the host map leniently: missing or corrupt files read
    /// empty (signed-out); legacy files migrate and persist the
    /// upgrade best-effort (under the mutation lock, re-verified so
    /// a concurrent migrator wins exactly once).
    fn load_map(&self) -> std::collections::HashMap<String, DeviceCredential> {
        let bytes = match self.read_store() {
            StoreRead::Missing => return std::collections::HashMap::new(),
            StoreRead::Bytes(bytes) => bytes,
            StoreRead::Unreadable(_) => return std::collections::HashMap::new(),
        };
        match Self::parse_store_bytes(&bytes) {
            Ok((map, migrated)) => {
                if migrated {
                    // Best-effort persist: re-check under the lock so
                    // concurrent migrators don't interleave.
                    if let Ok(_guard) = StoreLock::acquire(&self.lock_path()) {
                        let still_legacy = matches!(self.read_store(), StoreRead::Bytes(current) if current == bytes);
                        if still_legacy {
                            let _ = self.write_map(&map);
                        }
                    }
                }
                map
            }
            Err(_) => std::collections::HashMap::new(),
        }
    }

    /// Persist one forge credential, preserving every other forge.
    /// The whole read-modify-write holds the cross-process lock, so
    /// concurrent logins serialize instead of clobbering; unreadable
    /// stores fail closed instead of wiping unknown bytes.
    pub fn save(&self, credential: &DeviceCredential) -> std::io::Result<()> {
        if credential.host.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "credential has no forge host key",
            ));
        }
        // The lock file lives beside the store: ensure the parent
        // first so acquisition itself never fails on fresh homes.
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _guard = StoreLock::acquire(&self.lock_path())?;
        let mut map = match self.read_store() {
            StoreRead::Missing => std::collections::HashMap::new(),
            StoreRead::Bytes(bytes) => Self::parse_store_bytes(&bytes)
                .map(|(map, _)| map)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            StoreRead::Unreadable(e) => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }
        };
        map.insert(credential.host.clone(), credential.clone());
        let bytes = Self::encode_map(&map)?;
        self.write_bytes(&bytes)
    }

    /// Credentials for one host (`None` when that forge is signed out).
    pub fn load_forge(&self, host: &str) -> Option<DeviceCredential> {
        self.load_map().remove(host)
    }

    /// All stored credentials, sorted by host for stable display.
    pub fn load_all(&self) -> Vec<(String, DeviceCredential)> {
        let mut entries: Vec<_> = self.load_map().into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    fn encode_map(
        map: &std::collections::HashMap<String, DeviceCredential>,
    ) -> std::io::Result<Vec<u8>> {
        serde_json::to_vec_pretty(map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn write_map(
        &self,
        map: &std::collections::HashMap<String, DeviceCredential>,
    ) -> std::io::Result<()> {
        let bytes = Self::encode_map(map)?;
        self.write_bytes(&bytes)
    }

    /// Atomic private write of pre-encoded bytes (unique temp plus
    /// rename, scrubbed on failure).
    fn write_bytes(&self, bytes: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Unique temp sibling (pid + nanos): concurrent savers never
        // share a staging file, and a crash leaves only orphans.
        let tmp = self.path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let result = (|| -> std::io::Result<()> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)?;
                use std::io::Write;
                file.write_all(bytes)?;
                file.sync_all()?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&tmp, bytes)?;
                crate::winacl::restrict_to_owner(&tmp)?;
            }
            std::fs::rename(&tmp, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Delete one forge entry, preserving the rest (`Ok(true)`
    /// when an entry was removed). An emptied file is deleted so the
    /// store never lingers as `{}`. Unreadable files are unlinked
    /// outright: logout revokes unknown secrets rather than leaving
    /// them behind.
    pub fn clear_forge(&self, host: &str) -> std::io::Result<bool> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _guard = StoreLock::acquire(&self.lock_path())?;
        let mut map = match self.read_store() {
            StoreRead::Missing => return Ok(false),
            StoreRead::Bytes(bytes) => match Self::parse_store_bytes(&bytes) {
                Ok((map, _)) => map,
                Err(_) => return self.unlink_locked(),
            },
            StoreRead::Unreadable(_) => return self.unlink_locked(),
        };
        if map.remove(host).is_none() {
            return Ok(false);
        }
        if map.is_empty() {
            return self.unlink_locked();
        }
        self.write_map(&map)?;
        Ok(true)
    }

    /// Delete all stored credentials (`Ok(true)` when a file was
    /// removed, `Ok(false)` when already signed out). Serialized
    /// with savers so logout and login compose coherently.
    pub fn clear(&self) -> std::io::Result<bool> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _guard = StoreLock::acquire(&self.lock_path())?;
        self.unlink_locked()
    }

    /// Unlink the store file; callers hold the lock.
    fn unlink_locked(&self) -> std::io::Result<bool> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_preserves_comments_and_replaces_in_place() {
        let before = "# runner env\nRUNNER_GITHUB_TOKEN=old\nOTHER=1\n";
        let after = upsert_env_var(before, "RUNNER_GITHUB_TOKEN", "new");
        assert_eq!(after, "# runner env\nRUNNER_GITHUB_TOKEN=new\nOTHER=1\n");
    }

    #[test]
    fn upsert_appends_and_dedupes() {
        assert_eq!(upsert_env_var("", "A", "1"), "A=1\n");
        let dupes = "A=1\nB=x\nA=2\n";
        assert_eq!(upsert_env_var(dupes, "A", "3"), "A=3\nB=x\n");
        // export-prefixed and quoted forms still match the key.
        let exported = "export A=\"1\"\n";
        assert_eq!(upsert_env_var(exported, "A", "2"), "A=2\n");
        assert_eq!(
            upsert_env_var("# only a comment\n", "A", "1"),
            "# only a comment\nA=1\n"
        );
    }

    #[test]
    fn store_round_trip_is_private() {
        let dir = crate::test_support::TempDir::new("auth").unwrap();
        let store = TokenStore::new(dir.path().join("env"));
        assert!(!store.has_token(ProviderSlot::Github));
        let path = store.set_token(ProviderSlot::Github, "ghp_secret").unwrap();
        assert_eq!(path, store.path());
        assert!(store.has_token(ProviderSlot::Github));
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Windows proves the same privacy via DACL, not modes.
        #[cfg(windows)]
        {
            use crate::winacl::{read_dacl_sids, DaclTarget};
            assert_eq!(read_dacl_sids(DaclTarget::File(&path)).unwrap().len(), 2);
        }
        // Rotation replaces without duplicating.
        store.set_token(ProviderSlot::Github, "ghp_next").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("RUNNER_GITHUB_TOKEN=").count(), 1);
        assert!(text.contains("ghp_next"));
    }

    #[test]
    fn multiforge_slots_round_trip() {
        let dir = crate::test_support::TempDir::new("auth-multi").unwrap();
        let store = TokenStore::new(dir.path().join("env"));
        store.set_token(ProviderSlot::Gitlab, "glpat_x").unwrap();
        store
            .set_token(ProviderSlot::BitbucketClientId, "bb-id")
            .unwrap();
        store
            .set_token(ProviderSlot::BitbucketClientSecret, "bb-secret")
            .unwrap();
        assert!(store.has_token(ProviderSlot::Gitlab));
        assert!(store.has_token(ProviderSlot::BitbucketClientId));
        assert!(store.has_token(ProviderSlot::BitbucketClientSecret));
        assert!(!store.has_token(ProviderSlot::Github));
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(text.contains("RUNNER_GITLAB_TOKEN=glpat_x"));
        assert!(text.contains("RUNNER_BITBUCKET_CLIENT_ID=bb-id"));
        assert!(text.contains("RUNNER_BITBUCKET_CLIENT_SECRET=bb-secret"));
    }

    #[test]
    fn masking_keeps_scheme_prefix_only() {
        assert_eq!(mask_token("ghp_deadbeef1234"), "ghp_••••••");
        assert_eq!(mask_token("glpat-xyz789"), "glpat-••••••");
        assert_eq!(mask_token("bb_secretvalue"), "bb_••••••");
        // Opaque secrets fall back to two leading characters.
        assert_eq!(mask_token("AbCdEfGh"), "Ab••••••");
        // Short or blank values reveal nothing at all.
        assert_eq!(mask_token("ab"), "••••••");
        assert_eq!(mask_token(""), "••••••");
        // Full values never survive masking.
        for secret in ["ghp_deadbeef1234", "glpat-xyz789", "bb_secretvalue"] {
            assert!(!mask_token(secret).contains(&secret[4..]));
        }
    }

    #[test]
    fn masked_token_reads_store_without_exposing_values() {
        let dir = crate::test_support::TempDir::new("auth-masked").unwrap();
        let store = TokenStore::new(dir.path().join("env"));
        assert_eq!(store.masked_token(ProviderSlot::Github), None);
        store
            .set_token(ProviderSlot::Github, "ghp_livevalue")
            .unwrap();
        assert_eq!(
            store.masked_token(ProviderSlot::Github).as_deref(),
            Some("ghp_••••••")
        );
        // has_token keeps its contract through the shared reader.
        assert!(store.has_token(ProviderSlot::Github));
        assert!(!store.has_token(ProviderSlot::Gitlab));
    }

    fn credential() -> DeviceCredential {
        DeviceCredential {
            forge: "github".to_string(),
            host: "github.com".to_string(),
            username: "octocat".to_string(),
            scopes: vec!["repo".to_string()],
            access_token: "[REDACTED]".to_string(),
        }
    }

    fn gitlab_credential() -> DeviceCredential {
        DeviceCredential {
            forge: "gitlab".to_string(),
            host: "git.example.com".to_string(),
            username: "dev".to_string(),
            scopes: vec!["api".to_string()],
            access_token: "glpat-secret".to_string(),
        }
    }

    #[test]
    fn device_credential_debug_redacts_token() {
        let rendered = format!("{:?}", credential());
        assert!(!rendered.contains("gho_secret"), "{rendered}");
        assert!(rendered.contains("octocat"), "{rendered}");
    }

    #[test]
    fn auth_store_roundtrips_and_clears_idempotently() {
        let dir = crate::test_support::TempDir::new("auth-json").unwrap();
        let store = AuthStore::new(dir.path().join("auth.json"));
        assert_eq!(store.load_forge("github.com"), None);
        assert!(store.load_all().is_empty());
        store.save(&credential()).unwrap();
        assert_eq!(store.load_forge("github.com"), Some(credential()));
        assert!(store.clear().unwrap());
        assert_eq!(store.load_forge("github.com"), None);
        assert!(!store.clear().unwrap());
    }

    #[test]
    fn auth_store_survives_corruption_as_signed_out() {
        let dir = crate::test_support::TempDir::new("auth-corrupt").unwrap();
        let path = dir.path().join("auth.json");
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(&path, "{not json").unwrap();
        let store = AuthStore::new(path);
        assert_eq!(store.load_forge("github.com"), None);
        assert!(store.load_all().is_empty());
    }

    #[test]
    fn auth_store_failed_save_never_clobbers() {
        let dir = crate::test_support::TempDir::new("auth-noclobber").unwrap();
        let store = AuthStore::new(dir.path().join("auth.json"));
        store.save(&credential()).unwrap();
        // Early failure (unmakable parent): the error surfaces and
        // the working credentials are bit-identical afterwards.
        let blocker = dir.path().join("sub");
        std::fs::create_dir_all(&blocker).unwrap();
        std::fs::write(blocker.join("auth.json"), b"junk").unwrap();
        let dead = AuthStore::new(blocker.join("auth.json").join("nested.json"));
        assert!(dead.save(&credential()).is_err());
        assert_eq!(store.load_forge("github.com"), Some(credential()));
        // Late failure (rename onto a directory): the staging temp
        // is scrubbed, leaving no litter behind.
        let clash = dir.path().join("clash");
        std::fs::create_dir_all(clash.join("auth.json")).unwrap();
        let stuck = AuthStore::new(clash.join("auth.json"));
        assert!(stuck.save(&credential()).is_err());
        assert_eq!(
            std::fs::read_dir(&clash)
                .unwrap()
                .filter_map(|entry| entry.ok().map(|e| e.file_name()))
                .filter(|name| name.to_string_lossy().contains("tmp-"))
                .count(),
            0
        );
    }

    #[test]
    fn auth_store_isolates_forges_without_cross_clobber() {
        let dir = crate::test_support::TempDir::new("auth-multi").unwrap();
        let store = AuthStore::new(dir.path().join("auth.json"));
        store.save(&credential()).unwrap();
        // Second forge lands alongside; the first is untouched.
        store.save(&gitlab_credential()).unwrap();
        assert_eq!(store.load_forge("github.com"), Some(credential()));
        assert_eq!(
            store.load_forge("git.example.com"),
            Some(gitlab_credential())
        );
        let hosts: Vec<String> = store.load_all().into_iter().map(|(host, _)| host).collect();
        assert_eq!(hosts, vec!["git.example.com", "github.com"]);
        // Per-forge clear preserves the survivor; last one out
        // deletes the file instead of lingering as `{}`.
        assert!(store.clear_forge("git.example.com").unwrap());
        assert!(!store.clear_forge("git.example.com").unwrap());
        assert_eq!(store.load_forge("github.com"), Some(credential()));
        assert!(store.clear_forge("github.com").unwrap());
        assert!(!dir.path().join("auth.json").exists());
    }

    #[test]
    fn auth_store_concurrent_saves_lose_nothing() {
        let dir = crate::test_support::TempDir::new("auth-race").unwrap();
        let path = dir.path().join("auth.json");
        // Eight writers hammering distinct hosts: optimistic retry
        // merges every interleaving instead of last-write-wins.
        std::thread::scope(|scope| {
            for t in 0..8u32 {
                let path = path.clone();
                scope.spawn(move || {
                    let store = AuthStore::new(path);
                    for i in 0..25u32 {
                        let mut creds = credential();
                        creds.host = format!("h{t}.example.com");
                        creds.username = format!("u{t}-{i}");
                        store.save(&creds).unwrap();
                    }
                });
            }
        });
        let store = AuthStore::new(path);
        assert_eq!(store.load_all().len(), 8);
        for t in 0..8u32 {
            assert!(store.load_forge(&format!("h{t}.example.com")).is_some());
        }
    }

    #[test]
    fn auth_store_save_onto_corrupt_fails_without_wiping() {
        let dir = crate::test_support::TempDir::new("auth-corrupt-save").unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, "{not json").unwrap();
        let store = AuthStore::new(path.clone());
        let err = store.save(&credential()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // Unknown bytes survive untouched for forensics/recovery.
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    }

    #[test]
    fn clear_forge_on_unreadable_unlinks_without_reading() {
        let dir = crate::test_support::TempDir::new("auth-clear-corrupt").unwrap();
        let path = dir.path().join("auth.json");
        std::fs::write(&path, "{junk").unwrap();
        let store = AuthStore::new(path.clone());
        // Logout revokes unknown secrets instead of stranding them.
        assert!(store.clear_forge("github.com").unwrap());
        assert!(!path.exists());
        assert!(!store.clear_forge("github.com").unwrap());
    }

    #[test]
    fn auth_store_migrates_legacy_single_token() {
        let dir = crate::test_support::TempDir::new("auth-migrate").unwrap();
        let path = dir.path().join("auth.json");
        // Phase 1 shape: one bare credential, no host field.
        std::fs::write(
            &path,
            serde_json::json!({
                "forge": "github",
                "username": "octocat",
                "scopes": ["repo"],
                "access_token": "[REDACTED]",
            })
            .to_string(),
        )
        .unwrap();
        let store = AuthStore::new(path.clone());
        let migrated = store.load_forge("github.com").unwrap();
        assert_eq!(migrated.username, "octocat");
        assert_eq!(migrated.access_token, "[REDACTED]");
        // The migrated record carries its canonical host, so a
        // re-save lands on the same key instead of forking a "" one.
        assert_eq!(migrated.host, "github.com");
        store.save(&migrated).unwrap();
        assert_eq!(store.load_all().len(), 1);
        // Migration persists: the file is now the keyed shape.
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(raw.get("github.com").is_some(), "{raw}");
    }

    #[cfg(unix)]
    #[test]
    fn auth_store_file_is_owner_only() {
        let dir = crate::test_support::TempDir::new("auth-mode").unwrap();
        let path = dir.path().join("auth.json");
        AuthStore::new(path.clone()).save(&credential()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode is {mode:o}");
    }
}
