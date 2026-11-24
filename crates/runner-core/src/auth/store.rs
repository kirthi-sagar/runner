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
    pub username: String,
    pub scopes: Vec<String>,
    pub access_token: String,
}

impl std::fmt::Debug for DeviceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredential")
            .field("forge", &self.forge)
            .field("username", &self.username)
            .field("scopes", &self.scopes)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// Device-login store backed by one JSON file. Saves are atomic
/// (unique temp file plus rename) and private from creation
/// (`0600` at open on Unix, owner-only DACL on Windows), so a
/// failed or concurrent save can never expose or clobber working
/// credentials.
#[derive(Debug, Clone)]
pub struct AuthStore {
    path: PathBuf,
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

    /// Persist credentials atomically. Missing or corrupt files read
    /// back as signed-out (see [`load`](Self::load)).
    pub fn save(&self, credential: &DeviceCredential) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(credential)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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
                file.write_all(&bytes)?;
                file.sync_all()?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&tmp, &bytes)?;
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

    /// Load credentials (`None` when missing or corrupt — the caller
    /// reports signed-out either way).
    pub fn load(&self) -> Option<DeviceCredential> {
        let bytes = std::fs::read(&self.path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Delete stored credentials (`Ok(true)` when a file was
    /// removed, `Ok(false)` when already signed out).
    pub fn clear(&self) -> std::io::Result<bool> {
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
            username: "octocat".to_string(),
            scopes: vec!["repo".to_string()],
            access_token: "[REDACTED]".to_string(),
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
        assert_eq!(store.load(), None);
        store.save(&credential()).unwrap();
        assert_eq!(store.load(), Some(credential()));
        assert!(store.clear().unwrap());
        assert_eq!(store.load(), None);
        assert!(!store.clear().unwrap());
    }

    #[test]
    fn auth_store_survives_corruption_as_signed_out() {
        let dir = crate::test_support::TempDir::new("auth-corrupt").unwrap();
        let path = dir.path().join("auth.json");
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(AuthStore::new(path).load(), None);
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
        assert_eq!(store.load(), Some(credential()));
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
