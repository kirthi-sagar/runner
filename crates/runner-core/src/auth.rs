//! Provider credential management: tokens live in the `0600`
//! `~/.config/runner/env` secrets file (never in shareable `runner.toml`).
//! The daemon auto-loads that file on every (re)start, so `runner auth`
//! followed by `systemctl --user restart runner` rotates credentials with
//! no unit editing. Token values are never logged or echoed.

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
    /// forcing `0600` permissions. Returns the store path.
    pub fn set_token(&self, slot: ProviderSlot, token: &str) -> std::io::Result<PathBuf> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let current = std::fs::read_to_string(&self.path).unwrap_or_default();
        std::fs::write(
            &self.path,
            upsert_env_var(&current, slot.env_var(), token.trim()),
        )?;
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        Ok(self.path.clone())
    }

    /// Whether a non-empty token is stored (value never exposed).
    pub fn has_token(&self, slot: ProviderSlot) -> bool {
        std::fs::read_to_string(&self.path)
            .map(|text| {
                crate::config::parse_env_file(&text)
                    .iter()
                    .any(|(k, v)| k == slot.env_var() && !v.trim().is_empty())
            })
            .unwrap_or(false)
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
}
