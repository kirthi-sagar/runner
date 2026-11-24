//! `runner auth` device-flow surface: browser opener, status
//! rendering, and login orchestration separate from clap plumbing
//! (pure cores for tests; only the exec loop touches the network).

use runner_core::auth::store::DeviceCredential;

/// Browser opener per host platform: program plus fixed leading
/// args (the URL appends last). `cmd start` needs an empty title
/// slot or it eats the URL.
pub fn browser_command() -> (&'static str, &'static [&'static str]) {
    #[cfg(target_os = "macos")]
    {
        ("open", &[])
    }
    #[cfg(target_os = "windows")]
    {
        ("cmd", &["/C", "start", ""])
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        ("xdg-open", &[])
    }
}

/// Best-effort browser launch (callers fall back to printing the
/// URL when this fails — headless hosts, missing opener).
pub fn open_browser(url: &str) -> std::io::Result<()> {
    let (program, prefix) = browser_command();
    let status = std::process::Command::new(program)
        .args(prefix)
        .arg(url)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "browser opener exited with {status}"
        )))
    }
}

/// Device-login status line: identity plus granted scopes, or the
/// signed-out pointer. The token value never renders.
pub fn render_device_status(credential: Option<&DeviceCredential>) -> String {
    match credential {
        Some(creds) => {
            let scopes = if creds.scopes.is_empty() {
                "no scopes granted".to_string()
            } else {
                creds.scopes.join(", ")
            };
            format!(
                "signed in as {} ({}; scopes: {})\n",
                creds.username, creds.forge, scopes
            )
        }
        None => "not signed in (run `runner auth login`)\n".to_string(),
    }
}

/// Validate the login forge argument (Phase 1 ships GitHub only).
pub fn normalize_forge(forge: &str) -> Result<String, String> {
    let name = forge.trim().to_ascii_lowercase();
    if name == "github" {
        Ok(name)
    } else if name.is_empty() {
        Err("forge must not be empty".to_string())
    } else {
        Err(format!(
            "only github device login is supported in this release (got '{forge}')"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_command_targets_host_opener() {
        let (program, prefix) = browser_command();
        #[cfg(target_os = "macos")]
        assert_eq!((program, prefix), ("open", &[] as &[&str]));
        #[cfg(target_os = "windows")]
        assert_eq!((program, prefix), ("cmd", &["/C", "start", ""] as &[&str]));
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        assert_eq!((program, prefix), ("xdg-open", &[] as &[&str]));
        // Every branch takes the URL as a trailing argument.
        assert!(!program.is_empty());
    }

    #[test]
    fn status_renders_identity_and_masks_nothing_else() {
        let signed_in = render_device_status(Some(&DeviceCredential {
            forge: "github".to_string(),
            username: "octocat".to_string(),
            scopes: vec!["repo".to_string(), "read:user".to_string()],
            access_token: "[REDACTED]".to_string(),
        }));
        assert!(signed_in.contains("octocat"), "{signed_in}");
        assert!(signed_in.contains("github"), "{signed_in}");
        assert!(signed_in.contains("repo, read:user"), "{signed_in}");
        assert!(!signed_in.contains("gho_secret"), "{signed_in}");
        let bare = render_device_status(Some(&DeviceCredential {
            forge: "github".to_string(),
            username: "octocat".to_string(),
            scopes: vec![],
            access_token: "t".to_string(),
        }));
        assert!(bare.contains("no scopes granted"), "{bare}");
        assert!(render_device_status(None).contains("not signed in"));
    }

    #[test]
    fn forge_normalizes_github_only() {
        assert_eq!(normalize_forge("github").unwrap(), "github");
        assert_eq!(normalize_forge("  GitHub ").unwrap(), "github");
        assert!(normalize_forge("gitlab").is_err());
        assert!(normalize_forge("").is_err());
    }
}
