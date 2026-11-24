//! `runner auth` device-flow surface: browser opener, status
//! rendering, and login orchestration separate from clap plumbing
//! (pure cores for tests; only the exec loop touches the network).

use runner_core::auth::store::DeviceCredential;

/// Browser opener per host platform (non-Windows): program plus
/// fixed leading args (the URL appends last). Windows launches via
/// `ShellExecuteW` instead of a child process (see below), so no
/// shell ever parses the URL there.
#[cfg(not(target_os = "windows"))]
pub fn browser_command() -> (&'static str, &'static [&'static str]) {
    if cfg!(target_os = "macos") {
        ("open", &[])
    } else {
        ("xdg-open", &[])
    }
}

/// Characters that must never appear in a forge-supplied URL.
/// No shell exists in any opener transport (unix `execvp` argv,
/// Windows `ShellExecuteW`), so shell metacharacters (`&`, `%`, `|`
/// …) are inert — and real OAuth URLs need `&` query separators
/// and `%` escapes. Only characters that are never valid raw in a
/// URL fail closed: quotes, backslashes, and whitespace.
const URL_FORBIDDEN: [char; 3] = ['"', '\'', '\\'];

/// Validate a forge-supplied URL before handing it to the OS
/// opener: strict `http(s)` shape, non-empty host, and no quotes,
/// backslashes, or whitespace (injection defense now rests on the
/// shell-free transports; this gate keeps malformed URLs out with
/// a clear error). Tab/newline control characters fail closed
/// alongside spaces.
pub fn validate_browser_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| format!("verification URL is not http(s): '{url}'"))?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err(format!("verification URL has no host: '{url}'"));
    }
    if url
        .chars()
        .any(|c| c.is_whitespace() || URL_FORBIDDEN.contains(&c))
    {
        return Err("verification URL contains forbidden characters".to_string());
    }
    Ok(())
}

/// Best-effort browser launch (callers fall back to printing the
/// URL when this fails — headless hosts, missing opener). The URL
/// is validated first so a hostile forge response can never become
/// command execution.
pub fn open_browser(url: &str) -> std::io::Result<()> {
    validate_browser_url(url).map_err(std::io::Error::other)?;
    #[cfg(target_os = "windows")]
    {
        open_browser_windows(url)
    }
    #[cfg(not(target_os = "windows"))]
    {
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
}

/// Windows browser launch without `cmd.exe`: `ShellExecuteW` hands
/// the URL straight to the registered handler, so no shell ever
/// re-parses it (defense in depth behind `validate_browser_url`).
#[cfg(target_os = "windows")]
fn open_browser_windows(url: &str) -> std::io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

    let url_w: Vec<u16> = OsStr::new(url)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: Vec<u16> = OsStr::new("open")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both pointers reference live NUL-terminated UTF-16
    // buffers; remaining args are null/default per ShellExecute docs.
    // A return above 32 signals success; at or below is an error.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb_w.as_ptr(),
            url_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOW,
        )
    };
    if (result as usize) > 32 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "ShellExecute failed with code {}",
            result as usize
        )))
    }
}

/// Multi-forge status table, one line per connected host (entries
/// arrive host-sorted from the store). Token values never render.
pub fn render_multi_status(entries: &[(String, DeviceCredential)]) -> String {
    if entries.is_empty() {
        return "not signed in (run `runner auth login`)\n".to_string();
    }
    let mut out = if entries.len() == 1 {
        "signed in (1 forge):\n".to_string()
    } else {
        format!("signed in ({} forges):\n", entries.len())
    };
    for (host, creds) in entries {
        let scopes = if creds.scopes.is_empty() {
            "no scopes granted".to_string()
        } else {
            creds.scopes.join(", ")
        };
        out.push_str(&format!(
            "  {host}: {} (scopes: {scopes})\n",
            creds.username
        ));
    }
    out
}

/// Validate the login forge argument (github and gitlab only).
pub fn normalize_forge(forge: &str) -> Result<String, String> {
    let name = forge.trim().to_ascii_lowercase();
    if name == "github" || name == "gitlab" {
        Ok(name)
    } else if name.is_empty() {
        Err("forge must not be empty".to_string())
    } else {
        Err(format!(
            "only github and gitlab device login are supported (got '{forge}')"
        ))
    }
}

/// Split a store key (or logout argument) at its sub-path:
/// `git.corp.com/Team-A` → (`git.corp.com`, `/Team-A`); bare hosts
/// carry an empty path.
fn split_key(key: &str) -> (&str, &str) {
    match key.find('/') {
        Some(i) => (&key[..i], &key[i..]),
        None => (key, ""),
    }
}

/// Resolve a logout target against connected forges: an exact host
/// wins outright; otherwise a forge name must match exactly one
/// entry (ambiguous names list their hosts; unknown names fail
/// closed). Host matching is case-insensitive but sub-paths compare
/// byte-exact; the returned host keeps store casing.
pub fn resolve_logout_target<'a>(
    entries: &'a [(String, DeviceCredential)],
    arg: &str,
) -> Result<&'a str, String> {
    // Hosts fold case; sub-paths are byte-exact (`Team-A` and
    // `team-a` are distinct tenants on one domain).
    let want = arg.trim();
    let (want_host, want_path) = split_key(want);
    if let Some((host, _)) = entries.iter().find(|(host, _)| {
        let (host_part, path_part) = split_key(host);
        host_part.eq_ignore_ascii_case(want_host) && path_part == want_path
    }) {
        return Ok(host);
    }
    let want_lower = want.to_ascii_lowercase();
    let named: Vec<&str> = entries
        .iter()
        .filter(|(_, creds)| creds.forge.to_ascii_lowercase() == want_lower)
        .map(|(host, _)| host.as_str())
        .collect();
    match named.as_slice() {
        [host] => Ok(host),
        [] => Err(format!("not signed in to '{arg}'")),
        hosts => Err(format!(
            "multiple '{arg}' logins; specify one of: {}",
            hosts.join(", ")
        )),
    }
}

/// Map a registry host to the forge store key holding its device
/// credential: well-known pairs first (`ghcr.io`→`github.com`,
/// `registry.gitlab.com`→`gitlab.com`), else the registry host
/// itself — a colocated self-hosted forge answers under its own
/// name (the default GitLab registry port `:5050` strips so
/// `gitlab.company.com:5050` resolves to its forge login; the
/// store's port fallback absorbs explicit `:443`/`:80`, and a miss
/// simply means anonymous). Returns `None` for registries with no
/// device flow: Docker Hub stays anonymous.
pub fn registry_forge_key(registry: &str) -> Option<String> {
    let host = registry.trim();
    let bare = host
        .strip_suffix(":443")
        .or_else(|| host.strip_suffix(":80"))
        .unwrap_or(host)
        .to_ascii_lowercase();
    match bare.as_str() {
        "ghcr.io" => Some("github.com".to_string()),
        "registry.gitlab.com" => Some("gitlab.com".to_string()),
        "registry-1.docker.io" | "docker.io" => None,
        _ => Some(
            host.strip_suffix(":5050")
                .unwrap_or(host)
                .to_ascii_lowercase(),
        ),
    }
}

/// Sign out everywhere: unconditionally unlinks the store — even
/// corrupt or unreadable blobs — so secrets are guaranteed gone.
/// Returns the user message.
pub fn logout_all(store: &runner_core::auth::store::AuthStore) -> Result<String, String> {
    let count = store.load_all().len();
    let existed = store.path().exists();
    store
        .clear()
        .map_err(|e| format!("cannot clear credentials: {e}"))?;
    Ok(match (existed, count) {
        (false, _) => "not signed in".to_string(),
        (true, 0) | (true, 1) => "signed out".to_string(),
        (true, n) => format!("signed out of {n} forges"),
    })
}

/// Sign out of one target (host or forge name), preserving the rest.
/// Returns the user message.
pub fn logout_one(
    store: &runner_core::auth::store::AuthStore,
    target: &str,
) -> Result<String, String> {
    let entries = store.load_all();
    let host = resolve_logout_target(&entries, target)?;
    store
        .clear_forge(host)
        .map_err(|e| format!("cannot clear credentials: {e}"))?;
    Ok(format!("signed out of {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Windows launches via ShellExecuteW (no child process), so
    // there is no command shape to pin there.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn browser_command_targets_host_opener() {
        let (program, prefix) = browser_command();
        if cfg!(target_os = "macos") {
            assert_eq!((program, prefix), ("open", &[] as &[&str]));
        } else {
            assert_eq!((program, prefix), ("xdg-open", &[] as &[&str]));
        }
        // Every branch takes the URL as a trailing argument.
        assert!(!program.is_empty());
    }

    fn entry(host: &str, forge: &str) -> (String, DeviceCredential) {
        (
            host.to_string(),
            DeviceCredential {
                forge: forge.to_string(),
                host: host.to_string(),
                username: format!("user-of-{forge}"),
                scopes: vec!["repo".to_string()],
                access_token: "[REDACTED]".to_string(),
            },
        )
    }

    #[test]
    fn status_renders_every_forge_and_never_tokens() {
        let entries = vec![
            entry("git.example.com", "gitlab"),
            entry("github.com", "github"),
        ];
        let text = render_multi_status(&entries);
        assert!(text.contains("signed in (2 forges)"), "{text}");
        assert!(text.contains("git.example.com: user-of-gitlab"), "{text}");
        assert!(text.contains("github.com: user-of-github"), "{text}");
        assert!(!text.contains("gho_secret"), "{text}");
        let solo = render_multi_status(&entries[..1]);
        assert!(solo.contains("signed in (1 forge)"), "{solo}");
        let bare = render_multi_status(&[(
            "github.com".to_string(),
            DeviceCredential {
                forge: "github".to_string(),
                host: "github.com".to_string(),
                username: "octocat".to_string(),
                scopes: vec![],
                access_token: "t".to_string(),
            },
        )]);
        assert!(bare.contains("no scopes granted"), "{bare}");
        assert!(render_multi_status(&[]).contains("not signed in"));
    }

    #[test]
    fn browser_urls_reject_commands_and_accept_forges() {
        for ok in [
            "https://github.com/login/device",
            "https://git.example.com/oauth/authorize?x=1",
            // Real device-verification shape: query separators and
            // percent-escapes must open (shell-free transports make
            // them inert).
            "https://gitlab.example.com/activate?flow=device&client_id=123",
            "https://h/callback?code=a%20b&state=x%2Fy",
            "http://127.0.0.1:9/activate",
        ] {
            assert!(validate_browser_url(ok).is_ok(), "{ok}");
        }
        // Only never-valid-raw characters fail closed now (the
        // shell-free transports neutralize the rest).
        for evil in [
            "https://h/\"x\"",
            "https://h/x'y",
            "https://h/x\\y",
            "https://h/x y",
            "https://h/x\ty",
            "https://h/x\ny",
            "calc.exe",
            "",
            "https://",
            "file:///etc/passwd",
            "ftp://h/x",
        ] {
            assert!(validate_browser_url(evil).is_err(), "{evil:?}");
        }
        // The opener itself enforces validation (never spawns junk).
        assert!(open_browser("https://h/x y").is_err());
    }

    #[test]
    fn forge_normalizes_github_and_gitlab() {
        assert_eq!(normalize_forge("github").unwrap(), "github");
        assert_eq!(normalize_forge("  GitLab ").unwrap(), "gitlab");
        assert!(normalize_forge("bitbucket").is_err());
        assert!(normalize_forge("").is_err());
    }

    #[test]
    fn logout_all_unlinks_even_corrupt_stores() {
        use runner_core::auth::store::AuthStore;

        let dir = runner_core::test_support::TempDir::new("auth-logout-all").unwrap();
        let store = AuthStore::new(dir.path().join("auth.json"));
        assert_eq!(logout_all(&store).unwrap(), "not signed in");
        store
            .save(&DeviceCredential {
                forge: "github".to_string(),
                host: "github.com".to_string(),
                username: "octocat".to_string(),
                scopes: vec![],
                access_token: "t".to_string(),
            })
            .unwrap();
        assert_eq!(logout_all(&store).unwrap(), "signed out");
        assert!(!dir.path().join("auth.json").exists());
        // Corrupt blobs unlink too (secrets guaranteed gone).
        std::fs::write(dir.path().join("auth.json"), "{junk").unwrap();
        assert_eq!(logout_all(&store).unwrap(), "signed out");
        assert!(!dir.path().join("auth.json").exists());
    }

    #[test]
    fn logout_one_revokes_single_forge() {
        use runner_core::auth::store::AuthStore;

        let dir = runner_core::test_support::TempDir::new("auth-logout-one").unwrap();
        let store = AuthStore::new(dir.path().join("auth.json"));
        for (host, forge) in [("github.com", "github"), ("git.example.com", "gitlab")] {
            store
                .save(&DeviceCredential {
                    forge: forge.to_string(),
                    host: host.to_string(),
                    username: "u".to_string(),
                    scopes: vec![],
                    access_token: "t".to_string(),
                })
                .unwrap();
        }
        assert_eq!(
            logout_one(&store, "git.example.com").unwrap(),
            "signed out of git.example.com"
        );
        assert!(store.load_forge("github.com").is_some());
        assert!(logout_one(&store, "gitea").is_err());
    }

    #[test]
    fn logout_target_prefers_host_then_unique_forge() {
        let entries = vec![
            entry("git.example.com", "gitlab"),
            entry("github.com", "github"),
            entry("gitlab.com", "gitlab"),
        ];
        // Exact host wins even when the forge name is ambiguous.
        assert_eq!(
            resolve_logout_target(&entries, "gitlab.com").unwrap(),
            "gitlab.com"
        );
        assert_eq!(
            resolve_logout_target(&entries, "GIT.EXAMPLE.COM").unwrap(),
            "git.example.com"
        );
        // Unique forge name resolves to its host.
        assert_eq!(
            resolve_logout_target(&entries, "github").unwrap(),
            "github.com"
        );
        // Ambiguous forge names list their hosts.
        let err = resolve_logout_target(&entries, "gitlab").unwrap_err();
        assert!(err.contains("git.example.com"), "{err}");
        assert!(err.contains("gitlab.com"), "{err}");
        // Unknown names fail closed.
        assert!(resolve_logout_target(&entries, "gitea").is_err());
    }

    #[test]
    fn logout_target_folds_host_case_but_not_path_case() {
        let entries = vec![
            entry("git.corp.com/Team-A", "gitlab"),
            entry("git.corp.com/team-b", "gitlab"),
        ];
        // Host case folds; the path must match byte-exact.
        assert_eq!(
            resolve_logout_target(&entries, "GIT.CORP.COM/Team-A").unwrap(),
            "git.corp.com/Team-A"
        );
        assert_eq!(
            resolve_logout_target(&entries, "git.corp.com/team-b").unwrap(),
            "git.corp.com/team-b"
        );
        // Wrong path case is a different tenant: no match.
        assert!(resolve_logout_target(&entries, "git.corp.com/team-a").is_err());
        // Bare host matches neither sub-path entry.
        assert!(resolve_logout_target(&entries, "git.corp.com").is_err());
    }

    #[test]
    fn registry_forge_key_maps_known_and_colocated() {
        assert_eq!(registry_forge_key("ghcr.io").as_deref(), Some("github.com"));
        assert_eq!(
            registry_forge_key("GHCR.IO:443").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            registry_forge_key("registry.gitlab.com").as_deref(),
            Some("gitlab.com")
        );
        // Docker Hub has no device flow: anonymous.
        assert_eq!(registry_forge_key("registry-1.docker.io"), None);
        assert_eq!(registry_forge_key("docker.io"), None);
        // Colocated self-hosted forges answer under their own name
        // (explicit ports preserved for the store lookup, except the
        // default GitLab registry port).
        assert_eq!(
            registry_forge_key("registry.corp.com:5050").as_deref(),
            Some("registry.corp.com")
        );
        assert_eq!(
            registry_forge_key("Registry.Corp.Com").as_deref(),
            Some("registry.corp.com")
        );
        // Default GitLab registry port strips to the forge login.
        assert_eq!(
            registry_forge_key("gitlab.company.com:5050").as_deref(),
            Some("gitlab.company.com")
        );
        // Other explicit ports still pass through for the store.
        assert_eq!(
            registry_forge_key("gitlab.company.com:5443").as_deref(),
            Some("gitlab.company.com:5443")
        );
    }
}
