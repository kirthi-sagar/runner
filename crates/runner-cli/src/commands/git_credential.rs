//! `runner auth git-credential`: native git credential helper.
//! Pure request/response cores (tested here); only the thin
//! stdin/stdout loop in `main.rs` touches I/O. Protocol per
//! `gitcredentials(7)` / `git-credential(1)`: `key=value` lines to a
//! blank line or EOF.

use runner_core::auth::store::DeviceCredential;
use std::io::BufRead;

/// Parsed helper input block. Only the attributes lookup needs are
/// kept; input usernames never gate the answer (the stored token
/// determines identity).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialRequest {
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
}

/// Drain one credential block from a line reader: lines until the
/// first blank line (finding-literal `trim().is_empty()`) or EOF.
/// Git holds the pipe open waiting for our answer, so reading to EOF
/// unconditionally would deadlock; stopping at the blank line is the
/// protocol. I/O errors end the block early.
pub fn read_credential_block<R: BufRead>(reader: &mut R) -> String {
    let mut block = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.trim().is_empty() {
                    break;
                }
                block.push_str(&line);
            }
            Err(_) => break,
        }
    }
    block
}

/// Parse one helper input block. Malformed lines (no `=`) are
/// skipped; duplicate keys resolve last-wins; parsing stops at the
/// first blank line (a missing terminator reads to EOF).
pub fn parse_credential_request(input: &str) -> CredentialRequest {
    let mut request = CredentialRequest::default();
    for line in input.lines() {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "protocol" => request.protocol = Some(value.to_string()),
            "host" => request.host = Some(value.to_string()),
            "path" => request.path = Some(value.to_string()),
            _ => {}
        }
    }
    request
}

/// Loopback test for credential emission: tokens ride cleartext
/// HTTP only to the loopback device (hermetic tests). Ports strip
/// before comparing; bracketed and bare IPv6 both spell `::1`.
fn host_is_loopback(host: &str) -> bool {
    let bare = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(inner, _)| inner).unwrap_or(host),
        None => host,
    };
    let bare = match bare.rsplit_once(':') {
        Some((h, port)) if !h.contains(':') && !port.is_empty() => h,
        _ => bare,
    };
    bare.eq_ignore_ascii_case("localhost") || bare == "127.0.0.1" || bare == "::1"
}

/// Find the stored credential answering a git request. Tokens never
/// emit over cleartext HTTP except to loopback; tenant sub-path
/// keys (longest match) win over bare-host keys so coexisting
/// tenants are not shadowed; default ports strip scheme-aware
/// (`:443` for https-or-absent, `:80` for http). Unknown protocols
/// and empty hosts miss; a bare-host request never matches a
/// sub-path key (no tenant can be picked).
pub fn git_credential_lookup<'a>(
    entries: &'a [(String, DeviceCredential)],
    request: &CredentialRequest,
) -> Option<&'a DeviceCredential> {
    let scheme = request
        .protocol
        .as_deref()
        .map(|protocol| protocol.to_ascii_lowercase());
    if let Some(scheme) = &scheme {
        if scheme != "http" && scheme != "https" {
            return None;
        }
    }
    let host = request
        .host
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())?;
    let host = host.to_ascii_lowercase();
    if scheme.as_deref() == Some("http") && !host_is_loopback(&host) {
        return None;
    }
    let bare = if scheme.as_deref() == Some("http") {
        host.strip_suffix(":80").unwrap_or(host.as_str())
    } else {
        host.strip_suffix(":443").unwrap_or(host.as_str())
    };
    // Tenant sub-paths first: longest key whose host matches and
    // whose path prefixes the remote path.
    let remote = request
        .path
        .as_deref()
        .unwrap_or("")
        .trim()
        .trim_start_matches('/');
    if let Some((_, credential)) = entries
        .iter()
        .filter_map(|(key, credential)| {
            let (key_host, key_path) = key.split_once('/')?;
            if key_host != host && key_host != bare {
                return None;
            }
            let tenant = key_path.trim_matches('/');
            if tenant.is_empty() {
                return None;
            }
            if remote == tenant || remote.starts_with(&format!("{tenant}/")) {
                Some((key.len(), credential))
            } else {
                None
            }
        })
        .max_by_key(|(len, _)| *len)
    {
        return Some(credential);
    }
    // Exact host keys serve every repo path on that host.
    entries
        .iter()
        .find(|(key, _)| key == &host || key == bare)
        .map(|(_, credential)| credential)
}

/// Render a `get` answer: username + password in credential block
/// format (blank-line terminated, per the git I/O spec). Never emits
/// `quit`: misses answer with nothing at all so git falls through to
/// the next helper.
pub fn render_credential_answer(username: &str, password: &str) -> String {
    format!("username={username}\npassword={password}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, user: &str) -> (String, DeviceCredential) {
        (
            key.to_string(),
            DeviceCredential {
                forge: "gitlab".to_string(),
                host: key.to_string(),
                username: user.to_string(),
                scopes: vec![],
                access_token: format!("token-for-{user}"),
            },
        )
    }

    fn request(host: &str, path: Option<&str>) -> CredentialRequest {
        CredentialRequest {
            protocol: Some("https".to_string()),
            host: Some(host.to_string()),
            path: path.map(str::to_string),
        }
    }

    #[test]
    fn block_reader_stops_at_blank_line_without_eof() {
        // Trailing bytes after the blank line prove the reader never
        // waits for EOF (the git-fill deadlock shape).
        let mut cursor = std::io::Cursor::new(b"host=a.com\n\nSHOULD-NOT-BE-READ\n".as_slice());
        let block = read_credential_block(&mut cursor);
        assert_eq!(block, "host=a.com\n");
        assert_eq!(cursor.position() as usize, "host=a.com\n\n".len());
        // Missing terminator reads to EOF; empty input reads empty.
        let mut cursor = std::io::Cursor::new(b"host=a.com\n".as_slice());
        assert_eq!(read_credential_block(&mut cursor), "host=a.com\n");
        let mut cursor = std::io::Cursor::new(b"".as_slice());
        assert_eq!(read_credential_block(&mut cursor), "");
    }

    #[test]
    fn request_parsing_handles_framing_variants() {
        // Blank-line terminator; trailing attributes ignored.
        let parsed = parse_credential_request(
            "protocol=https\nhost=github.com\npath=a/b\n\nusername=late\n",
        );
        assert_eq!(
            parsed,
            CredentialRequest {
                protocol: Some("https".to_string()),
                host: Some("github.com".to_string()),
                path: Some("a/b".to_string()),
            }
        );
        // Missing terminator reads to EOF.
        let parsed = parse_credential_request("protocol=https\nhost=github.com\n");
        assert_eq!(parsed.host.as_deref(), Some("github.com"));
        assert_eq!(parsed.path, None);
        // Malformed lines skipped, duplicates last-wins, unknowns kept out.
        let parsed = parse_credential_request("junk\n\nhost=a.com\nhost=b.com\npassword=x\n");
        assert_eq!(parsed.host.as_deref(), None);
        let parsed = parse_credential_request("host=a.com\nhost=b.com\n");
        assert_eq!(parsed.host.as_deref(), Some("b.com"));
        assert_eq!(parse_credential_request(""), CredentialRequest::default());
    }

    #[test]
    fn lookup_matches_hosts_and_longest_tenant_prefix() {
        let entries = vec![
            entry("github.com", "octocat"),
            entry("git.corp.com/team-a", "alice"),
            entry("git.corp.com/team-a/nested", "nested"),
        ];
        // Exact host serves every repo path; case folds.
        let found = git_credential_lookup(&entries, &request("GITHUB.COM", Some("o/r"))).unwrap();
        assert_eq!(found.username, "octocat");
        let found = git_credential_lookup(&entries, &request("github.com:443", None)).unwrap();
        assert_eq!(found.username, "octocat");
        // Longest tenant prefix wins.
        let found =
            git_credential_lookup(&entries, &request("git.corp.com", Some("team-a/nested/r")))
                .unwrap();
        assert_eq!(found.username, "nested");
        let found = git_credential_lookup(&entries, &request("git.corp.com", Some("team-a/other")))
            .unwrap();
        assert_eq!(found.username, "alice");
        // Leading slashes tolerated; exact tenant path matches.
        let found =
            git_credential_lookup(&entries, &request("git.corp.com", Some("/team-a"))).unwrap();
        assert_eq!(found.username, "alice");
    }

    #[test]
    fn lookup_misses_unknown_protocols_hosts_and_tenants() {
        let entries = vec![
            entry("github.com", "octocat"),
            entry("git.corp.com/team-a", "alice"),
        ];
        assert!(git_credential_lookup(&entries, &request("evil.com", Some("o/r"))).is_none());
        // Bare host never picks a tenant; tenant typos miss.
        assert!(git_credential_lookup(&entries, &request("git.corp.com", None)).is_none());
        assert!(
            git_credential_lookup(&entries, &request("git.corp.com", Some("team-b/r"))).is_none()
        );
        // Prefix-boundary respected (`team-a2` is not under `team-a`).
        assert!(
            git_credential_lookup(&entries, &request("git.corp.com", Some("team-a2/r"))).is_none()
        );
        // Unknown protocols and empty hosts miss.
        let mut ftp = request("github.com", Some("o/r"));
        ftp.protocol = Some("ftp".to_string());
        assert!(git_credential_lookup(&entries, &ftp).is_none());
        assert!(git_credential_lookup(&entries, &request("", Some("o/r"))).is_none());
        assert!(git_credential_lookup(&entries, &request("   ", None)).is_none());
    }

    fn http_request(host: &str, path: Option<&str>) -> CredentialRequest {
        CredentialRequest {
            protocol: Some("http".to_string()),
            host: Some(host.to_string()),
            path: path.map(str::to_string),
        }
    }

    #[test]
    fn loopback_spellings_cover_names_ports_and_brackets() {
        for loopback in [
            "localhost",
            "LOCALHOST",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:80",
            "[::1]",
            "[::1]:8080",
            "::1",
        ] {
            assert!(host_is_loopback(loopback), "{loopback}");
        }
        // Strictly the loopback device: neighbours and lookalikes fail.
        for remote in [
            "github.com",
            "github.com:80",
            "127.0.0.2",
            "localhost.evil.com",
            "[::2]",
            "",
        ] {
            assert!(!host_is_loopback(remote), "{remote}");
        }
    }

    #[test]
    fn tokens_emit_over_http_only_to_loopback() {
        let entries = vec![entry("github.com", "octocat"), entry("127.0.0.1", "local")];
        // Cleartext to a remote host never answers, even when stored.
        assert!(
            git_credential_lookup(&entries, &http_request("github.com", Some("o/r")),).is_none()
        );
        // Loopback answers (hermetic tests serve plaintext HTTP);
        // non-default ports stay distinct instances, as in the store.
        let found =
            git_credential_lookup(&entries, &http_request("127.0.0.1", Some("o/r"))).unwrap();
        assert_eq!(found.username, "local");
        assert!(
            git_credential_lookup(&entries, &http_request("127.0.0.1:8080", Some("o/r"))).is_none()
        );
    }

    #[test]
    fn tenant_keys_win_over_bare_host_keys() {
        let entries = vec![
            entry("git.corp.com", "bob"),
            entry("git.corp.com/team-a", "alice"),
        ];
        // The tenant answers its own paths; the bare host no longer
        // shadows it.
        let found =
            git_credential_lookup(&entries, &request("git.corp.com", Some("team-a/r"))).unwrap();
        assert_eq!(found.username, "alice");
        // Other paths still fall through to the bare host.
        let found =
            git_credential_lookup(&entries, &request("git.corp.com", Some("team-b/r"))).unwrap();
        assert_eq!(found.username, "bob");
    }

    #[test]
    fn default_ports_strip_scheme_aware() {
        let entries = vec![entry("example.com", "user"), entry("127.0.0.1", "local")];
        // :443 strips for https and absent schemes only.
        assert!(git_credential_lookup(&entries, &request("example.com:443", None)).is_some());
        let mut absent = request("example.com:443", None);
        absent.protocol = None;
        assert!(git_credential_lookup(&entries, &absent).is_some());
        // :80 strips for http only (loopback, per the http gate).
        assert!(git_credential_lookup(&entries, &http_request("127.0.0.1:80", None)).is_some());
        assert!(git_credential_lookup(&entries, &request("example.com:80", None)).is_none());
        // Cross-scheme defaults keep their suffix and miss.
        assert!(git_credential_lookup(&entries, &http_request("127.0.0.1:443", None)).is_none());
    }

    #[test]
    fn answer_renders_exact_credential_block() {
        assert_eq!(
            render_credential_answer("octocat", "gho_x"),
            "username=octocat\npassword=gho_x\n\n"
        );
        // Never a chain-killing `quit` attribute (line-anchored).
        let hostile = render_credential_answer("quit", "quit=true");
        assert!(hostile.lines().all(|line| !line.starts_with("quit=")));
    }
}
