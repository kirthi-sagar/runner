//! Provider connectivity checks (`runner provider test`): credential
//! presence, API reachability, identity, and permissions. Pure mapping
//! helpers are unit-tested; live HTTP paths are covered by stub-server
//! tests next to each client. Tokens are never printed.

use runner_core::config::RunnerConfig;
use runner_providers::github::client::ScopeVerdict;

/// Provider under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderName {
    Github,
    Gitlab,
    Bitbucket,
    Local,
}

impl ProviderName {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "github" => Ok(Self::Github),
            "gitlab" => Ok(Self::Gitlab),
            "bitbucket" => Ok(Self::Bitbucket),
            "local" => Ok(Self::Local),
            other => Err(format!(
                "unknown provider: '{other}' (want github|gitlab|bitbucket|local)"
            )),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::Local => "local",
        }
    }
}

/// One provider verdict: `ok` plus human-readable lines.
#[derive(Debug, Clone)]
pub struct ProviderReport {
    pub provider: &'static str,
    pub ok: bool,
    pub lines: Vec<String>,
}

impl ProviderReport {
    fn pass(provider: &'static str, lines: Vec<String>) -> Self {
        Self {
            provider,
            ok: true,
            lines,
        }
    }

    fn fail(provider: &'static str, lines: Vec<String>) -> Self {
        Self {
            provider,
            ok: false,
            lines,
        }
    }
}

/// Render for terminal output.
pub fn render(report: &ProviderReport) -> String {
    let mut out = format!(
        "provider {}: {}\n",
        report.provider,
        if report.ok { "OK" } else { "FAILED" }
    );
    for line in &report.lines {
        out.push_str(&format!("  {line}\n"));
    }
    out
}

/// Map a scope verdict to (ok, line). Classic `admin:org`/`repo` proves
/// JIT issuance rights; fine-grained tokens carry no advertised scopes.
pub fn scope_line(verdict: &ScopeVerdict) -> (bool, String) {
    match verdict {
        ScopeVerdict::ClassicSufficient => {
            (true, "JIT runner admin: yes (classic scopes)".to_string())
        }
        ScopeVerdict::UnverifiableOffline => (
            true,
            "fine-grained/App token: permissions proven by API use".to_string(),
        ),
        ScopeVerdict::Insufficient { scopes } => {
            (false, format!("insufficient token scopes: {scopes}"))
        }
    }
}

/// Classify a GitLab client error: bad credentials vs connectivity.
pub fn gitlab_err_kind(message: &str) -> &'static str {
    if message.contains("401") {
        "bad runner token (401)"
    } else {
        "connectivity/API failure"
    }
}

/// Classify a Bitbucket OAuth error: bad credentials vs connectivity.
pub fn bitbucket_err_kind(message: &str) -> &'static str {
    if message.contains("400") || message.contains("401") {
        "bad OAuth credentials"
    } else {
        "connectivity/API failure"
    }
}

async fn test_github() -> ProviderReport {
    use runner_core::config::github_token_from_env;
    use runner_providers::github::client::GithubClient;

    let Some(token) = github_token_from_env() else {
        return ProviderReport::fail(
            "github",
            vec!["RUNNER_GITHUB_TOKEN unset; run `runner auth github`".to_string()],
        );
    };
    let client = match GithubClient::new(token) {
        Ok(client) => client,
        Err(e) => return ProviderReport::fail("github", vec![e]),
    };
    let mut lines = vec!["token: present (env)".to_string()];
    match client.whoami().await {
        Ok(login) => lines.push(format!("authenticated as: {login}")),
        Err(e) if e.contains("401") => {
            lines.push("credentials rejected (401 unauthorized)".to_string());
            return ProviderReport::fail("github", lines);
        }
        Err(e) => {
            lines.push(format!("connectivity failure: {e}"));
            return ProviderReport::fail("github", lines);
        }
    }
    match client.validate_token_scope().await {
        Ok(verdict) => {
            let (ok, line) = scope_line(&verdict);
            lines.push(line);
            if ok {
                ProviderReport::pass("github", lines)
            } else {
                ProviderReport::fail("github", lines)
            }
        }
        Err(e) => {
            lines.push(format!("scope check failed: {e}"));
            ProviderReport::fail("github", lines)
        }
    }
}

async fn test_gitlab(config: &RunnerConfig) -> ProviderReport {
    use runner_providers::providers::gitlab::{GitlabClient, GitlabSystemInfo};

    if !config.gitlab.enabled {
        return ProviderReport::fail(
            "gitlab",
            vec!["provider disabled; set [gitlab] enabled = true".to_string()],
        );
    }
    if config.gitlab.runner_token.trim().is_empty() {
        return ProviderReport::fail(
            "gitlab",
            vec!["runner_token empty in [gitlab] config".to_string()],
        );
    }
    let mut lines = vec![format!("endpoint: {}", config.gitlab.url)];
    let client = GitlabClient::new(config.gitlab.url.clone());
    match client
        .request_job(
            &config.gitlab.runner_token,
            &GitlabSystemInfo::local(),
            &config.gitlab.tags,
        )
        .await
    {
        Ok(None) => {
            lines.push("runner token accepted; queue empty".to_string());
            ProviderReport::pass("gitlab", lines)
        }
        Ok(Some(job)) => {
            lines.push(format!("runner token accepted; job #{} waiting", job.id));
            ProviderReport::pass("gitlab", lines)
        }
        Err(e) => {
            let message = e.to_string();
            lines.push(format!("{}: {message}", gitlab_err_kind(&message)));
            ProviderReport::fail("gitlab", lines)
        }
    }
}

async fn test_bitbucket(config: &RunnerConfig) -> ProviderReport {
    use runner_providers::providers::bitbucket::BitbucketClient;

    if !config.bitbucket.enabled {
        return ProviderReport::fail(
            "bitbucket",
            vec!["provider disabled; set [bitbucket] enabled = true".to_string()],
        );
    }
    if config.bitbucket.oauth_client_id.trim().is_empty()
        || config.bitbucket.oauth_client_secret.trim().is_empty()
    {
        return ProviderReport::fail(
            "bitbucket",
            vec!["oauth_client_id/secret empty in [bitbucket] config".to_string()],
        );
    }
    let client = BitbucketClient::new(
        config.bitbucket.oauth_client_id.clone(),
        config.bitbucket.oauth_client_secret.clone(),
    );
    match client.test_credentials().await {
        Ok(expiry) => {
            let secs = expiry
                .saturating_duration_since(std::time::Instant::now())
                .as_secs();
            ProviderReport::pass(
                "bitbucket",
                vec![format!("OAuth grant accepted; token expires in ~{secs}s")],
            )
        }
        Err(e) => {
            let message = e.to_string();
            ProviderReport::fail(
                "bitbucket",
                vec![format!("{}: {message}", bitbucket_err_kind(&message))],
            )
        }
    }
}

fn test_local() -> ProviderReport {
    let tier = if runner_sandbox::mounts::probe_userns() {
        "sandboxed (user namespaces)"
    } else {
        "governed-direct (no user namespaces)"
    };
    ProviderReport::pass("local", vec![format!("always available; execution {tier}")])
}

/// Run one provider check (network for remote providers).
pub async fn test_provider(name: ProviderName, config: &RunnerConfig) -> ProviderReport {
    match name {
        ProviderName::Github => test_github().await,
        ProviderName::Gitlab => test_gitlab(config).await,
        ProviderName::Bitbucket => test_bitbucket(config).await,
        ProviderName::Local => test_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_names_parse() {
        assert_eq!(
            ProviderName::from_name("github").unwrap(),
            ProviderName::Github
        );
        assert_eq!(
            ProviderName::from_name("GitLab").unwrap(),
            ProviderName::Gitlab
        );
        assert_eq!(
            ProviderName::from_name("BITBUCKET").unwrap(),
            ProviderName::Bitbucket
        );
        assert_eq!(
            ProviderName::from_name("local").unwrap(),
            ProviderName::Local
        );
        assert!(ProviderName::from_name("jenkins").is_err());
    }

    #[test]
    fn scope_lines_map_verdicts() {
        let (ok, line) = scope_line(&ScopeVerdict::ClassicSufficient);
        assert!(ok && line.contains("admin"));
        let (ok, _) = scope_line(&ScopeVerdict::UnverifiableOffline);
        assert!(ok);
        let (ok, line) = scope_line(&runner_providers::github::client::classic_scopes_verdict(
            "gist",
        ));
        assert!(!ok && line.contains("gist"));
    }

    #[test]
    fn error_kinds_classify() {
        assert_eq!(
            gitlab_err_kind("gitlab jobs/request: HTTP 401 Unauthorized"),
            "bad runner token (401)"
        );
        assert_eq!(
            gitlab_err_kind("gitlab jobs/request failed: dns"),
            "connectivity/API failure"
        );
        assert_eq!(
            bitbucket_err_kind("bitbucket oauth: HTTP 400 Bad Request"),
            "bad OAuth credentials"
        );
        assert_eq!(
            bitbucket_err_kind("bitbucket oauth failed: timeout"),
            "connectivity/API failure"
        );
    }

    #[test]
    fn local_report_always_passes_and_renders() {
        let report = test_local();
        assert!(report.ok);
        let text = render(&report);
        assert!(text.contains("provider local: OK"));
    }

    #[tokio::test]
    async fn disabled_providers_fail_with_guidance() {
        let config = RunnerConfig::default();
        let gitlab = test_provider(ProviderName::Gitlab, &config).await;
        assert!(!gitlab.ok);
        assert!(gitlab.lines[0].contains("enabled"));
        let bitbucket = test_provider(ProviderName::Bitbucket, &config).await;
        assert!(!bitbucket.ok);
    }
}
