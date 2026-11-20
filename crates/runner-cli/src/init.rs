//! Host onboarding (`runner init`): write config, seed layout, store secrets.
//!
//! All filesystem locations arrive as explicit paths so tests stay hermetic
//! (no `$HOME` reads here); `main.rs` resolves the real defaults. Existing
//! configs merge (never clobber), an unparsable config is refused, secrets
//! go to the 0600 env store, and report text never contains secret values.

use std::path::PathBuf;

use runner_core::auth::{ProviderSlot, TokenStore};
use runner_core::config::RunnerConfig;

/// Onboarding inputs with explicit output paths.
#[derive(Debug, Clone)]
pub struct InitOptions {
    pub org: Option<String>,
    /// Repository slug (`owner/name`) for coordinator queue polling.
    pub repo: Option<String>,
    /// GitHub token: stored in the env file, never printed.
    pub token: Option<String>,
    pub config_path: PathBuf,
    pub env_path: PathBuf,
    pub cache_dir: PathBuf,
}

/// What `run_init` did, plus operator next steps.
#[derive(Debug, Clone)]
pub struct InitReport {
    pub config_path: PathBuf,
    pub created_config: bool,
    pub changes: Vec<String>,
    pub next_steps: Vec<String>,
}

/// Split an `owner/name` slug; both parts must be non-empty.
pub fn parse_repo_slug(raw: &str) -> Result<(String, String), String> {
    let slug = raw.trim();
    let invalid = || format!("invalid --repo {raw:?}: expected owner/name (e.g. acme/web)");
    let (owner, name) = slug.split_once('/').ok_or_else(invalid)?;
    let (owner, name) = (owner.trim(), name.trim());
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Err(invalid());
    }
    Ok((owner.to_string(), name.to_string()))
}

fn non_empty(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Write/merge config, store the token, seed the cache dir. Fails closed:
/// validation and parsing happen before any write.
pub fn run_init(opts: &InitOptions) -> Result<InitReport, String> {
    // Validate everything before touching the filesystem.
    let repo = match non_empty(&opts.repo) {
        Some(slug) => Some(parse_repo_slug(&slug)?),
        None => None,
    };
    let org = non_empty(&opts.org);
    let token = non_empty(&opts.token);

    let existed = opts.config_path.exists();
    let mut config = if existed {
        RunnerConfig::load_from(&opts.config_path)?
    } else {
        RunnerConfig::default()
    };

    let mut changes = Vec::new();
    if let Some(org) = org {
        if config.org.as_deref() != Some(org.as_str()) {
            changes.push(format!("set org = {org}"));
            config.org = Some(org);
        }
    }
    if let Some((owner, name)) = repo {
        if config.coordinator.repo_owner.as_deref() != Some(owner.as_str())
            || config.coordinator.repo_name.as_deref() != Some(name.as_str())
        {
            changes.push(format!("set coordinator repository = {owner}/{name}"));
            config.coordinator.repo_owner = Some(owner);
            config.coordinator.repo_name = Some(name);
        }
    }

    config
        .save_to(&opts.config_path)
        .map_err(|e| format!("write {}: {e}", opts.config_path.display()))?;

    if let Some(secret) = token {
        TokenStore::new(opts.env_path.clone())
            .set_token(ProviderSlot::Github, &secret)
            .map_err(|e| format!("store github token: {e}"))?;
        changes.push(format!(
            "stored github token in {} (value never shown)",
            opts.env_path.display()
        ));
    }

    std::fs::create_dir_all(&opts.cache_dir)
        .map_err(|e| format!("create {}: {e}", opts.cache_dir.display()))?;

    let token_present = TokenStore::new(opts.env_path.clone()).has_token(ProviderSlot::Github);
    let mut next_steps = Vec::new();
    if token_present {
        next_steps.push("runner auth status  # verify stored credentials".to_string());
    } else {
        next_steps.push("runner auth github --token <T>  # store a GitHub token".to_string());
    }
    next_steps.push("runner service install  # run the daemon under systemd".to_string());
    next_steps.push("runner doctor  # verify host readiness".to_string());
    next_steps.push("runner start  # launch the coordinator".to_string());

    Ok(InitReport {
        config_path: opts.config_path.clone(),
        created_config: !existed,
        changes,
        next_steps,
    })
}

/// Render a human-readable report (text-only; outside the schema freeze).
pub fn render_report(report: &InitReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("initialized {}\n", report.config_path.display()));
    if report.changes.is_empty() {
        out.push_str("config already up to date (no changes)\n");
    } else {
        for change in &report.changes {
            out.push_str(&format!("  + {change}\n"));
        }
    }
    out.push_str("next steps:\n");
    for step in &report.next_steps {
        out.push_str(&format!("  - {step}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_slugs_split_and_reject() {
        assert_eq!(
            parse_repo_slug("acme/web").unwrap(),
            ("acme".to_string(), "web".to_string())
        );
        assert_eq!(
            parse_repo_slug("  acme/web  ").unwrap(),
            ("acme".to_string(), "web".to_string())
        );
        for bad in ["noslash", "a/b/c", "/name", "owner/", "", "  "] {
            let err = parse_repo_slug(bad).unwrap_err();
            assert!(err.contains("owner/name"), "slug {bad:?}: {err}");
        }
    }

    #[test]
    fn report_renders_changes_and_next_steps() {
        let report = InitReport {
            config_path: PathBuf::from("/tmp/x/config.toml"),
            created_config: true,
            changes: vec!["set org = acme".to_string()],
            next_steps: vec!["runner doctor".to_string()],
        };
        let rendered = render_report(&report);
        assert!(rendered.contains("/tmp/x/config.toml"), "{rendered}");
        assert!(rendered.contains("set org = acme"), "{rendered}");
        assert!(rendered.contains("runner doctor"), "{rendered}");

        let idle = InitReport {
            changes: Vec::new(),
            ..report
        };
        assert!(render_report(&idle).contains("already up to date"));
    }
}
