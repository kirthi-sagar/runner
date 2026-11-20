//! Daemon coordinator wiring: poll queued CI jobs and dispatch them.
//!
//! Lives in the library (not `main.rs`) so integration tests can drive
//! coordinator startup inside a tokio runtime.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use runner_core::config::{
    bitbucket_client_id_from_env, bitbucket_client_secret_from_env, github_token_from_env,
    gitlab_token_from_env, RunnerConfig,
};
use runner_core::governor::cgroup::CgroupSlice;
use runner_core::governor::supervisor::SharedState;
use runner_core::mesh::cloud::CloudPool;
use runner_providers::github::client::GithubClient;
use runner_providers::github::webhooks::{
    run_coordinator, run_watchdog_cycle, DispatchContext, JitScope, QueuePoller, WatchdogMap,
};
use runner_providers::providers::bitbucket::{run_bitbucket_loop, BitbucketProvider};
use runner_providers::providers::gitlab::{run_gitlab_loop, GitlabProvider};

/// Scale-to-zero cadence for the standalone watchdog (idle threshold
/// is 300s, so 30s granularity loses nothing and halves API traffic).
pub const WATCHDOG_INTERVAL_SECS: u64 = 30;

/// CI forges the daemon can supervise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forge {
    Github,
    Gitlab,
    Bitbucket,
}

/// CI credentials resolved from the config file + environment.
/// File values win; blanks fall back to `RUNNER_*` variables.
#[derive(Debug, Clone, Default)]
pub struct ForgeTokens {
    pub github: Option<String>,
    pub gitlab: Option<String>,
    pub bitbucket_id: Option<String>,
    pub bitbucket_secret: Option<String>,
}

fn nonblank(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolve every forge credential (pure wrt config + process env).
pub fn resolve_tokens(config: &RunnerConfig) -> ForgeTokens {
    ForgeTokens {
        github: github_token_from_env(),
        gitlab: nonblank(&config.gitlab.runner_token).or_else(gitlab_token_from_env),
        bitbucket_id: nonblank(&config.bitbucket.oauth_client_id)
            .or_else(bitbucket_client_id_from_env),
        bitbucket_secret: nonblank(&config.bitbucket.oauth_client_secret)
            .or_else(bitbucket_client_secret_from_env),
    }
}

/// Which forges may supervise jobs. Pure over config + resolved tokens
/// (no env reads here) so the matrix is unit-testable.
pub fn enabled_forges(config: &RunnerConfig, tokens: &ForgeTokens) -> Vec<Forge> {
    let mut forges = Vec::new();
    let coord = &config.coordinator;
    let repo_set = coord
        .repo_owner
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty())
        && coord
            .repo_name
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
    if repo_set && tokens.github.is_some() {
        forges.push(Forge::Github);
    }
    if config.gitlab.enabled && tokens.gitlab.is_some() {
        forges.push(Forge::Gitlab);
    }
    let bb = &config.bitbucket;
    if config.bitbucket.enabled
        && !bb.workspace.trim().is_empty()
        && !bb.runner_uuid.trim().is_empty()
        && tokens.bitbucket_id.is_some()
        && tokens.bitbucket_secret.is_some()
    {
        forges.push(Forge::Bitbucket);
    }
    forges
}

/// Startup reconciliation: discover live `runner-ci-*` nodes and track
/// the unknown ones (launches ledger-recorded idempotently inside
/// [`CloudPool::reconcile_active_nodes`]). Returns newly tracked nodes.
/// Never fails the daemon: API errors log loudly and yield zero.
pub async fn reconcile_into_state(pool: &CloudPool, state: &SharedState) -> usize {
    let found = match pool.reconcile_active_nodes().await {
        Ok(nodes) => nodes,
        Err(e) => {
            eprintln!("runner: cloud reconcile failed ({e})");
            return 0;
        }
    };
    if found.is_empty() {
        return 0;
    }
    let mut guard = state.write().await;
    let known: Vec<String> = guard.cloud_nodes().iter().map(|n| n.id.clone()).collect();
    let mut added = 0;
    for node in found {
        if known.contains(&node.id) {
            continue;
        }
        eprintln!(
            "runner: reconciled orphan cloud node {} [{}]",
            node.id, node.provider
        );
        guard.add_cloud_node(node);
        added += 1;
    }
    added
}

/// Standalone scale-to-zero watchdog: reconcile once at startup, then
/// reap 5-minute-idle nodes every [`WATCHDOG_INTERVAL_SECS`]. Runs
/// independently of every forge loop (and of forge outages).
pub async fn spawn_cloud_watchdog(pool: CloudPool, state: SharedState) {
    reconcile_into_state(&pool, &state).await;
    let mut watchdogs: WatchdogMap = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(WATCHDOG_INTERVAL_SECS)).await;
        let depth = state.read().await.queue_depth();
        run_watchdog_cycle(&pool, &state, &mut watchdogs, Instant::now(), depth).await;
    }
}

/// Re-announce cadence for joiners (heals coordinator restarts and
/// NAT rebinding; the first announce fires immediately at spawn).
pub const ANNOUNCE_INTERVAL_SECS: u64 = 60;

/// Spawn the WAN peer transport when `[mesh] peer_port` is set, plus the
/// join-announce loop when coordinator coordinates are configured. Runs
/// even with zero forges: donor-only nodes still serve peers. Silent
/// when unset; misconfiguration logs loudly and disables the transport.
pub async fn spawn_peer_transport(config: &RunnerConfig, state: SharedState) {
    use runner_core::mesh::invite::{secret_from_hex, InviteAuthority};
    use runner_core::mesh::peer::ensure_node_keypair;
    use runner_core::mesh::roles::{CoordinatorRole, MeshRoles, PeerRole};
    use runner_core::mesh::transport::{PeerTransport, TransportConfig};
    use runner_providers::wan::WorkerExecutor;
    use std::sync::Arc;

    let Some(port) = config.mesh.peer_port else {
        return;
    };
    let mut cfg = config.clone();
    let keys = match ensure_node_keypair(&mut cfg) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("runner: mesh identity invalid ({e}); WAN transport off");
            return;
        }
    };
    let secret_hex = match config.mesh.secret.clone() {
        Some(hex) => hex,
        None => {
            eprintln!("runner: [mesh] peer_port set without a mesh secret; WAN transport off");
            return;
        }
    };
    let authority = match secret_from_hex(&secret_hex)
        .map_err(|e| e.to_string())
        .and_then(InviteAuthority::new)
    {
        Ok(authority) => authority,
        Err(e) => {
            eprintln!("runner: mesh secret invalid ({e}); WAN transport off");
            return;
        }
    };
    let executor = Arc::new(WorkerExecutor::new(
        config.coordinator.worker_version.clone(),
        runner_sandbox::mounts::probe_userns(),
        Duration::from_secs(config.coordinator.job_timeout_mins.max(1) * 60),
        runner_core::governor::cgroup::CgroupSlice::system_default(),
        state.clone(),
    ));
    let roles = Arc::new(MeshRoles::new(
        CoordinatorRole::new(authority, state.clone(), RunnerConfig::default_path()),
        PeerRole::new(executor, state.clone()),
    ));
    let discover_roles = roles.clone();
    let tx = match PeerTransport::spawn(
        TransportConfig {
            listen: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            keys: keys.clone(),
        },
        roles,
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("runner: peer transport bind failed ({e}); WAN transport off");
            return;
        }
    };
    state.write().await.set_peer_transport(tx.clone());
    eprintln!("runner: WAN peer transport on 0.0.0.0:{port}");
    let stun_servers = runner_core::mesh::stun::resolve_stun_servers(
        &runner_core::mesh::stun::stun_servers(&config.mesh),
    )
    .await;
    // Self-discovery for JoinAccept replies (detached: accepts carry no
    // reflexive until it lands, and the mesh routes fine without it).
    if !stun_servers.is_empty() {
        let (discover_tx, discover_servers) = (tx.clone(), stun_servers.clone());
        tokio::spawn(async move {
            use runner_core::mesh::stun::discover_via_transport;
            match discover_via_transport(&discover_tx, &discover_servers).await {
                Ok(found) => {
                    discover_roles
                        .coordinator
                        .set_reflexive(found.reflexive)
                        .await;
                    eprintln!(
                        "runner: coordinator reflexive address is {}",
                        found.reflexive
                    );
                }
                Err(e) => eprintln!("runner: coordinator STUN discovery failed ({e})"),
            }
        });
    }
    if let (Some(coordinator), Some(pubkey), Some(token)) = (
        config.mesh.coordinator.clone(),
        config.mesh.coordinator_pubkey.clone(),
        config.mesh.join_token.clone(),
    ) {
        // Self record: the join-time entry matching our own public key.
        let me = config
            .peers
            .iter()
            .find(|p| p.public_key == keys.public_b64);
        match me {
            Some(record) => {
                let join = AnnounceIdentity {
                    node_id: record.node_id.clone(),
                    pubkey_b64: record.public_key.clone(),
                    max_cores: record.max_cores,
                    max_ram_mb: record.max_ram_mb,
                    listen_port: port,
                };
                tokio::spawn(announce_loop(
                    tx.clone(),
                    coordinator,
                    pubkey,
                    token,
                    join,
                    stun_servers.clone(),
                ));
            }
            None => eprintln!(
                "runner: no join record matching this identity; run `runner join` to federate"
            ),
        }
    }
}

/// Join-time identity + caps riding every announce.
struct AnnounceIdentity {
    node_id: String,
    pubkey_b64: String,
    max_cores: u32,
    max_ram_mb: u64,
    listen_port: u16,
}

/// NAT-traversal candidates for one announce: the STUN-discovered
/// reflexive address (best effort; `None` when STUN is disabled or
/// silent, in which case observed-source routing still works) plus the
/// LAN source address toward the coordinator.
async fn join_candidates(
    tx: &runner_core::mesh::transport::PeerTransport,
    stun_servers: &[std::net::SocketAddr],
    coordinator: std::net::SocketAddr,
    listen_port: u16,
) -> (Option<String>, Option<String>) {
    use runner_core::mesh::stun::{discover_via_transport, local_addr_for};
    let reflexive = if stun_servers.is_empty() {
        None
    } else {
        match discover_via_transport(tx, stun_servers).await {
            Ok(found) => {
                if let Some(nat) = found.nat {
                    eprintln!(
                        "runner: NAT mapping looks {nat:?}; reflexive is {}",
                        found.reflexive
                    );
                }
                Some(found.reflexive.to_string())
            }
            Err(e) => {
                eprintln!("runner: STUN discovery failed ({e}); announcing without reflexive");
                None
            }
        }
    };
    let lan = local_addr_for(coordinator)
        .map(|ip| std::net::SocketAddr::new(ip, listen_port).to_string());
    (reflexive, lan)
}

/// Announce this joiner to its coordinator immediately, then every
/// [`ANNOUNCE_INTERVAL_SECS`] (heals coordinator restarts and NAT
/// rebinding; the coordinator dedups known nodes by pubkey).
async fn announce_loop(
    tx: runner_core::mesh::transport::PeerTransport,
    coordinator: String,
    pubkey: String,
    token: String,
    me: AnnounceIdentity,
    stun_servers: Vec<std::net::SocketAddr>,
) {
    use runner_core::mesh::proto::JoinAnnounce;
    use tokio::net::lookup_host;

    let mut last_addr: Option<std::net::SocketAddr> = None;
    loop {
        let addr = match lookup_host(&coordinator).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    eprintln!("runner: coordinator {coordinator} resolved to nothing; retrying");
                    tokio::time::sleep(Duration::from_secs(ANNOUNCE_INTERVAL_SECS)).await;
                    continue;
                }
            },
            Err(e) => {
                eprintln!("runner: coordinator {coordinator} unresolvable ({e}); retrying");
                tokio::time::sleep(Duration::from_secs(ANNOUNCE_INTERVAL_SECS)).await;
                continue;
            }
        };
        // Session (re-)registration only when the endpoint is new;
        // steady state just re-announces over the live session.
        if last_addr != Some(addr) {
            if let Err(e) = tx.add_session("coordinator", &pubkey, addr).await {
                eprintln!("runner: coordinator session failed ({e}); retrying");
                tokio::time::sleep(Duration::from_secs(ANNOUNCE_INTERVAL_SECS)).await;
                continue;
            }
            last_addr = Some(addr);
        }
        let (reflexive, lan) = join_candidates(&tx, &stun_servers, addr, me.listen_port).await;
        let announce = JoinAnnounce {
            proto: runner_core::mesh::proto::PROTO_TAG.to_string(),
            node_id: me.node_id.clone(),
            pubkey_b64: me.pubkey_b64.clone(),
            token: token.clone(),
            listen_port: me.listen_port,
            max_cores: me.max_cores,
            max_ram_mb: me.max_ram_mb,
            reflexive,
            lan,
        };
        if let Err(e) = tx.announce(addr, announce).await {
            eprintln!("runner: join-announce to {coordinator} failed ({e}); retrying");
        }
        tokio::time::sleep(Duration::from_secs(ANNOUNCE_INTERVAL_SECS)).await;
    }
}

/// Spawn one coordinator task per enabled forge. Without any forge the
/// daemon runs governor-only.
///
/// Async throughout: shared-state access uses `.write().await`, never
/// `blocking_write()`, so calling this from a tokio runtime thread
/// cannot panic (regression: v0.4.1 aborted on startup whenever
/// `cloud.max_monthly_spend > 0`).
pub async fn spawn_coordinator(
    config: &RunnerConfig,
    state: runner_core::governor::supervisor::SharedState,
) {
    let tokens = resolve_tokens(config);
    let forges = enabled_forges(config, &tokens);
    let cloud = (config.cloud.max_monthly_spend > 0.0).then(|| CloudPool::from_config(config));
    // Attach the pool to shared state so IPC-driven termination
    // (`cloud_terminate`/`cloud_purge`) can reach the provider APIs,
    // and start the watchdog regardless of forge enablement: orphans
    // must reap even in governor-only mode or during forge outages.
    if let Some(pool) = cloud.clone() {
        state
            .write()
            .await
            .set_cloud_pool(pool.clone(), config.cloud.max_monthly_spend);
        tokio::spawn(spawn_cloud_watchdog(pool, state.clone()));
    }
    if forges.is_empty() {
        eprintln!("runner: no CI providers enabled; governor-only mode");
        return;
    }
    let sandboxed = runner_sandbox::mounts::probe_userns();
    if !sandboxed {
        eprintln!("runner: unprivileged userns blocked; dispatches run unsandboxed");
    }
    // One kill ceiling for every forge (GitLab/Bitbucket configs carry
    // no per-forge timeout).
    let timeout = Duration::from_secs(config.coordinator.job_timeout_mins * 60);
    if forges.contains(&Forge::Github) {
        spawn_github(config, &tokens, cloud.clone(), state.clone(), sandboxed).await;
    }
    if forges.contains(&Forge::Gitlab) {
        // Defensive: `enabled_forges` guarantees the token, but a
        // future mismatch must skip one forge, never abort the daemon
        // (release profile is `panic = "abort"`).
        if let Some(token) = tokens.gitlab.clone() {
            let provider = Arc::new(GitlabProvider::new(
                config.gitlab.url.clone(),
                token,
                config.gitlab.tags.clone(),
            ));
            let interval = Duration::from_secs(config.gitlab.poll_secs.max(5));
            tokio::spawn(run_gitlab_loop(
                provider,
                state.clone(),
                interval,
                !sandboxed,
                timeout,
            ));
        } else {
            eprintln!("runner: gitlab enabled without a token; skipping forge");
        }
    }
    if forges.contains(&Forge::Bitbucket) {
        if let (Some(id), Some(secret)) =
            (tokens.bitbucket_id.clone(), tokens.bitbucket_secret.clone())
        {
            let provider = Arc::new(BitbucketProvider::new(
                id,
                secret,
                config.bitbucket.workspace.clone(),
                config.bitbucket.repo_slug.clone(),
                config.bitbucket.runner_uuid.clone(),
                config.bitbucket.labels.clone(),
            ));
            let interval = Duration::from_secs(config.bitbucket.poll_secs.max(5));
            tokio::spawn(run_bitbucket_loop(
                provider,
                state.clone(),
                interval,
                !sandboxed,
                timeout,
            ));
        } else {
            eprintln!("runner: bitbucket enabled without credentials; skipping forge");
        }
    }
}

/// GitHub branch of [`spawn_coordinator`] (pre-existing behavior).
async fn spawn_github(
    config: &RunnerConfig,
    tokens: &ForgeTokens,
    cloud: Option<CloudPool>,
    state: runner_core::governor::supervisor::SharedState,
    sandboxed: bool,
) {
    let coord = &config.coordinator;
    let Some(token) = tokens.github.clone() else {
        eprintln!("runner: github enabled without a token; skipping forge");
        return;
    };
    let github = match GithubClient::new(token) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("runner: github client: {e}");
            return;
        }
    };
    let poller = QueuePoller::new(
        github.clone(),
        coord.repo_owner.clone().unwrap_or_default(),
        coord.repo_name.clone().unwrap_or_default(),
    )
    .with_interval(std::time::Duration::from_secs(coord.poll_secs.max(5)));
    let scope = match config.org.clone() {
        Some(org) => JitScope::Org { org },
        None => JitScope::Repo {
            owner: coord.repo_owner.clone().unwrap_or_default(),
            repo: coord.repo_name.clone().unwrap_or_default(),
        },
    };
    // Cache endpoint + token when the proxy bound successfully at boot.
    let (cache_url, cache_token) = {
        let guard = state.read().await;
        (guard.cache_base_url(), guard.cache_token())
    };
    // The polled repo is every job's true source (both JIT scopes).
    let repo_slug = match (coord.repo_owner.clone(), coord.repo_name.clone()) {
        (Some(owner), Some(repo)) if !owner.trim().is_empty() && !repo.trim().is_empty() => {
            Some(format!("{owner}/{repo}"))
        }
        _ => None,
    };
    let dispatch = coord.auto_dispatch.then(|| DispatchContext {
        github,
        scope,
        runner_group_id: coord.runner_group_id,
        worker_version: coord.worker_version.clone(),
        sandboxed,
        timeout: std::time::Duration::from_secs(coord.job_timeout_mins * 60),
        cache_url,
        cache_token,
        repo_slug,
    });
    tokio::spawn(run_coordinator(
        poller,
        dispatch,
        cloud,
        state,
        CgroupSlice::system_default(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(
        github: Option<&str>,
        gitlab: Option<&str>,
        bitbucket: Option<(&str, &str)>,
    ) -> ForgeTokens {
        ForgeTokens {
            github: github.map(str::to_string),
            gitlab: gitlab.map(str::to_string),
            bitbucket_id: bitbucket.map(|(id, _)| id.to_string()),
            bitbucket_secret: bitbucket.map(|(_, secret)| secret.to_string()),
        }
    }

    #[test]
    fn enablement_matrix() {
        let mut config = RunnerConfig::default();
        let none = tokens(None, None, None);
        assert!(enabled_forges(&config, &none).is_empty());

        // GitHub needs repo coordinates + token.
        config.coordinator.repo_owner = Some("o".to_string());
        config.coordinator.repo_name = Some("r".to_string());
        assert!(enabled_forges(&config, &none).is_empty());
        let github = tokens(Some("g"), None, None);
        assert_eq!(enabled_forges(&config, &github), vec![Forge::Github]);

        // GitLab needs enabled + token.
        config.gitlab.enabled = true;
        assert_eq!(enabled_forges(&config, &github), vec![Forge::Github]);
        let both = tokens(Some("g"), Some("gl"), None);
        assert_eq!(
            enabled_forges(&config, &both),
            vec![Forge::Github, Forge::Gitlab]
        );

        // Bitbucket needs enabled + workspace + uuid + id + secret.
        config.bitbucket.enabled = true;
        assert_eq!(
            enabled_forges(&config, &both),
            vec![Forge::Github, Forge::Gitlab]
        );
        config.bitbucket.workspace = "w".to_string();
        config.bitbucket.runner_uuid = "u".to_string();
        let all = tokens(Some("g"), Some("gl"), Some(("id", "secret")));
        assert_eq!(
            enabled_forges(&config, &all),
            vec![Forge::Github, Forge::Gitlab, Forge::Bitbucket]
        );
        // Half credentials stay disabled.
        let half = ForgeTokens {
            bitbucket_id: Some("id".to_string()),
            ..ForgeTokens::default()
        };
        assert!(enabled_forges(&config, &half).is_empty());
    }

    #[test]
    fn enabled_forge_always_carries_its_token() {
        // Invariant behind the defensive skips in `spawn_coordinator`:
        // an enabled forge implies its credential resolved. If this
        // ever fails, dispatch degrades to skip-one-forge, never abort.
        let mut config = RunnerConfig::default();
        config.coordinator.repo_owner = Some("o".to_string());
        config.coordinator.repo_name = Some("r".to_string());
        config.gitlab.enabled = true;
        config.bitbucket.enabled = true;
        config.bitbucket.workspace = "w".to_string();
        config.bitbucket.runner_uuid = "u".to_string();
        let full = tokens(Some("g"), Some("gl"), Some(("id", "secret")));
        for forge in enabled_forges(&config, &full) {
            match forge {
                Forge::Github => assert!(full.github.is_some()),
                Forge::Gitlab => assert!(full.gitlab.is_some()),
                Forge::Bitbucket => {
                    assert!(full.bitbucket_id.is_some());
                    assert!(full.bitbucket_secret.is_some());
                }
            }
        }
        // And no token can ever enable its forge.
        let none = tokens(None, None, None);
        assert!(enabled_forges(&config, &none).is_empty());
    }
}
