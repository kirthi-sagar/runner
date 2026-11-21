//! `runner` CLI entrypoint: host supervisor controls for humans and agents.

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use runner_cli::coordinator::spawn_coordinator;
use runner_core::config::{load_env_file, DonorConfig, PeerRecord, RunnerConfig};
use runner_core::governor::supervisor::{new_shared_state, run_supervisor};
use runner_core::ipc::{ipc_call, ipc_call_with, resolve_sock_path, IpcServer};
use runner_core::mcp::server::McpServer;
use runner_core::mcp::tools::ToolContext;
use runner_core::mesh::invite::{
    generate_secret_hex, parse_size_mb, parse_ttl_secs, secret_from_hex, InviteAuthority,
    InviteCaps, InviteRole, InviteToken,
};
use runner_core::mesh::peer::generate_keypair;
use runner_core::pidfile::{
    process_alive, read_pid, remove as remove_pidfile, resolve_pid_path, signal_daemon,
    wait_for_exit, write_current_pid,
};
use runner_core::status::status_report;

#[derive(Debug, Parser)]
#[command(
    name = "runner",
    version,
    about = "Zero-freeze GitHub Actions runner supervisor"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize host configuration (writes config, seeds layout)
    Init {
        #[arg(long)]
        org: Option<String>,
        /// Repository slug (`owner/name`) for coordinator queue polling
        #[arg(long)]
        repo: Option<String>,
        /// GitHub token: stored in the 0600 env file, never printed
        #[arg(long)]
        token: Option<String>,
    },
    /// Start the coordinator daemon (governor loop + IPC socket)
    Start {
        /// Run detached in the background (accepted; launch under
        /// systemd/setsid to detach).
        #[arg(long)]
        daemon: bool,
        /// Refuse to start when Tier-2 sandboxing is unavailable
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    /// Stop the daemon (SIGTERM, graceful; --force for SIGKILL)
    Stop {
        #[arg(long)]
        graceful: bool,
        #[arg(long)]
        force: bool,
    },
    /// Real-time health, slots, and jobs (spec section 4.2)
    Status {
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Start the MCP server for AI agents
    Mcp {
        #[arg(long, default_value = "stdio")]
        transport: String,
        #[command(subcommand)]
        command: Option<McpCommands>,
    },
    /// Start the enterprise web control plane (fleet API + OIDC SSO)
    Server {
        /// Listen address, e.g. 0.0.0.0:8080
        #[arg(long, default_value = "0.0.0.0:8080")]
        listen: String,
        /// OIDC issuer base URL (enables SSO with client id/secret)
        #[arg(long)]
        oidc_issuer: Option<String>,
        /// OIDC client id
        #[arg(long)]
        client_id: Option<String>,
        /// OIDC client secret
        #[arg(long)]
        client_secret: Option<String>,
    },
    /// Federated mesh controls
    Mesh {
        #[command(subcommand)]
        command: MeshCommands,
    },
    /// Join a mesh with an invitation token
    Join {
        token: String,
        /// Coordinator endpoint (host:port) for join-announce
        #[arg(long)]
        coordinator: String,
        /// Coordinator WireGuard public key (printed by `mesh invite`)
        #[arg(long)]
        coordinator_pubkey: String,
    },
    /// Manage the systemd user service (install/status/stop/start/uninstall)
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
    /// Store provider credentials in the local secrets file
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Verify the tamper-evident audit trail
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// Inspect fleet policy ceilings and gates
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Live terminal monitor: PSI gauges, governor weight, jobs, fleet
    Top {
        /// Redraw cadence in milliseconds (clamped 100..60000)
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
        /// Print a single snapshot and exit (scripts/CI)
        #[arg(long, default_value_t = false)]
        once: bool,
    },
    /// Listen for CI webhooks and dispatch instantly (HMAC-verified)
    Listen {
        /// TCP port to bind
        #[arg(long, default_value_t = 9898)]
        port: u16,
        /// HMAC webhook secret (or RUNNER_WEBHOOK_SECRET)
        #[arg(long)]
        secret: Option<String>,
    },
    /// Force the governor weight down for a duration (never freezes)
    Throttle {
        /// Throttle level: warning (weight 25), critical or high (weight 1)
        #[arg(long, default_value = "warning")]
        level: String,
        /// Override duration in minutes
        #[arg(long, default_value_t = 15)]
        duration: u64,
    },
    /// Diagnose system readiness (kernel, cgroups, sandboxes, daemon, MCP)
    Doctor {
        /// Also validate enterprise policy loading and audit continuity
        #[arg(long, default_value_t = false)]
        enterprise: bool,
        /// Also probe egress compliance (metadata/LAN blocked, HTTPS allowed)
        #[arg(long, default_value_t = false)]
        egress: bool,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
        /// Treat sandbox-guardrail warnings as fatal errors
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
    /// Provider credential and connectivity checks
    Provider {
        #[command(subcommand)]
        command: ProviderCommands,
    },
    /// Manage the git pre-commit hook (zero-freeze via runner exec)
    Hook {
        #[command(subcommand)]
        command: HookCommands,
    },
    /// Manage ephemeral cloud burst workers via the daemon
    Cloud {
        #[command(subcommand)]
        command: CloudCommands,
    },
    /// Inspect and manage the LAN cache proxy via the daemon
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Execute a command locally inside the zero-freeze sandbox
    Exec {
        /// Command and arguments to execute
        #[arg(required = true, trailing_var_arg = true)]
        command: Vec<String>,
        /// Bypass user namespace sandboxing (run directly with cgroup governance)
        #[arg(long, default_value_t = false)]
        no_sandbox: bool,
        /// Maximum execution timeout in minutes
        #[arg(long, default_value_t = 60)]
        timeout_mins: u64,
        /// Isolation tier: process (community namespaces) or microvm (enterprise Firecracker)
        #[arg(long, default_value = "process")]
        driver: String,
        /// Fail closed instead of running unsandboxed when Tier-2 is unavailable
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MeshCommands {
    /// Mint a signed invitation token for a trusted peer node (friends & family)
    Invite {
        #[arg(long, default_value = "donor")]
        role: String,
        #[arg(long, default_value = "4")]
        max_cores: u32,
        #[arg(long, default_value = "8G")]
        max_ram: String,
        #[arg(long, default_value = "7d")]
        ttl: String,
        #[arg(long, default_value = "peer")]
        name: String,
    },
    /// List connected WAN peers and cloud nodes (via daemon IPC)
    List {
        #[arg(long, default_value = "human")]
        format: String,
        /// Also browse the LAN for advertised peers (2s mDNS probe)
        #[arg(long)]
        lan: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommands {
    /// Write the user unit, enable it, and start the daemon
    Install,
    /// Show systemctl status of the user service
    Status,
    /// Stop the user service
    Stop,
    /// Start the user service
    Start,
    /// Stop, disable, and delete the user unit
    Uninstall,
}

#[derive(Debug, Subcommand)]
enum AuthCommands {
    /// Store the GitHub token (prompts when --token is omitted)
    Github {
        /// Token value (prefer piping; never pass via shared shell history on multi-user hosts)
        #[arg(long)]
        token: Option<String>,
    },
    /// Store the GitLab runner token (prompts when --token is omitted)
    Gitlab {
        /// Token value (prefer piping; never pass via shared shell history on multi-user hosts)
        #[arg(long)]
        token: Option<String>,
    },
    /// Store Bitbucket OAuth credentials (prompts for omitted values)
    Bitbucket {
        /// OAuth client id
        #[arg(long)]
        client_id: Option<String>,
        /// OAuth client secret
        #[arg(long)]
        client_secret: Option<String>,
    },
    /// Show credential presence per forge (tokens masked, never printed)
    Status,
}

#[derive(Debug, Subcommand)]
enum ProviderCommands {
    /// Validate credentials and connectivity for one provider
    Test {
        /// Provider name: github|gitlab|bitbucket|local
        provider: String,
    },
}

#[derive(Debug, Subcommand)]
enum HookCommands {
    /// Install a pre-commit hook routing checks through runner exec
    Install {
        /// Check command to run (auto-detected when omitted)
        #[arg(long)]
        cmd: Option<String>,
    },
    /// Remove the runner-managed hook, restoring any backup
    Uninstall,
}

#[derive(Debug, Subcommand)]
enum CloudCommands {
    /// List active cloud nodes with uptime and spend cap
    List {
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Terminate one cloud node by instance id
    Terminate {
        /// Instance id to destroy
        instance_id: String,
    },
    /// Terminate all tracked cloud nodes immediately
    Purge,
}

#[derive(Debug, Subcommand)]
enum CacheCommands {
    /// Show cache entries, size, hits, misses, and bandwidth saved
    Stats {
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Purge cached archives (all, or entries idle longer than N days)
    Clear {
        /// Remove every entry and reset counters
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Remove entries unaccessed for longer than N days
        #[arg(long)]
        older_than: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommands {
    /// Register the runner MCP server in an agent config (or print the snippet)
    Install {
        /// Agent config target
        #[arg(long, default_value = "generic")]
        target: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommands {
    /// Cryptographically verify the SHA-256 chained audit trail
    Verify {
        /// Trail file (default ~/.config/runner/audit.jsonl)
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
    /// Export the verified trail as JSONL for SIEM/compliance ingestion
    Export {
        /// Trail file (default ~/.config/runner/audit.jsonl)
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Export format (only "jsonl" is supported)
        #[arg(long, default_value = "jsonl")]
        format: String,
        /// Output path (default: stdout stream)
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Show tenant ceilings, provider gates, and burst restrictions
    Inspect,
}

/// Load the mesh signing authority, generating + persisting a secret once.
fn invite_authority(config: &mut RunnerConfig) -> Result<InviteAuthority, String> {
    if config.mesh.secret.is_none() {
        config.mesh.secret = Some(generate_secret_hex());
        config
            .save()
            .map_err(|e| format!("failed to save mesh secret: {e}"))?;
    }
    let hex = config.mesh.secret.clone().unwrap_or_default();
    InviteAuthority::new(secret_from_hex(&hex)?)
}

fn cmd_mesh_invite(role: &str, max_cores: u32, max_ram: &str, ttl: &str, name: &str) -> Result<()> {
    let mut config = RunnerConfig::load_or_default();
    let authority = invite_authority(&mut config).map_err(|e| anyhow::anyhow!(e))?;
    let token = InviteToken {
        role: role.parse::<InviteRole>().map_err(|e| anyhow::anyhow!(e))?,
        caps: InviteCaps {
            max_cores,
            max_ram_mb: parse_size_mb(max_ram).map_err(|e| anyhow::anyhow!(e))?,
        },
        ttl_secs: parse_ttl_secs(ttl).map_err(|e| anyhow::anyhow!(e))?,
        name: name.to_string(),
    };
    let minted = authority.mint(&token).map_err(|e| anyhow::anyhow!(e))?;
    let keys = runner_core::mesh::peer::ensure_node_keypair(&mut config)
        .map_err(|e| anyhow::anyhow!(e))?;
    config
        .save()
        .map_err(|e| anyhow::anyhow!("failed to save mesh identity: {e}"))?;
    println!("{minted}");
    println!("coordinator pubkey: {}", keys.public_b64);
    eprintln!("invite for {name}: role={role} cores={max_cores} ram={max_ram} ttl={ttl}");
    Ok(())
}

/// Split `host:port` for `--coordinator` (shape only; the daemon
/// resolves DNS when announcing).
fn parse_coordinator_endpoint(raw: &str) -> Result<(String, u16)> {
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("coordinator must be host:port, got {raw:?}"))?;
    if host.trim().is_empty() {
        anyhow::bail!("coordinator host is empty");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("coordinator port must be 1-65535"))?;
    if port == 0 {
        anyhow::bail!("coordinator port must be 1-65535");
    }
    Ok((host.trim().to_string(), port))
}

async fn cmd_join(token: &str, coordinator: &str, coordinator_pubkey: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let payload = InviteAuthority::decode_unverified(token).map_err(|e| anyhow::anyhow!(e))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now >= payload.expires_at {
        anyhow::bail!("invitation token has expired");
    }
    let (host, port) = parse_coordinator_endpoint(coordinator)?;
    if !runner_core::mesh::peer::valid_public_key(coordinator_pubkey) {
        anyhow::bail!("coordinator public key is not a valid base64 WireGuard key");
    }
    // This host donates *up to* the token caps: persist them so the local
    // supervisor (cgroups weight ladder + AFK boost + slot clamp) enforces
    // donor safety for every foreign job.
    let keys = generate_keypair();
    let node_id = format!(
        "{}-{}",
        payload.name,
        &keys.public_b64[..8.min(keys.public_b64.len())]
    );
    let record = PeerRecord {
        node_id: node_id.clone(),
        public_key: keys.public_b64.clone(),
        endpoint: None,
        max_cores: payload.max_cores,
        max_ram_mb: payload.max_ram_mb,
        status: "joining".to_string(),
    };
    let mut config = RunnerConfig::load_or_default();
    config.donor = Some(DonorConfig {
        max_cores: payload.max_cores,
        max_ram_mb: payload.max_ram_mb,
    });
    if !config.peers.iter().any(|p| p.node_id == node_id) {
        config.peers.push(record.clone());
    }
    // Mesh identity + federation coordinates (0600 file): the daemon
    // announces from these without further operator input.
    config.mesh.node_key = Some(keys.private_b64.clone());
    config.mesh.coordinator = Some(format!("{host}:{port}"));
    config.mesh.coordinator_pubkey = Some(coordinator_pubkey.to_string());
    config.mesh.join_token = Some(token.to_string());
    config.save()?;
    // Hot-add to a running daemon when present (best effort).
    let sock = resolve_sock_path();
    if sock.exists() {
        let params = serde_json::json!({ "record": record });
        if let Ok(res) = ipc_call_with(&sock, "join", Some(params)).await {
            if res.get("error").is_none() {
                eprintln!("daemon notified: peer {node_id} added");
            }
        }
    }
    println!(
        "joined as {node_id} (donor caps: {} cores, {}MB ram)",
        payload.max_cores, payload.max_ram_mb
    );
    println!("public key: {}", keys.public_b64);
    println!("private key stored in ~/.config/runner/config.toml (0600, never printed again)");
    println!("announcing to coordinator at {host}:{port} within 60s (or restart the daemon)");
    report_nat_diagnostic(&config).await;
    Ok(())
}

/// One-shot NAT diagnostic for `runner join`: prints this host's
/// reflexive mapping when STUN answers (first server only, so a silent
/// network costs at most ~3s). The daemon re-discovers on its own
/// socket at announce time; this never fails the join.
async fn report_nat_diagnostic(config: &RunnerConfig) {
    use runner_core::mesh::stun::{
        discover_reflexive_addr, resolve_stun_servers, stun_servers, STUN_TIMEOUT,
    };
    let servers = resolve_stun_servers(&stun_servers(&config.mesh)).await;
    let Some(server) = servers.first() else {
        return;
    };
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("NAT diagnostic skipped (no UDP socket: {e})");
            return;
        }
    };
    match discover_reflexive_addr(&socket, *server, STUN_TIMEOUT).await {
        Ok(reflexive) => println!("NAT diagnostic: this host's public mapping is {reflexive}"),
        Err(e) => eprintln!("NAT diagnostic: STUN silent ({e}); the daemon announces anyway"),
    }
}

async fn cmd_mesh_list(format: &str, lan: bool) -> Result<()> {
    if lan {
        let nodes = runner_core::mesh::discovery::LanDiscovery::browse_only(
            std::time::Duration::from_secs(2),
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        if format == "json" {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &nodes
                        .iter()
                        .map(|n| serde_json::json!({
                            "instance": n.instance, "host": n.host, "port": n.port,
                            "addrs": n.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                            "metrics": n.metrics.as_ref().map(|m| serde_json::json!({
                                "cores": m.cores, "ram_mb": m.ram_mb, "slots": m.slots,
                                "cache_port": m.cache_port,
                                "cache_enabled": m.cache_enabled,
                                "node_id": m.node_id,
                            })),
                        }))
                        .collect::<Vec<_>>()
                )?
            );
        } else {
            println!("lan peers: {}", nodes.len());
            for node in &nodes {
                println!("  - {} @ {} ({:?})", node.instance, node.host, node.metrics);
            }
        }
        return Ok(());
    }
    let sock = resolve_sock_path();
    let res = ipc_call(&sock, "peers")
        .await
        .map_err(|_| anyhow::anyhow!("daemon not reachable at {}", sock.display()))?;
    if let Some(err) = res.get("error") {
        anyhow::bail!("daemon error: {err}");
    }
    let result = &res["result"];
    if format == "json" {
        println!("{}", serde_json::to_string_pretty(result)?);
    } else {
        let peers = result["wan_peers"].as_array().cloned().unwrap_or_default();
        let cloud = result["cloud_nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        println!("wan peers: {}", peers.len());
        for peer in &peers {
            println!("  - {} [{}]", peer["node_id"], peer["status"]);
        }
        println!("cloud nodes: {}", cloud.len());
        for node in &cloud {
            println!(
                "  - {} ({}) [{}]",
                node["id"], node["provider"], node["status"]
            );
        }
    }
    Ok(())
}

/// Embedded webhook listener for daemon mode: shares the coordinator's
/// wake trigger. Missing secret fails closed (listener stays off).
async fn spawn_embedded_listener(
    config: &RunnerConfig,
    state: runner_core::governor::supervisor::SharedState,
) {
    let Some(port) = config.server.listen_port else {
        return;
    };
    let secret = std::env::var("RUNNER_WEBHOOK_SECRET").unwrap_or_default();
    if secret.trim().is_empty() {
        eprintln!("runner: [server] listen_port set but RUNNER_WEBHOOK_SECRET is empty; webhook listener off");
        return;
    }
    let notify = state.read().await.wakeup();
    tokio::spawn(async move {
        if let Err(e) = runner_enterprise::webhook::serve(port, secret, notify).await {
            eprintln!("runner: webhook listener exited: {e}");
        }
    });
}

#[cfg(unix)]
async fn listen_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    // Registration can fail in restricted containers; degrade to
    // "no signal handling" (SIGKILL still works) instead of aborting.
    let sigint = signal(SignalKind::interrupt()).ok();
    let sigterm = signal(SignalKind::terminate()).ok();
    if sigint.is_none() || sigterm.is_none() {
        eprintln!("runner: signal registration failed; signals ignored (SIGKILL still works)");
    }
    tokio::select! {
        _ = runner_core::governor::supervisor::wait_for_signal(sigint) => {},
        _ = runner_core::governor::supervisor::wait_for_signal(sigterm) => {},
    }
}

/// Windows has no POSIX signals; Ctrl-C is the only shutdown path.
#[cfg(windows)]
async fn listen_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Standalone `runner listen`: verify webhooks here, wake the daemon over
/// IPC. Runs until SIGINT/SIGTERM.
async fn cmd_listen(port: u16, secret: Option<String>) -> Result<()> {
    use tokio::sync::Notify;

    let secret = secret
        .or_else(|| std::env::var("RUNNER_WEBHOOK_SECRET").ok())
        .unwrap_or_default();
    if secret.trim().is_empty() {
        anyhow::bail!("refusing to listen without a secret (--secret or RUNNER_WEBHOOK_SECRET)");
    }
    let notify = Arc::new(Notify::new());
    let server = tokio::spawn(runner_enterprise::webhook::serve(
        port,
        secret.clone(),
        notify.clone(),
    ));
    let sock_path = resolve_sock_path();
    loop {
        tokio::select! {
            _ = notify.notified() => {
                match ipc_call(&sock_path, "poll_now").await {
                    Ok(_) => eprintln!("runner: daemon woken for instant dispatch"),
                    Err(e) => eprintln!("runner: daemon unreachable over IPC ({e}); event dropped"),
                }
            }
            _ = listen_shutdown() => break,
        }
    }
    server.abort();
    eprintln!("runner: listener stopped");
    Ok(())
}

fn cmd_stop(force: bool) -> Result<()> {
    let pid_path = resolve_pid_path();
    let sock_path = resolve_sock_path();
    let pid = match read_pid(&pid_path) {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!(
                "no pid file at {}; removing stale socket (if any)",
                pid_path.display()
            );
            let _ = std::fs::remove_file(&sock_path);
            return Ok(());
        }
    };
    if !process_alive(pid) {
        eprintln!("stale pid file (pid {pid} not running); cleaning up");
        remove_pidfile(&pid_path);
        let _ = std::fs::remove_file(&sock_path);
        return Ok(());
    }
    signal_daemon(pid, force).map_err(|e| anyhow::anyhow!(e))?;
    #[cfg(windows)]
    let signame = "stop signal (TerminateProcess)";
    #[cfg(not(windows))]
    let signame = if force { "SIGKILL" } else { "SIGTERM" };
    eprintln!("sent {signame} to daemon pid {pid}");
    if !force && !wait_for_exit(pid, std::time::Duration::from_secs(10)) {
        anyhow::bail!("daemon pid {pid} did not exit in 10s; retry with --force");
    }
    remove_pidfile(&pid_path);
    let _ = std::fs::remove_file(&sock_path);
    eprintln!("daemon stopped; socket and pid file cleaned");
    Ok(())
}

/// `runner auth github`: store the GitHub token in the 0600 secrets
/// file (created/updated in place, never logged). The daemon picks it up
/// on restart via env auto-load — no unit editing required.
fn cmd_init(
    config: &RunnerConfig,
    org: Option<String>,
    repo: Option<String>,
    token: Option<String>,
) -> Result<()> {
    use runner_cli::init::{run_init, InitOptions};
    use runner_core::config::{default_env_path, resolve_cache_dir};

    let config_path = RunnerConfig::default_path().context("no HOME for config path")?;
    let env_path = default_env_path().context("no HOME for env path")?;
    let report = run_init(&InitOptions {
        org,
        repo,
        token,
        config_path,
        env_path,
        cache_dir: resolve_cache_dir(&config.cache),
    })
    .map_err(|e| anyhow::anyhow!(e))?;
    print!("{}", runner_cli::init::render_report(&report));
    Ok(())
}

fn cmd_auth_github(token: Option<String>) -> Result<()> {
    use runner_core::auth::{ProviderSlot, TokenStore};

    let token = match token {
        Some(value) => value,
        None => {
            eprint!("GitHub token: ");
            use std::io::Write;
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    if token.trim().is_empty() {
        anyhow::bail!("no token provided; aborting (nothing written)");
    }
    let store = TokenStore::default_store().context("no HOME for secrets file")?;
    let path = store.set_token(ProviderSlot::Github, token.trim())?;
    println!(
        "github token stored in {} (0600); restart the daemon to apply",
        path.display()
    );
    Ok(())
}

fn prompt_secret(label: &str) -> Result<String> {
    eprint!("{label}: ");
    use std::io::Write;
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn cmd_auth_gitlab(token: Option<String>) -> Result<()> {
    use runner_core::auth::{ProviderSlot, TokenStore};

    let token = match token {
        Some(value) => value,
        None => prompt_secret("GitLab runner token")?,
    };
    if token.trim().is_empty() {
        anyhow::bail!("no token provided; aborting (nothing written)");
    }
    let store = TokenStore::default_store().context("no HOME for secrets file")?;
    let path = store.set_token(ProviderSlot::Gitlab, token.trim())?;
    println!(
        "gitlab token stored in {} (0600); restart the daemon to apply",
        path.display()
    );
    Ok(())
}

fn cmd_auth_status() -> Result<()> {
    use runner_core::auth::{ProviderSlot, TokenStore};

    let Some(store) = TokenStore::default_store() else {
        println!("no HOME for secrets file; no credentials configured");
        return Ok(());
    };
    println!("credentials: {}", store.path().display());
    for (label, slot) in [
        ("github", ProviderSlot::Github),
        ("gitlab", ProviderSlot::Gitlab),
        ("bitbucket client id", ProviderSlot::BitbucketClientId),
        (
            "bitbucket client secret",
            ProviderSlot::BitbucketClientSecret,
        ),
    ] {
        match store.masked_token(slot) {
            Some(masked) => println!("  {label:<24} {masked}"),
            None => println!("  {label:<24} not configured"),
        }
    }
    Ok(())
}

fn cmd_auth_bitbucket(client_id: Option<String>, client_secret: Option<String>) -> Result<()> {
    use runner_core::auth::{ProviderSlot, TokenStore};

    let client_id = match client_id {
        Some(value) => value,
        None => prompt_secret("Bitbucket OAuth client id")?,
    };
    let client_secret = match client_secret {
        Some(value) => value,
        None => prompt_secret("Bitbucket OAuth client secret")?,
    };
    if client_id.trim().is_empty() || client_secret.trim().is_empty() {
        anyhow::bail!("client id and secret are both required; aborting (nothing written)");
    }
    let store = TokenStore::default_store().context("no HOME for secrets file")?;
    store.set_token(ProviderSlot::BitbucketClientId, client_id.trim())?;
    let path = store.set_token(ProviderSlot::BitbucketClientSecret, client_secret.trim())?;
    println!(
        "bitbucket credentials stored in {} (0600); restart the daemon to apply",
        path.display()
    );
    Ok(())
}

/// `runner audit verify`: report chain integrity; exit 1 on tamper.
fn cmd_audit_verify(file: Option<std::path::PathBuf>) -> Result<()> {
    use runner_core::config::{effective_mode, ProfileMode};
    use runner_enterprise::audit::{default_audit_path, verify_file};

    match effective_mode() {
        ProfileMode::Local => println!("mode: community (local) — enterprise extensions dormant"),
        ProfileMode::Enterprise => println!("mode: enterprise"),
    }
    let path = match file {
        Some(path) => path,
        None => default_audit_path().context("no HOME for audit path")?,
    };
    let outcome = verify_file(&path);
    println!("{}", outcome.report());
    if outcome.ok() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// `runner audit export`: stream verified JSONL to stdout or a file.
/// Fails closed (exit 1, nothing written) on any chain tampering.
fn cmd_audit_export(
    file: Option<std::path::PathBuf>,
    format: &str,
    out: Option<std::path::PathBuf>,
) -> Result<()> {
    use runner_enterprise::audit::{default_audit_path, export_trail, ExportError};

    if !format.trim().eq_ignore_ascii_case("jsonl") {
        anyhow::bail!("unsupported audit export format {format:?}: only \"jsonl\"");
    }
    let path = match file {
        Some(path) => path,
        None => default_audit_path().context("no HOME for audit path")?,
    };
    match export_trail(&path) {
        Ok(jsonl) => match out {
            Some(dest) => {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dest, jsonl)?;
                println!("audit trail exported to {}", dest.display());
                Ok(())
            }
            None => {
                print!("{jsonl}");
                Ok(())
            }
        },
        Err(ExportError::Absent(path)) => {
            println!(
                "no audit trail at {} yet — nothing to export",
                path.display()
            );
            Ok(())
        }
        Err(ExportError::Tampered(reason) | ExportError::Io(reason)) => {
            // Io here means the verified file vanished mid-export: fail closed too.
            eprintln!("audit export refused: {reason}");
            std::process::exit(1);
        }
    }
}

/// `runner policy inspect`: show ceilings, gates, and air-gap status.
fn cmd_policy_inspect(config: &RunnerConfig) {
    use runner_core::config::{effective_mode, ProfileMode};
    use runner_enterprise::policy::{describe, load_or_permissive, FleetPolicy};

    match effective_mode() {
        ProfileMode::Local => println!("mode: community (local) — enterprise extensions dormant"),
        ProfileMode::Enterprise => println!("mode: enterprise"),
    }
    let (policy, note) = match runner_enterprise::policy::default_policy_path() {
        Some(path) => load_or_permissive(&path),
        None => (
            FleetPolicy::permissive(),
            "no HOME — permissive fleet defaults".to_string(),
        ),
    };
    println!("{note}");
    print!("{}", describe(&policy));
    println!(
        "air-gapped pool restriction: {}",
        if config.security.air_gapped {
            "ENFORCED (cloud bursting refused)"
        } else {
            "off"
        }
    );
}

/// `runner mcp install`: register the stdio server in an agent config,
/// or print the JSON snippet when the destination is unwritable.
fn cmd_mcp_install(target: &str) -> Result<()> {
    use runner_core::mcp::install::{
        current_exe_string, default_target_path, install_to_file, snippet_json, McpTarget,
    };

    let target = McpTarget::from_name(target).map_err(|e| anyhow::anyhow!(e))?;
    let exe = current_exe_string();
    let path = default_target_path(target);
    match path {
        Some(path) => match install_to_file(&path, &exe) {
            Ok(note) => {
                println!("{note}");
                println!("target: {}", target.name());
                Ok(())
            }
            Err(e) => {
                eprintln!("runner mcp install: {e}; printing snippet instead");
                println!("{}", snippet_json(&exe));
                Ok(())
            }
        },
        None => {
            println!("{}", snippet_json(&exe));
            Ok(())
        }
    }
}

/// `runner doctor`: print the readiness report; exit 1 on any failure.
async fn cmd_doctor(
    config: &RunnerConfig,
    enterprise: bool,
    egress: bool,
    format: &str,
    strict: bool,
) -> Result<()> {
    use runner_cli::doctor::{apply_strict, overall_ok, render_json, render_text, run_all};

    let strict = runner_core::config::is_strict(strict, config);
    if strict {
        eprintln!("[runner doctor] strict mode active: warnings treated as fatal errors");
    }
    let mut checks = run_all(config, enterprise, egress).await;
    if strict {
        // Fail-closed guardrails: sandbox defenses must be proven
        // present, not merely warned about.
        apply_strict(&mut checks);
    }
    match format.trim().to_ascii_lowercase().as_str() {
        "text" => print!("{}", render_text(&checks)),
        "json" => println!("{}", render_json(&checks)),
        other => anyhow::bail!("unsupported doctor format {other:?}: want text|json"),
    }
    if overall_ok(&checks) {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// `runner provider test`: print the connectivity verdict; exit 1 on failure.
async fn cmd_provider_test(provider: &str, config: &RunnerConfig) -> Result<()> {
    use runner_cli::provider::{render, test_provider, ProviderName};

    let name = ProviderName::from_name(provider).map_err(|e| anyhow::anyhow!(e))?;
    let report = test_provider(name, config).await;
    print!("{}", render(&report));
    if report.ok {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// `runner hook install`: write the managed pre-commit hook.
fn cmd_hook_install(cmd: Option<&str>) -> Result<()> {
    use runner_cli::hook::{detect_command, install};

    let cwd = std::env::current_dir().context("cannot resolve working directory")?;
    let command = match cmd {
        Some(explicit) => explicit.to_string(),
        None => detect_command(&cwd).ok_or_else(|| {
            anyhow::anyhow!("no check command detected; pass --cmd \"<COMMAND>\"")
        })?,
    };
    let path = install(&cwd, &command).map_err(|e| anyhow::anyhow!(e))?;
    println!(
        "hook installed: {} (runs `{command}` via runner exec)",
        path.display()
    );
    Ok(())
}

/// Current Unix epoch seconds (cloud uptime math).
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Call one daemon method, mapping transport + RPC errors to anyhow.
async fn daemon_call(method: &str, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
    let sock = resolve_sock_path();
    let res = ipc_call_with(&sock, method, params)
        .await
        .map_err(|_| anyhow::anyhow!("daemon not reachable at {}", sock.display()))?;
    if let Some(message) = runner_cli::cloud::daemon_error(&res) {
        anyhow::bail!("daemon error: {message}");
    }
    Ok(res["result"].clone())
}

/// `runner throttle`: engage a timed governor weight override on the
/// daemon. Text-only output (no JSON contract to freeze).
async fn cmd_throttle(level: &str, duration: u64) -> Result<()> {
    if duration == 0 {
        anyhow::bail!("duration must be > 0 minutes");
    }
    let result = daemon_call(
        "throttle_set",
        Some(serde_json::json!({ "level": level, "duration_minutes": duration })),
    )
    .await?;
    println!(
        "throttle {} engaged: cpu weight {} for {} minutes",
        result["level"].as_str().unwrap_or(level),
        result["cpu_weight"].as_u64().unwrap_or(0),
        result["duration_minutes"].as_u64().unwrap_or(duration),
    );
    Ok(())
}

/// `runner cloud list`: active burst workers with uptime + spend cap.
async fn cmd_cloud_list(format: &str) -> Result<()> {
    use runner_cli::cloud::{parse_list, render_list_json, render_list_text};

    let result = daemon_call("cloud_list", None).await?;
    let list = parse_list(&result, now_epoch_secs());
    match format.trim().to_ascii_lowercase().as_str() {
        "text" => print!("{}", render_list_text(&list)),
        "json" => println!("{}", render_list_json(&list)),
        other => anyhow::bail!("unsupported cloud list format {other:?}: want text|json"),
    }
    Ok(())
}

/// `runner cloud terminate`: destroy one worker by instance id.
async fn cmd_cloud_terminate(instance_id: &str) -> Result<()> {
    let result = daemon_call(
        "cloud_terminate",
        Some(serde_json::json!({ "instance_id": instance_id })),
    )
    .await?;
    println!(
        "terminated {}",
        result["terminated"].as_str().unwrap_or(instance_id)
    );
    Ok(())
}

/// `runner cloud purge`: destroy every tracked worker immediately.
async fn cmd_cloud_purge() -> Result<()> {
    let result = daemon_call("cloud_purge", None).await?;
    let purged = result["purged"].as_array().cloned().unwrap_or_default();
    let failed = result["failed"].as_array().cloned().unwrap_or_default();
    println!("purged {} node(s)", purged.len());
    for failure in &failed {
        eprintln!("failed: {failure}");
    }
    if !failed.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// `runner cache stats`: entries, size, hits, misses, bandwidth saved.
async fn cmd_cache_stats(format: &str) -> Result<()> {
    use runner_cli::cache::{parse_stats, render_stats_json, render_stats_text};

    let result = daemon_call("cache_stats", None).await?;
    let stats = parse_stats(&result);
    match format.trim().to_ascii_lowercase().as_str() {
        "text" => print!("{}", render_stats_text(&stats)),
        "json" => println!("{}", render_stats_json(&stats)),
        other => anyhow::bail!("unsupported cache stats format {other:?}: want text|json"),
    }
    Ok(())
}

/// `runner cache clear`: purge archives (all or idle longer than N days).
async fn cmd_cache_clear(all: bool, older_than: Option<u64>) -> Result<()> {
    if !all && older_than.is_none() {
        anyhow::bail!("pass --all or --older-than <days>");
    }
    let result = daemon_call(
        "cache_clear",
        Some(serde_json::json!({ "all": all, "older_than_days": older_than })),
    )
    .await?;
    println!(
        "cleared {} entries ({} freed)",
        result["removed"].as_u64().unwrap_or(0),
        runner_cli::cache::format_bytes(result["freed_bytes"].as_u64().unwrap_or(0)),
    );
    Ok(())
}

/// `runner hook uninstall`: remove the managed hook, restore backup.
fn cmd_hook_uninstall() -> Result<()> {
    use runner_cli::hook::uninstall;

    let cwd = std::env::current_dir().context("cannot resolve working directory")?;
    match uninstall(&cwd).map_err(|e| anyhow::anyhow!(e))? {
        Some(restored) => println!("hook removed; restored {}", restored.display()),
        None => println!("hook removed"),
    }
    Ok(())
}

/// `runner exec --driver microvm`: route through the Tier-1 engine.
/// Kernel/rootfs come from the sandbox config; exits nonzero with a clean
/// message when KVM, images, or the Firecracker binary are unavailable.
async fn cmd_exec_microvm(config: &RunnerConfig, command: &[String], timeout: std::time::Duration) {
    use runner_sandbox::driver::{SandboxDriver, SandboxEngine};
    use runner_sandbox::microvm::MicroVmConfig;

    let (Some(kernel), Some(rootfs)) = (
        config.sandbox.kernel_path.clone(),
        config.sandbox.rootfs_path.clone(),
    ) else {
        eprintln!("runner exec failed: microvm tier needs sandbox.kernel_path and sandbox.rootfs_path in config");
        std::process::exit(1);
    };
    let tag = format!("exec-{}", std::process::id());
    let socket = std::env::temp_dir().join(format!("firecracker-{tag}.sock"));
    let vsock = std::env::temp_dir().join(format!("fc-vsock-{tag}.sock"));
    let bin = config
        .sandbox
        .firecracker_bin
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("firecracker"));
    let engine = SandboxEngine::new(SandboxDriver::MicroVm)
        .with_microvm(MicroVmConfig::new(socket, kernel, rootfs, vsock), bin);
    match engine.execute(command, timeout).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("runner exec failed: {e}");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load ~/.config/runner/env first so every subcommand sees configured
    // secrets without the user sourcing the file in shell.
    let _ = load_env_file();
    let cli = Cli::parse();
    let config = RunnerConfig::load_or_default();
    match cli.command {
        Commands::Init { org, repo, token } => {
            cmd_init(&config, org, repo, token)?;
        }
        Commands::Start { daemon, strict } => {
            let strict = runner_core::config::is_strict(strict, &config);
            // Fail-closed boot: a strict daemon refuses to supervise
            // workers it cannot sandbox.
            #[cfg(target_os = "macos")]
            let tier2 = runner_sandbox::seatbelt::probe_seatbelt();
            #[cfg(target_os = "linux")]
            let tier2 = runner_sandbox::mounts::probe_userns();
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            let tier2 = false;
            if strict && !tier2 {
                eprintln!(
                    "runner start failed: sandbox unavailable: \
                     --strict refuses to supervise unsandboxed workers"
                );
                std::process::exit(1);
            }
            if daemon {
                eprintln!("runner: --daemon accepted; launch under systemd/setsid to detach");
            }
            let state = new_shared_state();
            state.write().await.seed_from_config(&config);
            let sock_path = resolve_sock_path();
            match IpcServer::bind(&sock_path, state.clone()).await {
                Ok(server) => {
                    eprintln!("runner: ipc listening on {}", server.path().display());
                    let server = Arc::new(server);
                    tokio::spawn(async move {
                        if let Err(e) = server.serve().await {
                            eprintln!("runner: ipc server exited: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("runner: ipc unavailable ({e}); continuing without socket");
                }
            }
            // LAN cache proxy: bind synchronously so dispatch knows
            // whether worker injection is safe; failure degrades to
            // upstream caching without affecting the daemon.
            {
                use runner_core::cache::server::{public_base_url, serve_on, CacheServerState};
                use runner_core::cache::store::CacheStore;
                let dir = runner_core::config::resolve_cache_dir(&config.cache);
                let max_bytes = config.cache.max_size_gb.saturating_mul(1024 * 1024 * 1024);
                match CacheStore::open(&dir, max_bytes) {
                    Ok(store) => match tokio::net::TcpListener::bind(&config.cache.listen).await {
                        Ok(listener) => {
                            let port = listener.local_addr().map(|a| a.port()).unwrap_or(8787);
                            let base = public_base_url(&config.cache.listen, port);
                            let server_state = CacheServerState::new(store, base.clone());
                            state.write().await.set_cache(server_state.clone());
                            eprintln!(
                                "runner: cache proxy on {} (advertised {base})",
                                config.cache.listen
                            );
                            // Background TTL sweep (creation-age eviction).
                            if server_state
                                .store
                                .spawn_ttl_sweeper(config.cache.ttl_secs, config.cache.sweep_secs)
                                .is_some()
                            {
                                eprintln!(
                                    "runner: cache TTL sweep every {}s (ttl {}s)",
                                    config.cache.sweep_secs.max(60),
                                    config.cache.ttl_secs
                                );
                            }
                            // LAN federation: advertise cache capability via
                            // mDNS when bound beyond loopback.
                            if runner_core::mesh::discovery::listen_is_lan(&config.cache.listen) {
                                match runner_core::mesh::discovery::primary_lan_ip() {
                                    Some(ip) => {
                                        let node_id =
                                            runner_core::mesh::discovery::generate_node_id();
                                        let token = server_state.token.clone();
                                        let state = state.clone();
                                        tokio::spawn(async move {
                                            runner_core::mesh::discovery::LanDiscovery::advertise_loop(
                                                state, node_id, ip, port, token,
                                            )
                                            .await;
                                        });
                                    }
                                    None => eprintln!(
                                        "runner: no LAN address; skipping mDNS advertisement"
                                    ),
                                }
                            }
                            tokio::spawn(async move {
                                if let Err(e) = serve_on(listener, server_state).await {
                                    eprintln!("runner: cache proxy exited: {e}");
                                }
                            });
                        }
                        Err(e) => eprintln!(
                            "runner: cache proxy unavailable ({e}); workers use upstream caching"
                        ),
                    },
                    Err(e) => eprintln!(
                        "runner: cache store unavailable ({e}); workers use upstream caching"
                    ),
                }
            }
            let pid_path = resolve_pid_path();
            if let Err(e) = write_current_pid(&pid_path) {
                eprintln!("runner: pid file unavailable ({e})");
            }
            // WAN federation identity (persisted once when generated;
            // untouched otherwise so daemon boots never rewrite config).
            let mut mesh_config = config.clone();
            let mut mesh_changed = false;
            if mesh_config.mesh.secret.is_none() {
                mesh_config.mesh.secret = Some(generate_secret_hex());
                mesh_changed = true;
            }
            let had_key = mesh_config.mesh.node_key.is_some();
            match runner_core::mesh::peer::ensure_node_keypair(&mut mesh_config) {
                Ok(_) => {
                    mesh_changed |= !had_key;
                }
                Err(e) => {
                    eprintln!("runner: mesh identity unavailable ({e}); WAN federation off");
                }
            }
            if mesh_changed {
                if let Err(e) = mesh_config.save() {
                    eprintln!("runner: failed to save mesh identity ({e}); WAN federation off");
                }
            }
            runner_cli::coordinator::spawn_peer_transport(&mesh_config, state.clone()).await;
            spawn_coordinator(&config, state.clone()).await;
            spawn_embedded_listener(&config, state.clone()).await;
            run_supervisor(state).await?;
            remove_pidfile(&pid_path);
        }
        Commands::Stop { force, .. } => {
            cmd_stop(force)?;
        }
        Commands::Status { format } => {
            let report = status_report();
            if format == "json" {
                // Prefer the daemon's state-enriched report (per-forge
                // health included); fall back to a local kernel read.
                let sock_path = resolve_sock_path();
                match ipc_call(&sock_path, "status").await {
                    Ok(resp) if resp.get("result").is_some() => {
                        println!("{}", serde_json::to_string_pretty(&resp["result"])?);
                    }
                    _ => println!("{}", serde_json::to_string_pretty(&report)?),
                }
            } else {
                let temp = report
                    .host
                    .temperature_c
                    .map(|t| format!("{t:.1}°C"))
                    .unwrap_or_else(|| "n/a".to_string());
                let power = if report.host.discharging {
                    "battery"
                } else {
                    "AC"
                };
                // Prefer the daemon's live AFK latch; local read otherwise.
                let (afk_boost, afk_mode) = match ipc_call(&resolve_sock_path(), "snapshot").await {
                    Ok(resp) => (
                        resp["result"]["afk_boosted"].as_bool().unwrap_or(false),
                        resp["result"]["afk_mode"]
                            .as_str()
                            .unwrap_or("auto")
                            .to_string(),
                    ),
                    _ => (
                        report.concurrency.afk_boost,
                        report.concurrency.afk_mode.clone(),
                    ),
                };
                let afk = if afk_boost {
                    format!("BOOSTED ({afk_mode})")
                } else {
                    afk_mode
                };
                println!(
                    "runner {} | cores {}/{} | mem {}MB avail | cpu PSI {:.2}% ({:?}) | slots {} | weight {:?} | temp {} | power {} | afk {}",
                    report.status,
                    report.host.total_cores,
                    report.host.physical_cores,
                    report.host.available_memory_bytes / 1024 / 1024,
                    report.host.psi_pressure.cpu_some_avg10,
                    report.host.psi_pressure.cpu_level,
                    report.concurrency.max_slots,
                    report.host.cgroup_weight,
                    temp,
                    power,
                    afk,
                );
            }
        }
        Commands::Mcp { transport, command } => {
            if let Some(McpCommands::Install { target }) = command {
                cmd_mcp_install(&target)?;
                return Ok(());
            }
            if transport != "stdio" {
                anyhow::bail!("unsupported mcp transport {transport:?}: only \"stdio\"");
            }
            let state = new_shared_state();
            state.write().await.seed_from_config(&config);
            let agent = Arc::new(runner_cli::agent::CliAgentTools::new(config.clone()));
            let server = McpServer::new(ToolContext::new(state, config).with_agent(agent));
            server.serve_stdio().await?;
        }
        Commands::Server {
            listen,
            oidc_issuer,
            client_id,
            client_secret,
        } => {
            use runner_enterprise::control_plane::auth::{OidcConfig, OidcManager, SessionStore};
            use runner_enterprise::control_plane::fleet::FleetRegistry;
            use runner_enterprise::control_plane::server::{serve_on, AppState};
            let oidc = match (oidc_issuer, client_id, client_secret) {
                (Some(issuer), Some(id), Some(secret)) => {
                    eprintln!("runner: OIDC SSO enabled (issuer {issuer})");
                    Some(OidcManager::new(OidcConfig {
                        issuer_url: issuer.clone(),
                        client_id: id,
                        client_secret: secret,
                        redirect_uri: format!("http://{listen}/auth/callback"),
                    }))
                }
                (None, None, None) => {
                    eprintln!("runner: OIDC disabled; fleet API only");
                    None
                }
                _ => anyhow::bail!("OIDC needs all of --oidc-issuer, --client-id, --client-secret"),
            };
            let state = AppState::new(
                FleetRegistry::new(),
                SessionStore::new(std::time::Duration::from_secs(3600)),
                oidc,
            );
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            eprintln!("runner: control plane listening on {listen}");
            serve_on(listener, state).await?;
        }
        Commands::Mesh { command } => match command {
            MeshCommands::Invite {
                role,
                max_cores,
                max_ram,
                ttl,
                name,
            } => {
                cmd_mesh_invite(&role, max_cores, &max_ram, &ttl, &name)?;
            }
            MeshCommands::List { format, lan } => {
                cmd_mesh_list(&format, lan).await?;
            }
        },
        Commands::Join {
            token,
            coordinator,
            coordinator_pubkey,
        } => {
            cmd_join(&token, &coordinator, &coordinator_pubkey).await?;
        }
        Commands::Service { command } => match command {
            ServiceCommands::Install => runner_cli::service::install()?,
            ServiceCommands::Status => runner_cli::service::status()?,
            ServiceCommands::Stop => runner_cli::service::stop()?,
            ServiceCommands::Start => runner_cli::service::start()?,
            ServiceCommands::Uninstall => runner_cli::service::uninstall()?,
        },
        Commands::Auth { command } => match command {
            AuthCommands::Github { token } => cmd_auth_github(token)?,
            AuthCommands::Gitlab { token } => cmd_auth_gitlab(token)?,
            AuthCommands::Bitbucket {
                client_id,
                client_secret,
            } => cmd_auth_bitbucket(client_id, client_secret)?,
            AuthCommands::Status => cmd_auth_status()?,
        },
        Commands::Audit { command } => match command {
            AuditCommands::Verify { file } => cmd_audit_verify(file)?,
            AuditCommands::Export { file, format, out } => cmd_audit_export(file, &format, out)?,
        },
        Commands::Policy { command } => match command {
            PolicyCommands::Inspect => cmd_policy_inspect(&config),
        },
        Commands::Top { interval_ms, once } => {
            runner_cli::top::run(&resolve_sock_path(), interval_ms, once).await?;
        }
        Commands::Listen { port, secret } => {
            cmd_listen(port, secret).await?;
        }
        Commands::Throttle { level, duration } => {
            cmd_throttle(&level, duration).await?;
        }
        Commands::Doctor {
            enterprise,
            egress,
            format,
            strict,
        } => {
            cmd_doctor(&config, enterprise, egress, &format, strict).await?;
        }
        Commands::Provider { command } => match command {
            ProviderCommands::Test { provider } => {
                cmd_provider_test(&provider, &config).await?;
            }
        },
        Commands::Hook { command } => match command {
            HookCommands::Install { cmd } => {
                cmd_hook_install(cmd.as_deref())?;
            }
            HookCommands::Uninstall => {
                cmd_hook_uninstall()?;
            }
        },
        Commands::Cloud { command } => match command {
            CloudCommands::List { format } => {
                cmd_cloud_list(&format).await?;
            }
            CloudCommands::Terminate { instance_id } => {
                cmd_cloud_terminate(&instance_id).await?;
            }
            CloudCommands::Purge => {
                cmd_cloud_purge().await?;
            }
        },
        Commands::Cache { command } => match command {
            CacheCommands::Stats { format } => {
                cmd_cache_stats(&format).await?;
            }
            CacheCommands::Clear { all, older_than } => {
                cmd_cache_clear(all, older_than).await?;
            }
        },
        Commands::Exec {
            command,
            no_sandbox,
            timeout_mins,
            driver,
            strict,
        } => {
            let timeout = std::time::Duration::from_secs(timeout_mins.max(1) * 60);
            let strict = runner_core::config::is_strict(strict, &config);
            let tier = match runner_sandbox::driver::SandboxDriver::from_name(&driver) {
                Ok(tier) => tier,
                Err(e) => {
                    eprintln!("runner exec failed: {e}");
                    std::process::exit(1);
                }
            };
            if tier == runner_sandbox::driver::SandboxDriver::MicroVm {
                cmd_exec_microvm(&config, &command, timeout).await;
                return Ok(());
            }
            match runner_providers::providers::local::execute_local_sandboxed(
                &command, no_sandbox, timeout, strict,
            )
            .await
            {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("runner exec failed: {e:#}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn root_version_flags_print_runner_version() {
        for flag in ["--version", "-V"] {
            let err = Cli::command()
                .try_get_matches_from(["runner", flag])
                .unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
            let rendered = err.render().to_string();
            assert!(
                rendered.contains(&format!("runner {}", env!("CARGO_PKG_VERSION"))),
                "unexpected version output: {rendered}"
            );
        }
    }
}
