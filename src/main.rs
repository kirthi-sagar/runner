//! `runner` CLI entrypoint: host supervisor controls for humans and agents.

use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};

use runner::config::{DonorConfig, PeerRecord, RunnerConfig, github_token_from_env};
use runner::github::client::GithubClient;
use runner::github::webhooks::{DispatchContext, JitScope, QueuePoller, run_coordinator};
use runner::governor::cgroup::CgroupSlice;
use runner::governor::supervisor::{new_shared_state, run_supervisor};
use runner::mesh::cloud::CloudPool;
use runner::ipc::{IpcServer, ipc_call, ipc_call_with, resolve_sock_path};
use runner::mcp::server::McpServer;
use runner::mcp::tools::ToolContext;
use runner::mesh::invite::{
    InviteAuthority, InviteCaps, InviteRole, InviteToken, generate_secret_hex, parse_size_mb,
    parse_ttl_secs, secret_from_hex,
};
use runner::mesh::peer::{DEFAULT_KEEPALIVE_SECS, generate_keypair, render_config};
use runner::pidfile::{
    process_alive, read_pid, remove as remove_pidfile, resolve_pid_path, signal_daemon,
    wait_for_exit, write_current_pid,
};
use runner::status::status_report;

#[derive(Debug, Parser)]
#[command(name = "runner", about = "Zero-freeze GitHub Actions runner supervisor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize host configuration
    Init {
        #[arg(long)]
        org: Option<String>,
    },
    /// Start the coordinator daemon (governor loop + IPC socket)
    Start {
        /// Run detached in the background (accepted; launch under
        /// systemd/setsid to detach).
        #[arg(long)]
        daemon: bool,
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
    },
    /// Federated mesh controls
    Mesh {
        #[command(subcommand)]
        command: MeshCommands,
    },
    /// Join a mesh with an invitation token
    Join {
        token: String,
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

/// Load the mesh signing authority, generating + persisting a secret once.
fn invite_authority(config: &mut RunnerConfig) -> Result<InviteAuthority, String> {
    if config.mesh.secret.is_none() {
        config.mesh.secret = Some(generate_secret_hex());
        config.save().map_err(|e| format!("failed to save mesh secret: {e}"))?;
    }
    let hex = config.mesh.secret.clone().unwrap_or_default();
    InviteAuthority::new(secret_from_hex(&hex)?)
}

fn cmd_mesh_invite(
    role: &str,
    max_cores: u32,
    max_ram: &str,
    ttl: &str,
    name: &str,
) -> Result<()> {
    let mut config = RunnerConfig::load_or_default();
    let authority = invite_authority(&mut config).map_err(|e| anyhow::anyhow!(e))?;
    let token = InviteToken {
        role: role.parse::<InviteRole>().map_err(|e| anyhow::anyhow!(e))?,
        caps: InviteCaps { max_cores, max_ram_mb: parse_size_mb(max_ram).map_err(|e| anyhow::anyhow!(e))? },
        ttl_secs: parse_ttl_secs(ttl).map_err(|e| anyhow::anyhow!(e))?,
        name: name.to_string(),
    };
    let minted = authority.mint(&token).map_err(|e| anyhow::anyhow!(e))?;
    println!("{minted}");
    eprintln!("invite for {name}: role={role} cores={max_cores} ram={max_ram} ttl={ttl}");
    Ok(())
}

async fn cmd_join(token: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let payload = InviteAuthority::decode_unverified(token).map_err(|e| anyhow::anyhow!(e))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if now >= payload.expires_at {
        anyhow::bail!("invitation token has expired");
    }
    // This host donates *up to* the token caps: persist them so the local
    // supervisor (cgroups weight ladder + AFK boost + slot clamp) enforces
    // donor safety for every foreign job.
    let keys = generate_keypair();
    let node_id = format!("{}-{}", payload.name, &keys.public_b64[..8.min(keys.public_b64.len())]);
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
    println!("joined as {node_id} (donor caps: {} cores, {}MB ram)",
        payload.max_cores, payload.max_ram_mb);
    println!("--- wireguard identity (send PublicKey to the coordinator) ---");
    println!("{}", render_config(
        &keys.private_b64,
        "<coordinator-pubkey>",
        &["10.9.0.0/24"],
        None,
        DEFAULT_KEEPALIVE_SECS,
    ));
    println!("public key: {}", keys.public_b64);
    Ok(())
}

async fn cmd_mesh_list(format: &str, lan: bool) -> Result<()> {
    if lan {
        let nodes = runner::mesh::discovery::LanDiscovery::browse_only(
            std::time::Duration::from_secs(2),
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        if format == "json" {
            println!("{}", serde_json::to_string_pretty(
                &nodes.iter().map(|n| serde_json::json!({
                    "instance": n.instance, "host": n.host, "port": n.port,
                    "addrs": n.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    "metrics": n.metrics.as_ref().map(|m| serde_json::json!({
                        "cores": m.cores, "ram_mb": m.ram_mb, "slots": m.slots,
                    })),
                })).collect::<Vec<_>>()
            )?);
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
        let cloud = result["cloud_nodes"].as_array().cloned().unwrap_or_default();
        println!("wan peers: {}", peers.len());
        for peer in &peers {
            println!("  - {} [{}]", peer["node_id"], peer["status"]);
        }
        println!("cloud nodes: {}", cloud.len());
        for node in &cloud {
            println!("  - {} ({}) [{}]", node["id"], node["provider"], node["status"]);
        }
    }
    Ok(())
}

/// Spawn the coordinator poll loop when a repo + token are configured.
/// Without them the daemon runs governor-only.
fn spawn_coordinator(config: &RunnerConfig, state: runner::governor::supervisor::SharedState) {
    let coord = &config.coordinator;
    let (Some(owner), Some(repo)) = (coord.repo_owner.clone(), coord.repo_name.clone()) else {
        eprintln!("runner: no coordinator repo configured; governor-only mode");
        return;
    };
    let Some(token) = github_token_from_env() else {
        eprintln!("runner: RUNNER_GITHUB_TOKEN unset; governor-only mode");
        return;
    };
    let github = match GithubClient::new(token) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("runner: github client: {e}");
            return;
        }
    };
    let poller = QueuePoller::new(github.clone(), owner, repo)
        .with_interval(std::time::Duration::from_secs(coord.poll_secs.max(5)));
    let scope = match config.org.clone() {
        Some(org) => JitScope::Org { org },
        None => JitScope::Repo {
            owner: coord.repo_owner.clone().unwrap_or_default(),
            repo: coord.repo_name.clone().unwrap_or_default(),
        },
    };
    let dispatch = coord.auto_dispatch.then(|| DispatchContext {
        github,
        scope,
        runner_group_id: coord.runner_group_id,
        worker_version: coord.worker_version.clone(),
        sandboxed: runner::sandbox::mounts::probe_userns(),
        timeout: std::time::Duration::from_secs(coord.job_timeout_mins * 60),
    });
    if dispatch.as_ref().is_some_and(|d| !d.sandboxed) {
        eprintln!("runner: unprivileged userns blocked; dispatches run unsandboxed");
    }
    let cloud = (config.cloud.max_monthly_spend > 0.0).then(|| CloudPool::from_config(config));
    tokio::spawn(run_coordinator(
        poller,
        dispatch,
        cloud,
        state,
        CgroupSlice::system_default(),
    ));
}

fn cmd_stop(force: bool) -> Result<()> {
    let pid_path = resolve_pid_path();
    let sock_path = resolve_sock_path();
    let pid = match read_pid(&pid_path) {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!("no pid file at {}; removing stale socket (if any)", pid_path.display());
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
    eprintln!("sent {} to daemon pid {pid}", if force { "SIGKILL" } else { "SIGTERM" });
    if !force && !wait_for_exit(pid, std::time::Duration::from_secs(10)) {
        anyhow::bail!("daemon pid {pid} did not exit in 10s; retry with --force");
    }
    remove_pidfile(&pid_path);
    let _ = std::fs::remove_file(&sock_path);
    eprintln!("daemon stopped; socket and pid file cleaned");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = RunnerConfig::load_or_default();
    match cli.command {
        Commands::Init { org } => {
            println!("runner init: org={org:?} (prints only, no writes yet)");
        }
        Commands::Start { daemon } => {
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
            let pid_path = resolve_pid_path();
            if let Err(e) = write_current_pid(&pid_path) {
                eprintln!("runner: pid file unavailable ({e})");
            }
            spawn_coordinator(&config, state.clone());
            run_supervisor(state).await?;
            remove_pidfile(&pid_path);
        }
        Commands::Stop { force, .. } => {
            cmd_stop(force)?;
        }
        Commands::Status { format } => {
            let report = status_report();
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "runner {} | cores {}/{} | mem {}MB avail | cpu PSI {:.2}% ({:?}) | slots {} | weight {:?}",
                    report.status,
                    report.host.total_cores,
                    report.host.physical_cores,
                    report.host.available_memory_bytes / 1024 / 1024,
                    report.host.psi_pressure.cpu_some_avg10,
                    report.host.psi_pressure.cpu_level,
                    report.concurrency.max_slots,
                    report.host.cgroup_weight,
                );
            }
        }
        Commands::Mcp { transport } => {
            if transport != "stdio" {
                anyhow::bail!("unsupported mcp transport {transport:?}: only \"stdio\"");
            }
            let state = new_shared_state();
            state.write().await.seed_from_config(&config);
            let server = McpServer::new(ToolContext::new(state, config));
            server.serve_stdio().await?;
        }
        Commands::Mesh { command } => match command {
            MeshCommands::Invite { role, max_cores, max_ram, ttl, name } => {
                cmd_mesh_invite(&role, max_cores, &max_ram, &ttl, &name)?;
            }
            MeshCommands::List { format, lan } => {
                cmd_mesh_list(&format, lan).await?;
            }
        },
        Commands::Join { token } => {
            cmd_join(&token).await?;
        }
        Commands::Exec { command, no_sandbox, timeout_mins } => {
            let timeout = std::time::Duration::from_secs(timeout_mins.max(1) * 60);
            match runner::providers::local::execute_local_sandboxed(&command, no_sandbox, timeout)
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
