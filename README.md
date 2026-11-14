# runner
### High-Performance, Zero-Freeze, AI-Agent-Native Local & Federated GitHub Actions Runner Mesh

> **Status**: Architectural Specification & Implementation Guide (Revision 4)  
> **Target Audience**: Autonomous AI Coding Agents (Codex CLI, Antigravity, Muse CLI, Claude Code), Solo Developers, and Teams with Workstations, Spare PCs, Connected Peers, and Cloud Credits.  
> **Notice**: This repository contains the system architecture specification and builder prompts only. No build steps, binaries, or code compilations are executed here.

---

## 1. Executive Summary

Modern software development with autonomous AI coding agents (such as Codex in terminal, Antigravity, and VS Code agents) generates rapid commit-and-PR cycles. When running comprehensive multi-job test suites (e.g. parallel multi-database backends, linting, unit tests, frontend builds, and security scans), commercial cloud CI minutes disappear almost immediately:

- **GitHub Actions free tier**: 2,000 minutes/month pooled across all repositories in an organization.
- **Blacksmith.sh free tier**: 3,000 minutes/month, rapidly depleted by 4–6 parallel jobs per PR.
- **Trial-based alternatives (Shipfox, Tenki, Ubicloud, Puzl)**: Rely on one-time credits ($10–$100) expiring within 30 days, offering no permanent free tier.
- **Discontinued options**: DigitalOcean GitHub Student Pack credits discontinued; Travis CI student plans expired and restricted to single concurrency without GitHub Actions workflow compatibility.

Developers and autonomous agents need a way to run unlimited, zero-cost, high-parallelism CI jobs using all available computing resources:
1. **Local Workstation**: The primary computer sitting on the desk.
2. **Spare Local Computers**: Any laptops, old desktops, or mini-PCs on the local network (LAN).
3. **Trusted Peer Nodes (Friends & Family)**: Trusted peer machines connected over the internet via encrypted peer-to-peer WireGuard tunnels (with explicit consent and donor resource caps).
4. **Cloud Credit Bursting**: Ephemeral virtual machines spun up using promotional cloud credits (e.g., DigitalOcean droplets, Render.com background workers, Oracle Free Tier), configured with automated scale-to-zero when queues clear.

Existing self-hosted runners fail at this because:
1. **They freeze the host workstation**: Official runners and Docker wrappers have zero resource governors. They consume 100% of CPU and RAM, starving browsers, desktop IDEs, and terminal AI agents, often triggering Linux OOM kills.
2. **They are far too complex**: Actions Runner Controller (ARC) demands a complete Kubernetes cluster with Helm charts, cert-manager, and heavy control-plane RAM overhead (2–4 GB wasted before running a job).
3. **They are not built for AI agents**: Terminal AI agents cannot inspect, throttle, scale, or control existing runners via clean, deterministic JSON APIs or Model Context Protocol (MCP).
4. **They cannot federate peer and cloud hardware**: Pooling a trusted peer's PC (friends & family) over WAN or auto-bursting onto cloud credits requires manual server orchestration.
5. **The Custom Engine Trap**: Tools like `nektos/act` try to reimplement GitHub's proprietary runtime from scratch, creating endless compatibility drift with expressions, actions, and secrets.

**`runner`** solves this by acting as a **Host Supervisor, Federated Mesh Coordinator, and Sandbox Hypervisor** that embeds Microsoft's official `actions/runner` worker inside an unprivileged, kernel-governed sandbox across local, peer, and cloud environments.

---

## 2. Core Pillars & Architecture at a Glance

```
                                  +---------------------------------------+
                                  |         GitHub Actions Queue          |
                                  |     (Workflow Dispatch / Webhooks)    |
                                  +-------------------+-------------------+
                                                      |
                                 Webhook Notification |  Queue Polling
                                                      v
+---------------------------------------------------------------------------------------------------------+
|                                       RUNNER COORDINATOR DAEMON                                         |
|                       Super Admin: Human User  |  Admin: Autonomous AI Agent (MCP)                      |
|                                                                                                         |
|   +--------------------------------+   +--------------------------------+   +-----------------------+   |
|   |   Autonomous Agent Interface   |   |   Zero-Freeze Kernel Governor  |   | Federated Hybrid Mesh |   |
|   |  - Native MCP Server (stdio)   |   |  - Linux cgroups v2 slices     |   |  - mDNS LAN Discovery |   |
|   |  - Unix Socket: /run/runner.sock|  |  - Linux PSI Pressure Monitor  |   |  - WireGuard P2P WAN  |   |
|   |  - JSON CLI for terminal agents|   |  - CFS cpu.weight: 1 trickle   |   |  - Cloud Bursting     |   |
|   |  - AFK Boost Mode (Screen Lock)|   |  - Darwin QoS E-Core Pinning   |   |  - Dynamic Capability |   |
|   +--------------------------------+   +--------------------------------+   +-----------------------+   |
+-----------------------------------------------------+---------------------------------------------------+
                                                      |
                                 Coordinator-First JIT Dispatch Protocol
                                                      |
       +----------------------------------------------+----------------------------------------------+
       |                                              |                                              |
       v                                              v                                              v
+-----------------------------+        +-----------------------------+        +-----------------------------+
|      LOCAL WORKSTATION      |        |      TRUSTED PEER NODES     |        |     CLOUD CREDIT FLEET      |
|                             |        |      (Friends & Family)     |        |                             |
|  +-----------------------+  |        |  +-----------------------+  |        |  +-----------------------+  |
|  | Ephemeral Container   |  |        |  | Ephemeral Container   |  |        |  | Ephemeral VM / Worker |  |
|  | - Wrapped Worker      |  |        |  | - Wrapped Worker      |  |        |  | - Wrapped Worker      |  |
|  | - cgroups v2: wt 100  |  |        |  | - Donor Cap: 4 cores  |  |        |  | - DigitalOcean/Render |  |
|  | - Local Cache Mirror  |  |        |  | - Encrypted P2P Tunnel|  |        |  | - Auto Scale-to-Zero  |  |
|  +-----------------------+  |        |  +-----------------------+  |        |  +-----------------------+  |
|  Job: backend (postgres)    |        |  Job: frontend (vitest)     |        |  Job: heavy integration    |
+-----------------------------+        +-----------------------------+        +-----------------------------+
```

1. **Kernel-Enforced "Zero-Freeze" Governor with Timer-Safe Throttling**:
   - Uses Linux cgroups v2 (`cpu.weight`, `memory.high`, `memory.max`) and Pressure Stall Information (`/proc/pressure/{cpu,memory,io}`).
   - Guarantees minimum reserved headroom (e.g., 2 dedicated CPU cores and 4 GB RAM) for interactive user applications (browser, Antigravity, terminal Codex sessions).
   - Under heavy system pressure, dynamically drops runner `cpu.weight` to `1` (minimum CFS weight) and throttles `io.max`. This avoids `cgroup.freeze` timeouts, keeping database keepalives and test timers alive with trickle cycles while yielding >99% throughput to desktop apps.
   - On macOS Apple Silicon, maps to Darwin QoS (`PRIO_DARWIN_BG`), pinning CI workloads exclusively to Efficiency (E) cores while keeping Performance (P) cores 100% dedicated to user apps.

2. **First-Class Autonomous AI Agent Control & Native MCP Server**:
   - Terminal-native JSON CLI (`runner status --format=json`, `runner throttle --level=high`).
   - High-speed Unix domain socket (`/run/runner.sock`).
   - Native **Model Context Protocol (MCP)** server (`runner mcp`) enabling agents (Claude Code, Cursor, Windsurf, Codex CLI, Antigravity) to mount runner tools (`reserve_host_resources`, `get_ci_status`, `request_cloud_capacity`) directly into their context window.
   - **AFK Boost Mode**: Listens to desktop screen-lock events (`org.freedesktop.ScreenSaver` / Wayland idle notify) to automatically collapse reserved headroom to zero when the user is away, converting the workstation into a 100% dedicated build server until user input resumes.

3. **Federated Hybrid Mesh & Cloud Bursting**:
   - **Local LAN**: Connect spare PCs or Mac minis with `runner join <token>`.
   - **Trusted Peer Nodes (Friends & Family WAN)**: Connect trusted peer machines across the internet over encrypted peer-to-peer WireGuard tunnels with mutual invite tokens. Peer donors set explicit donor limits (e.g. "donate up to 4 idle cores"), ensuring foreign CI jobs never interrupt their own computer use.
   - **Cloud Bursting Connectors**: Native connectors for DigitalOcean droplets and Render.com background workers allow the fleet to absorb CI spikes using free/promotional credits. When the queue clears, cloud instances terminate automatically after 5 minutes of idle time.

4. **Dual-Tier Role-Based Governance (RBAC)**:
   - **Super Admin (Human User)**: Sovereign authority over monthly cloud credit spend caps, trusted peer invitation approvals, node revocations, and emergency kill-switches.
   - **Admin (Autonomous AI Coding Agent via MCP)**: Operational fleet manager. Inspects node capacity, routes jobs based on hardware requirements (e.g., dispatching heavy PostgreSQL suites to cloud/peers while running quick linters locally), and requests cloud scaling within pre-approved budget boundaries.

5. **Transparent LAN Caching (`ACTIONS_CACHE_URL`)**:
   - Injects `ACTIONS_CACHE_URL` pointing to `runner`'s local LAN caching daemon into standard runner environments.
   - Standard actions (`actions/cache@v4`, `actions/setup-node`, `actions/setup-python`, `Swatinem/rust-cache`) read and write cache archives over Gigabit LAN at **100–120 MB/s** with **zero workflow file edits**.

6. **100% GitHub Compatibility via Official Worker Wrapping**:
   - Embeds an ephemeral, pre-cached copy of Microsoft's official `actions/runner` worker binary inside an unprivileged container or microVM.
   - Zero divergence from GitHub Actions syntax, expressions, secrets, or composite actions, while maintaining 100% host kernel isolation and resource control.

---

## 3. Comprehensive Comparison: `runner` vs. Alternatives

| Feature / Dimension | `runner` | Official GitHub Runner | Actions Runner Controller (ARC) | `nektos/act` | Blacksmith / Ubicloud |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Cost** | **$0 / Free Forever** | $0 (Self-hosted) | $0 (Self-hosted) | $0 (Local only) | Metered ($/min after free pool) |
| **Workflow Compatibility** | **100% (Wrapped Official Worker)** | 100% (Official) | 100% (Official in k8s) | Partial (Emulation drift) | 100% (Cloud VM) |
| **Workstation Safety (Zero Lag)**| **Yes (cgroups v2 + PSI)** | No (Spikes to 100% CPU/RAM) | No (Requires dedicated node) | No (Docker consumes host) | Runs in cloud VM |
| **Test Timer Protection** | **Yes (CFS weight 1 trickle)** | N/A (Runs at 100%) | N/A (Dedicated node) | No | Managed cloud VM |
| **Autonomous AI Agent API** | **Native MCP + Unix Socket + CLI**| None | Kubernetes CRDs only | CLI flags only | Web UI / Cloud API |
| **Dual-Tier RBAC** | **Yes (Human Super Admin / AI Admin)**| None | Kubernetes RBAC | None | SaaS Team Roles |
| **Peer WAN Federation** | **Yes (WireGuard P2P Trusted Peers)**| Manual | Complex VPN / Multi-cluster | None | None |
| **Cloud Credit Bursting** | **Yes (DigitalOcean / Render auto-scale)**| None | Custom autoscalers | None | Proprietary SaaS |
| **AFK Boost Mode** | **Yes (Desktop Idle Listener)** | None | None | None | N/A |
| **Infrastructure Overhead** | **Zero (Single static binary)** | Low (Directory install) | Very High (Kubernetes cluster) | Low (Docker CLI) | Managed SaaS |
| **Distributed LAN Cache** | **Transparent (ACTIONS_CACHE_URL)**| No | Optional (MinIO / S3 setup) | Local Docker volume only | Cloud cache |
| **macOS Apple Silicon Support** | **Darwin QoS (E-Core Pinning)** | Unmanaged | Not supported | Local Docker (Rosetta/arm) | Metered cloud |

---

## 4. Documentation Navigation

- **Agent Instructions**: [`AGENTS.md`](file:///home/linux/runner/AGENTS.md)
  - Build/test/run directives and coding conventions for autonomous agents.
- **Detailed Architectural Specification**: [`AI_AGENT_RUNNER_SPECIFICATION.md`](file:///home/linux/runner/AI_AGENT_RUNNER_SPECIFICATION.md)
  - Section 1: Detailed Market & Technology Failure Analysis
  - Section 2: Architectural Deep Dive & The Wrapped Worker Paradigm
  - Section 3: Pillar 1 — The Zero-Freeze Linux Resource Governor & Timer Safety
  - Section 3.6: Deep Dive — CPU Core & Thread Topology (4c/4t vs. 4c/8t, SMT Scheduling, and `nproc` Clamping)
  - Section 4: Pillar 2 — Autonomous AI Agent Interface, MCP Server & Diagnostics
  - Section 4.5: Deep Dive — Dual-Tier Governance & RBAC Model (Super Admin vs. AI Admin)
  - Section 5: Pillar 3 — Multi-PC LAN Mesh, Coordinator-First JIT & Caching
  - Section 5.5: Deep Dive — The Federated Hybrid Mesh (Trusted Peers & Cloud Credit Bursting)
  - Section 6: Pillar 4 — Ephemeral Sandboxing, Service Containers & Security
  - Section 6.3: Deep Dive — Tiered Virtualization Matrix (Firecracker KVM MicroVMs vs. Rootless Containers)
  - Section 7: Pillar 5 — GitHub Actions Protocol Integration
  - Section 8: CLI Reference, MCP Tools & JSON Schemas
  - Section 9: Phased Implementation Roadmap

---

## 5. 60-Second Quickstart

Prerequisites: Linux kernel ≥ 5.8 with cgroups v2 (`/sys/fs/cgroup/cgroup.controllers`).

```bash
# 1. Build (or let the installer build for you)
cargo build --release

# 2. Install (per-user: ~/.local/bin + systemd user service)
./install.sh

# 3. Add your GitHub token (see Token section below)
echo 'RUNNER_GITHUB_TOKEN=ghp_...' >> ~/.config/runner/env

# 4. Start the daemon
systemctl --user enable --now runner
# ... or in the foreground:
runner start

# 5. Verify host telemetry
runner status --format=json
```

Root installs system-wide instead: `sudo ./install.sh` (binary to `/usr/local/bin`,
config to `/etc/runner`, unit to `/etc/systemd/system`).

---

## 6. Configuration Reference

Config lives at `~/.config/runner/config.toml` (`/etc/runner/config.toml` for
system installs), written with `0600` permissions:

```toml
# org = "my-org"          # org-level JIT issuance (optional)

[cloud]
max_monthly_spend = 0     # USD ceiling; 0 disables cloud bursting
# digitalocean_token = "..."
# render_token = "..."
# render_owner_id = "..."

[coordinator]
# repo_owner = "octocat"  # queue polling repo (both required to poll)
# repo_name = "hello-world"
poll_secs = 15            # queue poll cadence (min 5)
auto_dispatch = false     # true = launch sandboxes for routed jobs
runner_group_id = 1       # JIT runner group (1 = Default)
worker_version = "2.338.2"
job_timeout_mins = 60     # supervisor kill ceiling per job
```

Key behaviors:

- **Job timeout**: `job_timeout_mins` (default 60) is a hard ceiling — runaway
  jobs and infinite loops are killed by the supervisor, never left leaking
  host compute. Stuck workers are killed, never frozen mid-test.
- **Headroom**: the governor reserves `max(2, 25%)` cores and
  `max(4 GiB, 20%)` RAM for interactive apps; AFK Boost collapses headroom
  when the desktop is idle and restores it on first input.
- **Spend caps (Super Admin)**: agents and automation can request cloud
  capacity only within `max_monthly_spend`, and only for providers with
  configured tokens. A zero cap denies every request with a reason.

Secrets: the GitHub token lives in `~/.config/runner/env`
(`RUNNER_GITHUB_TOKEN=`), sourced by systemd — never in `config.toml`.

---

## 7. GitHub Token Configuration

JIT issuance needs `administration:write`:

1. **Classic PAT** (simplest): GitHub → Settings → Developer settings →
   Personal access tokens → *Tokens (classic)* → scopes **`repo`**
   (single-repo runners) and/or **`admin:org`** (org runners).
2. **Fine-grained PAT**: same location → *Fine-grained tokens* → target
   repo(s) → Repository permissions → **Administration: Read & write**.

Export it for the daemon:

```bash
echo 'RUNNER_GITHUB_TOKEN=ghp_...' >> ~/.config/runner/env
systemctl --user restart runner
```

`runner` validates classic scopes via the API's advertised scopes and
reports fine-grained tokens as offline-unverifiable (proven by the JIT
call itself). Point the coordinator at a repo (`repo_owner`/`repo_name`)
and set `auto_dispatch = true` to execute queued `[self-hosted, runner]`
jobs; starter workflows live in [`examples/`](file:///home/linux/runner/examples).

---

## 8. Autonomous AI Agent Guide

Agents connect over the Model Context Protocol (JSON-RPC 2.0 stdio):

```bash
runner mcp --transport=stdio
```

Lifecycle: `initialize` → `notifications/initialized` → `tools/list` →
`tools/call`. MCP-compatible clients (Claude Code, Cursor, Antigravity,
Muse CLI, Goose) mount it as a stdio server. Seven admin tools:

| Tool | Purpose |
| :--- | :--- |
| `get_ci_status` | Host health, PSI pressure, slots, reservations |
| `get_fleet_topology` | Local / WAN peers / cloud nodes split |
| `reserve_host_resources` | Hold cores + RAM for local agent work |
| `release_host_resources` | Release a reservation |
| `throttle_runner` | Force `warning` (25) / `critical` (1) weights |
| `request_cloud_capacity` | Burst within the pre-approved budget |
| `drain_node` | Stop dispatching to a node |

Example stdio session:

```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize",
 "params": {"protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "agent", "version": "1"}}}
{"jsonrpc": "2.0", "method": "notifications/initialized"}
{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
 "params": {"name": "get_ci_status"}}
```

Every CLI command also serves agents: `runner status --format=json`
emits the same telemetry shape over stdout.

---

## 9. Federated Mesh Expansion

Pool a trusted peer machine (friends & family) over an encrypted WireGuard mesh:

```bash
# On the coordinator (Super Admin): mint a capped invitation
runner mesh invite --role=donor --max-cores=4 --max-ram=8G --ttl=7d --name=alice-desktop
# → prints: runner1.<payload>.<signature>

# On the trusted peer machine: join with the token
runner join 'runner1....'

# Back on the coordinator (or any daemon): list the fleet
runner mesh list
```

Donor safety is structural: the joiner's supervisor enforces the token's
caps through the local cgroups weight ladder, AFK Boost, and slot
clamping, so foreign CI jobs yield to the donor's own apps. Discover LAN
machines with `runner mesh list --lan`. Revoke by draining:
`drain_node` via MCP stops new dispatches to a peer.
