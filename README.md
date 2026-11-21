# runner

[![CI](https://github.com/kirthi-sagar/runner/actions/workflows/ci.yml/badge.svg)](https://github.com/kirthi-sagar/runner/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/kirthi-sagar/runner?color=blue&label=release)](https://github.com/kirthi-sagar/runner/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)](https://github.com/kirthi-sagar/runner#platform-support)
[![Tests](https://img.shields.io/badge/tests-452%20passed-success.svg)](https://github.com/kirthi-sagar/runner/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 2021](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/)
[![Zero Dependencies](https://img.shields.io/badge/runtime-single%20static%20binary-brightgreen.svg)](#)

### High-Performance, Zero-Freeze, AI-Agent-Native Local & Federated GitHub Actions Runner Mesh

> **Status**: Generally Available (v1.8.x) — install with `./install.sh`, run with `runner start`.  
> **Target Audience**: Autonomous AI Coding Agents (Codex CLI, Antigravity, Muse CLI, Claude Code), Solo Developers, and Teams with Workstations, Spare PCs, Connected Peers, and Cloud Credits.

---

## Platform Support

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Tier-3 dispatch | ✅ | ✅ | ✅ |
| Governor (PSI + cgroups) | ✅ | ✅ | ❌ logged |
| Tier-2 sandbox (namespaces) | ✅ | ⚠ degraded | ❌ logged |
| Tier-1 microVM (Firecracker) | ✅ | ❌ | ❌ logged |
| WireGuard transport | ✅ | ✅ | ✅ |
| STUN NAT traversal | ✅ | ✅ | ✅ |

Windows runs Tier-3 dispatch natively (`runner.exe`); every
unsupported subsystem logs `unsupported on Windows` at the point of
use — see [`docs/windows.md`](docs/windows.md). Full Linux
capabilities (governor, sandbox) are available on Windows via WSL2.

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
   - Terminal-native JSON CLI (`runner status --format=json`, `runner throttle --level=high --duration=5`).
   - High-speed Unix domain socket (`/run/runner.sock`).
   - Native **Model Context Protocol (MCP)** server (`runner mcp`) enabling agents (Claude Code, Cursor, Windsurf, Codex CLI, Antigravity) to mount runner tools (`reserve_host_resources`, `get_ci_status`, `request_cloud_capacity`) directly into their context window.
   - **AFK Boost Mode**: Listens to desktop screen-lock events (`org.freedesktop.ScreenSaver` / Wayland idle notify) to automatically collapse reserved headroom to zero when the user is away, converting the workstation into a 100% dedicated build server until user input resumes.

3. **Federated Hybrid Mesh & Cloud Bursting**:
   - **Local LAN**: Connect spare PCs or Mac minis with `runner join <token> --coordinator <host:port> --coordinator-pubkey <key>`.
   - **Trusted Peer Nodes (Friends & Family WAN)**: Connect trusted peer machines across the internet over encrypted peer-to-peer WireGuard tunnels with mutual invite tokens. Peer donors set explicit donor limits (e.g. "donate up to 4 idle cores"), ensuring foreign CI jobs never interrupt their own computer use.
   - **Cloud Bursting Connectors**: Native connectors for DigitalOcean droplets and Render.com background workers allow the fleet to absorb CI spikes using free/promotional credits. When the queue clears, cloud instances terminate automatically after 5 minutes of idle time.

4. **Dual-Tier Role-Based Governance (RBAC)**:
   - **Super Admin (Human User)**: Sovereign authority over monthly cloud credit spend caps, trusted peer invitation approvals, node revocations, and emergency kill-switches.
   - **Admin (Autonomous AI Coding Agent via MCP)**: Operational fleet manager. Inspects node capacity, routes jobs based on hardware requirements (e.g., dispatching heavy PostgreSQL suites to cloud/peers while running quick linters locally), and requests cloud scaling within pre-approved budget boundaries.

5. **Transparent LAN Caching (`ACTIONS_CACHE_URL`)**:
   - Injects `ACTIONS_CACHE_URL` pointing to `runner`'s local LAN caching daemon (`127.0.0.1:8787` by default) into standard runner environments.
   - Standard actions (`actions/cache@v4`, `actions/setup-node`, `actions/setup-python`, `Swatinem/rust-cache`) read and write cache archives over Gigabit LAN at **100–120 MB/s** with **zero workflow file edits**.
   - Content-addressed disk store (`~/.runner/cache/`, 10 GB LRU budget); inspect with `runner cache stats`, purge with `runner cache clear --all`.

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
| **Peer WAN Federation** | **Yes (P2P WireGuard mesh + STUN NAT traversal)**| Manual | Complex VPN / Multi-cluster | None | None |
| **Cloud Credit Bursting** | **Yes (DigitalOcean / Render auto-scale)**| None | Custom autoscalers | None | Proprietary SaaS |
| **AFK Boost Mode** | **Yes (shipped v0.7.0)** | None | None | None | N/A |
| **Infrastructure Overhead** | **Zero (Single static binary)** | Low (Directory install) | Very High (Kubernetes cluster) | Low (Docker CLI) | Managed SaaS |
| **Distributed LAN Cache** | **Transparent (ACTIONS_CACHE_URL)**| No | Optional (MinIO / S3 setup) | Local Docker volume only | Cloud cache |
| **macOS Apple Silicon Support** | **Yes (Darwin QoS E-Core Pinning)** | Unmanaged | Not supported | Local Docker (Rosetta/arm) | Metered cloud |
| **Multi-Provider CI** | **GitHub + GitLab + Bitbucket + Local** | GitHub only | GitHub only | GitHub emu only | GitHub (+ paid add-ons) |
| **Tier-1 MicroVMs** | **Yes (Firecracker + vsock guest agent)** | None | None | None | Yes (Firecracker per job) |

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

Prerequisites: Linux kernel ≥ 5.8 with cgroups v2 (`/sys/fs/cgroup/cgroup.controllers`), Apple Silicon macOS (see [`docs/macos.md`](docs/macos.md)), or Windows via WSL2 (see [`docs/windows.md`](docs/windows.md)).

Zero-dependency install (downloads the prebuilt v1.8.1 binary with SHA-256 verification — no Rust toolchain needed):

```bash
curl -fsSL https://raw.githubusercontent.com/kirthi-sagar/runner/main/install.sh | sh
```

Or build from source:

```bash
# 1. Build (or let the installer build for you)
cargo build --release -p runner-cli

# 2. Install (per-user: ~/.local/bin + systemd user service)
./install.sh

# 3. Onboard: write config and store your GitHub token (§7 for token scopes)
runner init --org=my-org --repo=my-org/my-repo --token=ghp_...

# 4. Start the daemon
systemctl --user enable --now runner
# ... or in the foreground:
runner start

# 5. Verify host telemetry
runner status --format=json
```

Root installs system-wide instead: `sudo ./install.sh` (binary to `/usr/local/bin`,
config to `/etc/runner`, unit to `/etc/systemd/system`).

### Watch the zero-freeze governor live

```bash
runner top
```

```text
runner top v1.8.1  (q quit, live cadence)
CPU  [##----------------------]   7.4% some avg10
MEM  [#-----------------------]   2.4% some avg10
IO   [#-----------------------]   6.2% full avg10
governor weight 100 (normal) | slots 1
jobs: 0 in-flight, 0 queued
fleet: 4 local cores | 0 WAN peers | 0 cloud nodes | 0 drained
```

Kernel PSI gauges drive the cgroups v2 weight ladder (100 normal → 25
warning → 1 critical trickle — active tests are never frozen), alongside
live slots, in-flight jobs with provider tags, and the fleet split.
`runner top --once` emits one snapshot for scripts and CI.

### Sub-second dispatch with webhooks

```bash
runner listen --port 9898 --secret "$RUNNER_WEBHOOK_SECRET"
```

HMAC-verified (`X-Hub-Signature-256`) GitHub `workflow_job.queued` and
GitLab build events wake the coordinator instantly instead of waiting
for the next poll cycle. Or embed the listener in the daemon:

```toml
[server]
listen_port = 9898
```

with the secret in `RUNNER_WEBHOOK_SECRET` (never in config files).

### Diagnose host readiness

```bash
runner doctor --egress
```

```text
runner doctor
[✓] kernel     6.6.147-09648-g97ef00d8a343 with PSI (cpu/memory/io)
[✓] cgroupsv2  controllers: cpuset cpu io memory hugetlb pids
[!] userns     user namespaces unavailable; jobs run governed-direct (Tier-2 degraded)
[✓] kvm        /dev/kvm ready (Tier-1 microVM)
[✓] ebpf       unprivileged socket-filter attach works
[✓] daemon     IPC alive at /home/linux/.runner/runner.sock (0600)
[!] mcp        no agent registration found; run `runner mcp install --target cursor|claude`
[✓] cache      proxy on 127.0.0.1:8787, store writable, TTL 7d active
[✓] guards     temp 51.2°C, power AC (85°C latch armed)
[✓] afk        mode auto, idle detector ready
[✓] egress:metadata 169.254.169.254:80: expected blocked, observed blocked
[✓] egress:rfc1918 10.255.255.1:443: expected blocked, observed blocked
[✓] egress:https 1.1.1.1:443: expected allowed, observed reachable
result: healthy
```

Flags: `--enterprise` adds fleet-policy and audit-chain checks,
`--egress` adds the report-only network compliance probes,
`--format json` emits the machine-readable report (exit code is 0
unless a check fails).

Fail-capable checks (kernel, PSI, cgroups) gate readiness; KVM, eBPF,
daemon, and MCP degrade to warnings. `--egress` adds report-only
network compliance probes; `--enterprise` adds fleet policy and audit
continuity; `--format json` emits the machine-readable report.

### Validate provider credentials

```bash
runner provider test github
```

```text
provider github: OK
  token: present (env)
  authenticated as: kirthi-sagar
  JIT runner admin: yes (classic scopes)
```

Probes credentials, API reachability, identity, and JIT issuance
rights for `github`, `gitlab`, `bitbucket`, or `local`. Tokens are
never printed; exit code is nonzero on failure for scripting.

### Lifecycle, service & compliance commands

```bash
runner init --org=my-org --repo=my-org/my-repo --token=$TOKEN  # writes config, stores token, seeds layout
runner stop                     # graceful SIGTERM (--force for SIGKILL)
runner throttle --level=high --duration=5   # weight 1 for 5 min (never freezes)
runner service install          # user systemd unit: enable + start
runner audit verify             # SHA-256 chain integrity of the audit trail
runner policy inspect           # tenant ceilings and burst restrictions
```

`service` also offers `status`, `stop`, `start`, and `uninstall`;
`audit export` streams verified JSONL for SIEM ingestion;
`throttle` accepts `warning` (weight 25), `critical`/`high`
(weight 1) with `--duration` in minutes (default 15).

### Zero-freeze pre-commit hooks

```bash
runner hook install
```

```text
hook installed: /tmp/hook-doc/.git/hooks/pre-commit (runs `cargo test` via runner exec)
```

Auto-detects `cargo test` (`Cargo.toml`), `npm test`
(`package.json`), or `pytest` (`pytest.ini`/`pyproject.toml`) — or
pass `--cmd "<COMMAND>"` explicitly. The generated hook runs checks
under `runner exec --no-sandbox` (cgroup governance, repo cwd) so
commits never freeze the workstation; a failing check blocks the
commit. Existing hooks are backed up to `pre-commit.bak` and
restored by `runner hook uninstall`.

### Web control plane dashboard

```bash
runner server --listen 0.0.0.0:8080
# then open http://localhost:8080/dashboard
```

```bash
curl -s localhost:8080/health | python3 -m json.tool
```

```json
{"status": "healthy", "version": "1.8.1", "governor": "normal",
 "psi": {"cpu": 5.3, "memory": 0.6, "io": 6.9}, "cloud_nodes_active": 0}
```

Single-file embedded dashboard (zero external assets): host PSI
gauges, KPI cards, live fleet table, and a cloud-node badge,
auto-refreshing every 2.5 seconds from `/health` and `/api/v1/fleet`.

### AI-agent native MCP server

```bash
runner mcp --transport=stdio
```

12 tools over JSON-RPC 2.0 stdio: the 7 resource/fleet admin tools
plus `diagnose_system`, `test_provider`, `exec_command`,
`manage_cloud_capacity`, and `get_cache_stats`. One-command client
registration with `runner mcp install --target cursor|claude|generic`
(see §8).

### Cloud bursting lifecycle

```bash
runner cloud list
runner cloud terminate <instance-id>
runner cloud purge
```

```text
cloud nodes: 0 (spend $0.00 / cap $50.00/mo)
```

Ephemeral workers burst within the `max_monthly_spend` cap and a
5-minute idle watchdog terminates them automatically (scale-to-zero);
the CLI manages the same daemon-tracked nodes on demand.

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

[gitlab]                  # native GitLab CI runner (REST v4)
enabled = false           # true = poll jobs/request on poll_secs cadence
url = "https://gitlab.com"
# runner_token = "..."    # or RUNNER_GITLAB_TOKEN (see §7)
poll_secs = 10
tags = ["zero-freeze", "linux", "runner"]

[bitbucket]               # native Bitbucket Pipelines runner (OAuth)
enabled = false           # true = poll the runner step queue
workspace = ""            # workspace id
repo_slug = ""            # repository slug
runner_uuid = ""          # self-hosted runner UUID
# oauth_client_id = "..."     # or RUNNER_BITBUCKET_CLIENT_ID
# oauth_client_secret = "..." # or RUNNER_BITBUCKET_CLIENT_SECRET
poll_secs = 10
labels = ["zero-freeze", "linux", "runner"]

[cache]                   # transparent LAN cache proxy
listen = "127.0.0.1:8787" # proxy bind address
# dir = ""                # store override (default ~/.runner/cache/)
max_size_gb = 10          # disk budget before LRU eviction
ttl_secs = 604800         # entry age before background sweep evicts (7d; 0 disables)
sweep_secs = 3600         # TTL sweep cadence (60s floor)

[governor]                # PSI weight ladder + AFK boost
warn_cpu_psi = 20.0       # CPU some-avg10 where throttling begins (weight 25)
crit_cpu_psi = 40.0       # CPU some-avg10 for the trickle throttle (weight 1)
afk_mode = "auto"         # auto | always (headless) | never
afk_idle_seconds = 300    # desktop idle time before AFK boost engages
```

Key behaviors:

- **Job timeout**: `job_timeout_mins` (default 60) is a hard ceiling — runaway
  jobs and infinite loops are killed by the supervisor, never left leaking
  host compute. Stuck workers are killed, never frozen mid-test.
- **Headroom**: the governor reserves `max(2, 25%)` cores and
  `max(4 GiB, 20%)` RAM for interactive apps; AFK Boost collapses headroom
  when the desktop is idle and restores it on first input. Idle state is
  probed from `loginctl` every 5s; headless hosts read Active, so
  headless CI servers should set `afk_mode = "always"`.
- **Cache TTL**: the background sweep evicts entries older than `ttl_secs`
  by creation age (staleness), independent of the `--older-than` access
  idleness used by manual `cache clear`.
- **WAN routing**: jobs route to a WAN peer only while its handshake
  status reads `active`; otherwise routing falls through to cloud burst
  or waits — unproven peers never receive jobs.
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

Prefer the credential helper over hand-editing the env file (prompts
when values are omitted; always stored `0600`):

```bash
runner auth github --token ghp_...
runner auth gitlab --token glpat-...
runner auth bitbucket --client-id <id> --client-secret <sec>
```

GitLab runners need a runner token (GitLab → Admin → Runners, or the
project's *Settings → CI/CD → Runners*); set `[gitlab] enabled = true`
and matching `tags`, then restart the daemon. Bitbucket runners need
an OAuth consumer (workspace *Settings → OAuth consumers* with
*pipelines* scope) plus `workspace`, `repo_slug`, and `runner_uuid`
in `[bitbucket]`; starter configs live in [`examples/`](file:///home/linux/runner/examples).

---

## 8. Autonomous AI Agent Guide

Agents connect over the Model Context Protocol (JSON-RPC 2.0 stdio):

```bash
runner mcp --transport=stdio
# One-command client registration (cursor | claude | generic snippet):
runner mcp install --target cursor
```

Full agent setup, tool catalog, and stdio examples: [`docs/mcp.md`](docs/mcp.md).
Frozen machine-readable contracts: [`docs/mcp.md`](docs/mcp.md) (tool
inputs/outputs) and [`docs/cli-json.md`](docs/cli-json.md) (`status`,
`doctor`, `cache stats`, `cloud list` JSON shapes).

Lifecycle: `initialize` → `notifications/initialized` → `tools/list` →
`tools/call`. MCP-compatible clients (Claude Code, Cursor, Antigravity,
Muse CLI, Goose) mount it as a stdio server. Twelve tools:

| Tool | Purpose |
| :--- | :--- |
| `get_ci_status` | Host health, PSI pressure, slots, reservations |
| `get_fleet_topology` | Local / WAN peers / cloud nodes split |
| `reserve_host_resources` | Hold cores + RAM for local agent work |
| `release_host_resources` | Release a reservation |
| `throttle_runner` | Force `warning` (25) / `critical` (1) weights |
| `request_cloud_capacity` | Burst within the pre-approved budget |
| `drain_node` | Stop dispatching to a node |
| `diagnose_system` | Host diagnostics as JSON |
| `test_provider` | Verify CI provider credentials |
| `exec_command` | Run a governed command; capture output |
| `manage_cloud_capacity` | List / terminate / purge cloud workers |
| `get_cache_stats` | Cache entries, hits, misses, bandwidth saved |

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
# → prints: coordinator pubkey: <base64>  (send both to the peer operator)

# On the trusted peer machine: join with the token + coordinator coordinates
runner join 'runner1....' --coordinator 203.0.113.7:48717 --coordinator-pubkey '<base64>'

# Back on the coordinator (or any daemon): list the fleet
runner mesh list
```

Set `[mesh] peer_port` (e.g. `48717`) on both daemons to enable the
transport; see [`docs/wan-federation.md`](docs/wan-federation.md) for the
protocol, donor model, and limits.

Donor safety is structural: the joiner's supervisor enforces the token's
caps through the local cgroups weight ladder, AFK Boost, and slot
clamping, so foreign CI jobs yield to the donor's own apps. Discover LAN
machines with `runner mesh list --lan`. Revoke by draining:
`drain_node` via MCP stops new dispatches to a peer.

---

## 10. Universal Multi-Provider CI Matrix

`runner` is a single, unified zero-freeze mesh across every CI source.
One governor, one sandbox, one fleet — four providers behind the common
`ProviderAdapter` trait (`poll → claim → execute → complete`):

1. **GitHub Actions**: Official wrapped worker with ephemeral JIT tokens.
   Workflows target `runs-on: [self-hosted, runner]`; the coordinator
   polls queued jobs, mints single-use JIT configs, and supervises the
   official `actions/runner` binary in the tmpfs sandbox.
2. **GitLab CI**: Native REST v4 runner protocol. Configure `[gitlab]`
   (`url`, `runner_token`, `tags`) and tag jobs
   `[zero-freeze, runner]`; `runner` long-polls `jobs/request`, executes
   scripts sandboxed, and streams logs via trace chunks.
3. **Bitbucket Pipelines**: Atlassian OAuth runner protocol. Configure
   `[bitbucket]` (workspace, repo, runner UUID, OAuth client) and target
   `runs-on: [zero-freeze, runner]`; steps execute sandboxed with chunked
   log upload and `SUCCESS`/`FAILED` status reports.
4. **Local Git / CLI**: Zero-freeze offline command execution for
   developers, AI agents, and pre-commit hooks — no remote CI needed:
   `runner exec -- <cmd> [args...]` runs anything under the PSI governor
   with cgroup isolation, exit-code propagation, and timeout kill.

Providers register in `ProviderRegistry` and poll independently: one
provider's outage never stalls the others.

---

## 11. Enterprise Hardening (v0.3.0)

Three production capabilities for regulated and large-scale fleets:

### Native eBPF Egress Filtering

`crates/runner-sandbox/src/ebpf.rs` generates socket-filter bytecode in pure Rust — no
external `nftables` CLI execution. The program drops RFC 1918, `169.254/16`
metadata, and IPv6 ULA destinations, allows only UDP 53 (DNS) and TCP 443
(HTTPS), and default-drops everything else. `probe_ebpf()` detects
unprivileged attach support at runtime without panicking.

### Firecracker MicroVM Execution (Tier-1)

`crates/runner-sandbox/src/microvm.rs` drives Firecracker's REST socket API: boot source,
rootfs, vsock, `InstanceStart`, and graceful `SendCtrlAltDel` shutdown.
`MicroVmSupervisor` polls socket readiness with timeout and cleans up on
exit. `probe_kvm()` gates Tier-1 on `/dev/kvm` availability — hosts
without KVM degrade gracefully to Tier-2 namespaces, never crashing.

Workload dispatch runs over vsock: the host serves one exec session per
boot to the in-guest agent (`crates/runner-guest-agent`, baked into the
rootfs), streams its stdio, and returns its exit code. See
[`docs/microvm-tier.md`](docs/microvm-tier.md) for the protocol, the
rootfs-baking recipe, and the vsock assumptions.

### Centralized Control Plane with OIDC SSO

`runner server --listen 0.0.0.0:8080` starts the embedded Axum plane:

- `GET /health` — liveness + version.
- `GET /api/v1/fleet` — active runners, capacities, PSI telemetry.
- `POST /api/v1/runners/register` — enroll a node, receive a bearer token.
- `POST /api/v1/runners/heartbeat` — Bearer-authenticated telemetry.
- `GET /auth/login` → OIDC redirect (Okta, Keycloak, Google Workspace).
- `GET /auth/callback` — code exchange, RS256 JWKS verification, session.

Stale runners past the heartbeat TTL are evicted automatically. Enable SSO
with `--oidc-issuer`, `--client-id`, and `--client-secret`.

---

## 12. Open-Core Architecture (Cargo Workspace Monorepo)

`runner` serves two audiences from one repository at
`https://github.com/kirthi-sagar/runner` — no repo split, no feature
gating by binary. A Cargo workspace keeps every layer loosely coupled:

| Crate | Role | Edition focus |
|---|---|---|
| `crates/runner-core` | Execution engine: config, resource governor, federated mesh, IPC, MCP, status | Both |
| `crates/runner-sandbox` | Dual-tier isolation: process namespaces / Firecracker microVMs | Both |
| `crates/runner-providers` | Universal `ProviderAdapter` (GitHub, GitLab, Bitbucket, local) | Both |
| `crates/runner-telemetry` | Ring-buffer capture + structured JSON logs | Both |
| `crates/runner-enterprise` | Control plane, audit trail, fleet policy, SSO hooks | Enterprise |
| `crates/runner-cli` | Unified `runner` binary entrypoint | Both |
| `crates/runner-guest-agent` | Tier-1 in-guest exec agent (vsock) | Both |

The root `runner` crate is a thin facade re-exporting the stable
`runner::*` API, so existing agents, tests, and scripts keep working
unchanged. Core crates never depend on enterprise code.

### Community Edition — indie developers & AI agents

Free, unlimited self-hosted CI on local and spare hardware. Zero-friction
profile (`~/.config/runner/runner.toml`):

```toml
mode = "local"

[governor]
max_cpu_percent = 70
```

`mode = "local"` selects the lightweight process sandbox; the governor
keeps interactive apps smooth while jobs run.

### Enterprise Edition — platform & security teams

Sovereign, air-gapped, zero-trust execution mesh with hardware-isolated
sandboxes and multi-provider unification:

```toml
mode = "enterprise"

[sandbox]
driver = "microvm"
kernel_path = "/srv/microvm/vmlinux"
rootfs_path = "/srv/microvm/rootfs.ext4"

[security]
air_gapped = true
```

`mode = "enterprise"` defaults to the microVM tier; `air_gapped = true`
refuses cloud bursting at the pool; the audit trail (`runner::audit`),
fleet policy (`runner::policy`), and SSO hooks (`runner::sso`) govern
the fleet. `runner.toml` layers over `config.toml` (profile wins);
a malformed profile warns and never blocks startup.
