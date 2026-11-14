# AI-Agent-Native Local Runner Mesh Specification
## Project: runner
### Architectural Blueprint for a High-Concurrency, Zero-Freeze, Distributed Self-Hosted GitHub Actions Runner System for Local Workstations and Autonomous Coding Agents

---

## 1. Context, Background & Market Failure Analysis

### 1.1 The Developer & Autonomous AI Agent Bottleneck
The emergence of autonomous AI coding agents—operating in local terminals (Codex CLI, Claude Code), IDE extensions (Cursor, Windsurf, GitHub Copilot Workspace), and dedicated desktop environments (Google Antigravity, ChatGPT Codex Desktop)—has fundamentally transformed software delivery velocity.

In traditional workflows, a human engineer might open 2 to 5 pull requests per day. An autonomous coding agent working through structured test-driven milestones opens 15 to 40 pull requests per day. Each commit triggers continuous integration (CI) workflows that test multiple database configurations (e.g., SQLite, PostgreSQL), perform static analysis, execute unit and integration test suites, build frontend assets, and generate compliance artifacts (such as Software Bills of Materials).

Running 6 parallel jobs per commit across 30 commits per day consumes **3,000 to 6,000 CI minutes every single week**.

### 1.2 The Failure of Commercial CI Tiers
Commercial cloud CI providers cannot sustainably serve this velocity under free or low-cost student/hobbyist models:
1. **GitHub Actions**: Provides 2,000 free minutes per month for organizations and free accounts. When testing parallel jobs on standard 2-vCPU `ubuntu-latest` instances, 2,000 minutes can be exhausted in less than two weeks of active agent development. Once depleted, builds fail immediately unless costly paid billing is configured.
2. **Blacksmith.sh**: Offers high-performance 4-vCPU runners and a generous 3,000-minute free monthly tier. However, autonomous agents working concurrently on multiple PRs will consume this pool within a single billing cycle. Overage billing requires credit card verification and strict spend caps.
3. **Cloud Alternatives with Misleading "Free" Claims**:
   - **Shipfox.io**: Offers a $10 credit, but the credit expires strictly within 30 days. No permanent free tier exists.
   - **Tenki.cloud**: Advertises a $100 one-time credit, but lacks any sustained free monthly allowance.
   - **Ubicloud & Puzl.cloud**: Require credit card commitments; neither offers a recurring free tier for runners.
4. **Educational Program Depreciation**:
   - **DigitalOcean**: Discontinued its long-standing $200 student pack hosting credit from the GitHub Student Developer Pack.
   - **Travis CI**: GitHub Student Developer Pack integration has expired for many students (limiting concurrency to 1, non-functional with GitHub Actions workflows).
   - **GitLab CI**: Free tiers require educational institution enterprise agreements, excluding individual student developers.

### 1.3 Critical Deficiencies in Existing Self-Hosted Runner Software
Developers often turn to running self-hosted runners on their own personal computers, but existing open-source and commercial solutions suffer from fatal technical flaws:

#### Defect A: Unmanaged Resource Starvation (The "Desktop Freeze" Problem)
- **Official GitHub Actions Runner (`actions/runner`)**: Written in .NET Core. When installed on a developer's workstation, it spawns job processes directly on the host operating system with normal scheduling priority.
- If a CI job runs `npm run build`, `cargo build --release`, or extensive pytest integration suites across multiple cores, the runner allows worker threads to consume 100% of CPU time and unconstrained system RAM.
- **Consequences**:
  - The developer's desktop UI stutters or locks completely.
  - Web browsers (Chrome, Firefox) drop active tabs or stutter audio/video during calls.
  - Active terminal sessions running autonomous coding agents (Codex, Antigravity) experience high latency, shell timeouts, or termination.
  - Linux Out-Of-Memory (OOM) killer indiscriminately terminates user processes (often killing the IDE or browser) rather than cleanly throttling the background runner.

#### Defect B: Infrastructure Bloat & Operational Complexity
- **Actions Runner Controller (ARC)**: GitHub's enterprise-recommended auto-scaling runner system requires a complete Kubernetes cluster. Running Minikube, K3s, or MicroK8s on a local workstation consumes 2 GB to 4 GB of RAM solely for Kubernetes control-plane components (etcd, apiserver, kubelet, cert-manager, webhook pods) before a single CI job even executes. For an individual developer or small team with spare PCs, running Kubernetes is excessive, brittle, and battery-draining.
- **`nektos/act` (The Emulation Compatibility Trap)**: While useful for quick local linting, `act` attempts to reimplement GitHub Actions from scratch inside a CLI emulator. It does not connect to GitHub's repository webhook queues, fails on complex expression contexts (`${{ ... }}`), struggles with composite and JavaScript actions, diverges in secret handling, and cannot be used for remote GitHub PR checks.
- **Actuated**: A microVM runner system utilizing Firecracker. While technically fast, Actuated is a closed, commercial enterprise product requiring expensive monthly licensing. It is targeted at dedicated bare-metal cloud servers rather than local developer workstations or multi-PC home networks.
- **Docker-in-Docker Wrappers (`myoung34/docker-github-actions-runner`)**: Requires running Docker containers with `--privileged` flags. This exposes the host system kernel to arbitrary root code executed within CI workflows, creates Docker storage driver leakages (`overlay2` bloat), and provides zero dynamic CPU/RAM throttling relative to host desktop activity.

#### Defect C: Complete Lack of Autonomous AI Agent Interfaces
None of the existing solutions provide an API designed for autonomous AI agents running in the terminal. An agent like Codex running in a local shell cannot:
- Dynamically query how much hardware headroom is currently available before initiating a heavy test run.
- Tell the runner daemon: *"I am about to compile a 50,000-line codebase locally; throttle all background CI jobs to 1 core for the next 5 minutes."*
- Connect natively via Model Context Protocol (MCP) to invoke runner tools programmatically.
- Programmatically inspect sandbox failure logs via structured JSON to autonomously repair broken test setups.

---

## 2. System Architecture: The Supervisor & Wrapped Worker Model

A key design failure of previous community attempts to replace GitHub Actions runners was attempting to rewrite GitHub's proprietary, undocumented `.NET` job execution engine from scratch in Rust or Go. Doing so creates an endless game of catch-up with GitHub's evolving workflow expression engine, composite action resolvers, secret decryptors, and internal broker protocols.

**runner avoids this trap through the "Supervisor + Wrapped Official Worker" architecture:**

```
+---------------------------------------------------------------------------------------------------+
|                                   RUNNER SUPERVISOR (Rust / Go)                                   |
|                                                                                                   |
|  - Manages GitHub REST API communication (JIT Config generation via generate-jitconfig)           |
|  - Enforces Linux cgroups v2 resource slices and Pressure Stall Information (PSI) monitoring      |
|  - Serves Unix Domain Socket API (/run/runner.sock) and Model Context Protocol (MCP) server |
|  - Coordinates Multi-PC LAN Mesh discovery, work routing, and distributed package caching         |
+-------------------------------------------------+-------------------------------------------------+
                                                  | Spawns & Isolates
                                                  v
+---------------------------------------------------------------------------------------------------+
|                           EPHEMERAL SANDBOX (Rootless Podman / MicroVM)                           |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  |                 WRAPPED OFFICIAL WORKER BINARY (actions/runner.worker)                      |  |
|  |                                                                                             |  |
|  |  - 100% native GitHub Actions workflow execution fidelity                                   |  |
|  |  - Native handling of ${{ ... }} expressions, composite actions, and job steps              |  |
|  |  - Scoped strictly inside unprivileged user namespace and runner.slice cgroup          |  |
|  |  - Injected with ACTIONS_CACHE_URL pointing to local LAN cache proxy                         |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

### Core Architecture Roles
1. **runner Supervisor (Host Daemon)**: Written in Rust or Go as a single static binary. It handles the local OS kernel interfaces (cgroups v2, PSI, Darwin QoS), hosts the agent IPC socket, serves the MCP server, and communicates with the GitHub REST API.
2. **Ephemeral Sandbox Hypervisor**: Instantiates an unprivileged, isolated execution sandbox (Rootless Podman/crun or Firecracker MicroVM).
3. **Wrapped Official Worker**: Inside the ephemeral sandbox, runner runs an unmodified, pre-cached copy of the official `actions/runner.worker` binary. 
4. **The Strategic Advantage**: This gives runner **100% day-one compatibility with all GitHub Actions workflows, actions, and features**, while maintaining **100% kernel-level resource governance and desktop safety** on the host.

---

## 3. Pillar 1: The Zero-Freeze Resource Governor & Timer Safety

To ensure background runner jobs never starve the host workstation, runner implements a multi-tiered kernel-level resource governor using modern Linux cgroups v2, Pressure Stall Information (PSI), and timer-safe scheduling.

```
+---------------------------------------------------------------------------------------------------+
|                                      HOST LINUX SYSTEM                                            |
|                                                                                                   |
|  +----------------------------------------------------+   +------------------------------------+  |
|  |     User Interactive Slice (High Priority)         |   |    runner Slice (Yielding)      |  |
|  |     Path: /sys/fs/cgroup/user.slice                |   |    Path: /sys/fs/cgroup/runner|  |
|  |                                                    |   |                                    |  |
|  |  [Desktop UI / Wayland / X11]                      |   |  [Governor Daemon (Monitor)]       |  |
|  |  [Chrome / Firefox Browsers]                       |   |                                    |  |
|  |  [VS Code / Antigravity Desktop]                   |   |  Job Sandbox 1    Job Sandbox 2    |  |
|  |  [Codex Terminal Agent Session]                    |   |  (cpu.weight: 100)(cpu.weight: 100)|  |
|  |                                                    |   |  (memory.high)    (memory.high)    |  |
|  |  CPU Weight: 1000 (Default)                        |   |  CPU Weight: 1-100 (Throttled)     |  |
|  |  Memory: Unconstrained                             |   |  Memory Max: Soft-Capped           |  |
|  +----------------------------------------------------+   +------------------------------------+  |
|                            ^                                                 |                    |
|                            |               PSI Feedback Loop                 |                    |
|                            +-------------------------------------------------+                    |
|                              Reads: /proc/pressure/{cpu, memory, io}                              |
|                              Action: Throttles CFS weights; protects test timers                 |
+---------------------------------------------------------------------------------------------------+
```

### 3.1 Kernel cgroups v2 Hierarchy
runner creates a dedicated systemd scope and cgroup slice for all runner workloads:
- **Slice Path**: `/sys/fs/cgroup/runner.slice/`
- **CPU Weighting (`cpu.weight`)**: The Linux Completely Fair Scheduler (CFS) divides CPU time based on proportional weights (ranging from 1 to 10,000).
  - User desktop processes run in `user.slice` with the default weight of `1000`.
  - runner runner jobs run in `runner.slice` with a base weight of `100` (configurable down to `1`).
  - **Result**: When the host CPU is under 100% load, the desktop environment and terminal agents receive **10x to 1000x more CPU cycles** than background runner jobs. If the user starts a build or opens a web application, the kernel automatically squeezes the runner's CPU consumption down to background idle time without dropping a single frame.

### 3.2 Pressure Stall Information (PSI) Monitoring Loop
Relying on standard CPU utilization percentages is insufficient because a system can be at 100% CPU utilization while remaining completely responsive, or at 60% CPU utilization while thrashing heavily on disk I/O or memory paging.

runner monitors the Linux kernel's Pressure Stall Information in real-time by polling `/proc/pressure/cpu`, `/proc/pressure/memory`, and `/proc/pressure/io`:
- **Sampling Interval**: 250 milliseconds.
- **Metrics Tracked**: `some avg10` (the percentage of time in the last 10 seconds where at least one process was stalled waiting for resources) and `full avg10` (where all processes were stalled).

### 3.3 Timer-Safe Throttling (The `cgroup.freeze` Hazard & Solution)
A critical systems hazard in previous runner concepts was using `cgroup.freeze` to pause active runner jobs during high system load.

**The Flaw of `cgroup.freeze` on Active Tests**:
- `cgroup.freeze` places processes into an uninterruptible sleep state, but **wall-clock time (`CLOCK_MONOTONIC` and `CLOCK_REALTIME`) continues to advance**.
- If a CI job is running PostgreSQL integration tests (such as Resub Health's backend suites) or Jest/Playwright tests with 5-second to 30-second timeouts, freezing the cgroup for 10–20 seconds causes database keepalives (`keepalives_idle`), TCP connection handshakes, and test timers to immediately expire. Upon unfreezing, the tests crash with timeout errors.

**The runner Solution: CFS Trickle Scheduling**:
1. **Never Hard-Freeze Active Test Steps**: When CPU or Memory pressure exceeds warning thresholds, runner drops `cpu.weight` down to `1` (the absolute CFS minimum) and throttles `io.max`.
2. **Trickle CPU Protection**: At `cpu.weight: 1`, the runner receives approximately 0.1% to 1% of CPU cycles. This is enough to keep database heartbeats, TCP sockets, and test framework clock loops alive, while yielding >99% of CPU throughput to the user's desktop applications and terminal agents.
3. **Restricted Freezing**: `cgroup.freeze` is used **only** between workflow steps (inter-step pauses) or during explicit user/agent reservations (`runner reserve`), where the supervisor waits for the current test step to complete before pausing the runner container.

#### Governor Action Thresholds:
| Kernel Pressure Metric | Normal State | Warning State (Soft Throttle) | Critical State (Trickle Throttle) |
| :--- | :--- | :--- | :--- |
| **Memory PSI (`some avg10`)** | `< 5.0%` | `5.0% - 15.0%` (Reduce slots, lower `memory.high`) | `> 15.0%` (Drain pending jobs, drop `cpu.weight` to 1) |
| **CPU PSI (`some avg10`)** | `< 20.0%` | `20.0% - 40.0%` (Drop runner `cpu.weight` to 25) | `> 40.0%` (Drop runner `cpu.weight` to 1, throttle `io.max`) |
| **I/O PSI (`full avg10`)** | `< 3.0%` | `3.0% - 10.0%` (Throttle runner I/O via `io.max`) | `> 10.0%` (Cap runner disk IOPS to 100) |

### 3.4 Dynamic Concurrency Engine & AFK Boost Mode
runner calculates safe parallel runner slots ($S$) dynamically using:

$$S = \max\left(1, \min\left( \left\lfloor \frac{C_{\text{total}} - C_{\text{reserved}}}{C_{\text{job\_min}}} \right\rfloor, \left\lfloor \frac{M_{\text{avail}} - M_{\text{reserved}}}{M_{\text{job\_min}}} \right\rfloor \right)\right)$$

Where:
- $C_{\text{total}}$: Total logical CPU cores on host.
- $C_{\text{reserved}}$: Guaranteed core headroom for user apps (default: $\max(2, 0.25 \times C_{\text{total}})$).
- $M_{\text{avail}}$: Available system RAM reported by kernel `/proc/meminfo`.
- $M_{\text{reserved}}$: Guaranteed RAM headroom reserved for desktop/agents (default: $\max(4\,\text{GB}, 0.20 \times M_{\text{total}})$).
- $C_{\text{job\_min}}$: Minimum cores required per CI job slot (default: 1.5 cores).
- $M_{\text{job\_min}}$: Minimum RAM required per CI job slot (default: 2.0 GB).

#### AFK Boost Mode (Desktop Idle Detection)
When a developer leaves their desk, locking their screen or becoming idle, their workstation's full hardware capacity sits unused. runner includes an **AFK Boost Mode**:
- Listens to Wayland / X11 idle notifications and screensaver events (`org.freedesktop.ScreenSaver`, `ext-idle-notify-v1`, or `MIT-SCREEN-SAVER`).
- When the desktop locks or passes the idle threshold (e.g. 5 minutes without input), runner automatically shifts $C_{\text{reserved}}$ and $M_{\text{reserved}}$ to near-zero.
- The workstation instantly transforms into a **100% dedicated high-throughput CI server**, increasing parallel job slots to maximum capacity.
- On the very first mouse movement or keyboard press, the governor immediately restores full reserved headroom and lowers runner weights back to background levels within 50 milliseconds.

### 3.5 macOS Apple Silicon Portability (Efficiency Core Pinning)
While Linux relies on cgroups v2 and PSI, runner maps cleanly to macOS Apple Silicon (M1/M2/M3/M4) architectures:
- Uses Darwin Quality of Service (QoS) classes via `setpriority(PRIO_DARWIN_BG)`.
- **Efficiency (E) Core Pinning**: On Apple Silicon, background QoS threads are automatically scheduled by the macOS kernel exclusively onto low-power Efficiency cores.
- This leaves the high-performance Performance (P) cores 100% free for the developer's interactive IDE, browser, and local AI agent execution.
- Integrates with Apple's `Virtualization.framework` to spin up ephemeral lightweight Linux guest kernels for running Linux-based GitHub Actions workflows locally.

### 3.6 Deep Dive: CPU Core & Thread Topology (4c/4t vs. 4c/8t, SMT Scheduling & Over-Subscription Protection)

In modern hardware architecture, the operating system kernel views each hardware thread as an independent logical CPU ($C_{\text{total}}$). Simultaneous Multithreading (SMT / Intel Hyper-Threading) alters the execution dynamics of parallel CI workloads significantly.

#### Comparative Topology Matrix:
| Architecture Metric | Case 1: 4 Cores / 4 Threads (No SMT) | Case 2: 4 Cores / 8 Threads (With SMT) |
| :--- | :--- | :--- |
| **Visible Logical CPUs ($C_{\text{total}}$)** | **4 logical CPUs** | **8 logical CPUs** |
| **Hardware Core Context** | 1 hardware thread = 1 physical core | 2 hardware threads share 1 physical core |
| **Interactive Reserved Headroom ($C_{\text{reserved}}$)** | $\max(2, 0.25 \times 4) = \mathbf{2\text{ CPUs}}$ | $\max(2, 0.25 \times 8) = \mathbf{2\text{ CPUs}}$ |
| **Available Runner Capacity (Interactive)** | $4 - 2 = \mathbf{2\text{ CPUs}}$ | $8 - 2 = \mathbf{6\text{ CPUs}}$ |
| **Parallel CI Job Slots ($S$) (Interactive)** | **1 Concurrent Job Slot** | **3 to 4 Concurrent Job Slots** *(RAM permitting)* |
| **Parallel CI Job Slots ($S$) (AFK Boost Mode)** | **2 Concurrent Job Slots** | **5 Concurrent Job Slots** |
| **Kernel Scheduler Mechanism** | Completely Fair Scheduler (CFS) | SMT-Aware CFS (`CONFIG_SCHED_SMT`) |
| **PSI Pressure Spike Profile** | High sensitivity (saturates physical ALUs) | Moderate (extra hardware threads buffer I/O wait) |

#### 1. Case 1: 4 Cores / 4 Threads (Physical Cores Only)
- In a 4c/4t system, there are no sibling execution threads. When a test framework spins up multiple processes (e.g. `pytest -n 4`), all 4 physical execution pipelines hit 100% load.
- **Governor Action**: `runner` strictly allocates **1 concurrent runner slot** in interactive mode. Because `user.slice` maintains a 10x scheduling weight (`cpu.weight: 1000` vs `runner.slice: 100`), interactive desktop keystrokes and browser render loops preempt runner threads without input lag.
- If CPU PSI (`some avg10`) exceeds 20%, `runner` automatically lowers the runner slice weight to `25` (and down to `1` during critical pressure).

#### 2. Case 2: 4 Cores / 8 Threads (SMT / Hyper-Threading Enabled)
- In a 4c/8t system, each physical core hosts 2 logical threads sharing execution units, instruction decoders, and L1/L2 caches.
- **Kernel SMT Coordination**: Linux kernel CFS features `CONFIG_SCHED_SMT` topology awareness. When a foreground user application demands CPU time, the kernel prioritizes scheduling it on an idle physical core. If a physical core is shared between a user process and a runner worker, the user process receives primary execution cycles, leaving the runner to execute in trickle cycles on the sibling SMT thread.
- **Expanded Concurrency**: Because 6 logical threads remain unreserved, the coordinator can safely dispatch **3 to 4 parallel CI jobs** simultaneously (e.g., PostgreSQL tests, Jest frontend suite, and linting running concurrently).

#### 3. Over-Subscription Prevention: Clamping the `nproc` Trap
A critical hazard on local workstations is that standard test tools and build systems blindly query the host CPU count (e.g. `make -j$(nproc)`, `cargo build`, or `pytest -n auto`). On an 8-thread machine running 3 parallel CI jobs, unmanaged tools would spawn $3 \times 8 = 24$ heavy compilation threads on 4 physical cores, triggering extreme CPU cache thrashing, L3 eviction, and memory exhaustion.

`runner` prevents this inside its unprivileged sandbox environment:
1. **Dynamic Environment Variable Clamping**:
   - `CMAKE_BUILD_PARALLEL_LEVEL=2`
   - `UV_CONCURRENT_DOWNLOADS=4`
   - `MKL_NUM_THREADS=2`
   - `OPENBLAS_NUM_THREADS=2`
2. **CFS Bandwidth Quotas (`cpu.max`) vs. Rigid `cpuset` Pinning**:
   - Rigid core pinning (`cpuset.cpus: 2,3`) is rejected because it wastes cores when user applications are idle and causes desktop stutters when user applications need more than 2 cores.
   - Instead, `runner` sets proportional CFS bandwidth quotas (`cpu.max: 200000 100000` = 200% CPU max over a 100ms window), allowing the runner processes to float across any core while strictly bounding aggregate thread load.

---

## 4. Pillar 2: Autonomous AI Agent Interface, Native MCP & Diagnostics

Autonomous AI coding agents operate through terminal shells, IDE tool calls, and protocol integrations. runner provides a unified supervisory interface tailored for programmatic AI control.

```
+---------------------------------------------------------------------------------------------------+
|                                    AUTONOMOUS AI CODING AGENT                                     |
|                      (Codex CLI, Antigravity, Claude Code, Cursor, Windsurf)                      |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                    +-----------------------------+-----------------------------+
                    |                                                           |
                    v                                                           v
       [Model Context Protocol (MCP)]                                 [Terminal JSON CLI]
         `runner mcp` (stdio)                                `runner status --format=json`
                    |                                                           |
                    +-----------------------------+-----------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                  RUNNER AGENT SUPERVISORY API                                     |
|                                                                                                   |
|  - `reserve_host_resources(cores, ram, duration)`: Holds headroom for agent's local compiles      |
|  - `throttle_runner(level, duration)`            : Immediately yields CPU to foreground tasks     |
|  - `get_ci_status()`                             : Real-time JSON telemetry of mesh and queue     |
|  - `get_failed_job_trace(job_id)`                : Deterministic stack trace and failure extraction|
+---------------------------------------------------------------------------------------------------+
```

### 4.1 Native Model Context Protocol (MCP) Server
In addition to standard CLI flags and Unix domain sockets (`/run/runner.sock`), runner implements a native **Model Context Protocol (MCP)** server via `runner mcp` (stdio or SSE).

Any MCP-compatible AI agent (Claude Code, Cursor, Windsurf, Codex CLI, Antigravity) can mount runner directly into its system prompt with zero shell wrappers:

#### Exposed MCP Tools:
1. `runner_get_status`: Returns current mesh capacity, running jobs, and PSI pressure.
2. `runner_reserve_resources`: Temporarily reserves CPU cores and RAM for agent local compilation.
3. `runner_throttle`: Forces background runner jobs into trickle mode.
4. `runner_get_failure_trace`: Returns parsed stack traces and culprit files from failed CI runs.

### 4.2 Terminal CLI (Machine-Readable Output)
Every CLI command accepts the `--format=json` flag, returning deterministic JSON objects optimized for LLM token efficiency:

```bash
runner status --format=json
```
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "host": {
    "total_cores": 16,
    "available_cores_for_ci": 12,
    "total_memory_bytes": 34359738368,
    "available_memory_bytes": 18253611008,
    "psi_pressure": {
      "cpu_avg10": 4.2,
      "memory_avg10": 0.8,
      "io_avg10": 0.1
    }
  },
  "concurrency": {
    "max_slots": 4,
    "active_slots": 2,
    "queued_github_jobs": 1
  },
  "active_jobs": [
    {
      "job_id": "job-89104",
      "workflow": "ci.yml",
      "name": "backend (postgresql)",
      "repo": "resub-health/resub",
      "pr_number": 142,
      "elapsed_seconds": 184,
      "cgroup_cpu_usage_pct": 192.4,
      "cgroup_memory_bytes": 1610612736
    }
  ],
  "mesh_nodes": [
    {
      "node_id": "spare-pc-office",
      "ip": "192.168.1.45",
      "cores": 8,
      "active_jobs": 2,
      "status": "online"
    }
  ]
}
```

### 4.3 Agent Resource Reservation Primitives
An autonomous agent planning to run heavy local tasks (such as running local unit tests, compiling binaries, or running static analysis) can coordinate directly with runner before starting:

```bash
# Agent reserves 4 cores and 6GB RAM for the next 10 minutes
runner reserve --cores=4 --ram=6G --duration=10m --reason="codex-local-compilation"

# Agent releases the reservation immediately when done
runner release --reservation-id="res-7712"
```

### 4.4 Deterministic Log Diagnostics vs. LLM Remediation
To ensure reliability and prevent hallucinated diagnostic hints, runner separates failure analysis into two distinct layers:
1. **Deterministic Parser Layer (Default)**:
   - Strips ANSI escape codes.
   - Extracts structured failure blocks using regex and standard JUnit / SARIF / pytest test report parsers.
   - Outputs the exact failing step, exit code, culprit source file, line number, and verbatim stack trace without editorializing.
2. **Optional Semantic Remediation Hook**:
   - If enabled by the user or agent, passes the extracted 50-line failure context to a local small language model (SLM) or agent API hook to generate code fix suggestions.

---

### 4.5 Deep Dive: Dual-Tier Governance & RBAC Model (Super Admin vs. AI Agent Admin)

To ensure both absolute safety for the human owner and maximum operational autonomy for AI coding agents, `runner` implements a formal Dual-Tier Role-Based Access Control (RBAC) model:

```
+---------------------------------------------------------------------------------------------------+
|                                     DUAL-TIER GOVERNANCE MODEL                                    |
|                                                                                                   |
|  +----------------------------------------------------+   +------------------------------------+  |
|  |             SUPER ADMIN (Human User)               |   |   ADMIN (Autonomous AI Coding Agent|  |
|  |             Interface: CLI & Config File           |   |   Interface: Native MCP Server     |  |
|  |                                                    |   |                                    |  |
|  |  - Sovereign spend cap on cloud credits ($ limit)  |   |  - Real-time fleet capability query|  |
|  |  - Generate / revoke invitations for trusted peer nodes (friends & family)  |   |  - Dynamic job dispatch & routing  |  |
|  |  - Approve cloud provider credentials (API keys)  |   |  - Request ephemeral cloud scaling |  |
|  |  - Set thermal & battery safety thresholds         |   |  - Dynamic throttling (PSI feedback|  |
|  |  - Instant emergency mesh kill switch              |   |  - Workstation resource reservation|  |
|  +----------------------------------------------------+   +------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

#### Authority Matrix:
| Capability / Dimension | Super Admin (Human User) | Admin (Autonomous AI Agent via MCP) |
| :--- | :---: | :---: |
| **Set Maximum Monthly Cloud Spend / Credit Cap** | ✅ Full Authority | ❌ Read-Only (Cannot exceed pre-set cap) |
| **Approve / Revoke Trusted Peer Invitations** | ✅ Full Authority | ❌ Read-Only (Can query peer status) |
| **Emergency Host & Mesh Kill Switch** | ✅ Instant Hard Kill (`runner stop --force`) | ❌ Graceful Drain Only (`drain_node`) |
| **Dynamic Job Dispatch & Capability Routing** | ✅ Configurable Rules | ✅ Autonomous Dispatching |
| **Reserve Workstation Resources for Local Builds** | ✅ Manual CLI Override | ✅ Programmatic MCP Call (`reserve_host_resources`) |
| **Request Cloud Scale-Up during Backlog** | ✅ Pre-approves Auto-Rules | ✅ Triggers within approved budget (`request_cloud_capacity`) |
| **Dynamic Concurrency & Throttling (`cpu.weight: 1`)**| ✅ Manual Override | ✅ Real-time PSI Feedback Loop (`throttle_runner`) |

#### Agent Admin MCP Tool Specifications:
The AI agent interacts with the fleet using structured MCP tools:
1. `request_cloud_capacity`:
   - Parameters: `provider` ("digitalocean" | "render" | "oracle"), `max_instances` (integer), `duration_hours` (number), `reason` (string).
   - Behavior: Verifies that requested compute does not exceed the Super Admin's credit budget limit. Provisions ephemeral cloud worker nodes, which automatically scale to zero when idle for > 5 minutes.
2. `get_fleet_topology`:
   - Parameters: `{}`.
   - Behavior: Returns real-time breakdown of all active nodes across local LAN, connected trusted peers (friends & family) over WAN, and active cloud instances, including current load and capabilities.
3. `drain_node`:
   - Parameters: `node_id` (string), `reason` (string).
   - Behavior: Marks a node as draining so no new jobs are scheduled on it, allowing a peer donor to reclaim their machine smoothly.

---

## 5. Pillar 3: Multi-PC LAN Mesh & Coordinator-First JIT Dispatch

Most developers and student engineers have access to more than one computing device: an old desktop under a desk, a secondary laptop, or a low-power home server. runner aggregates these heterogeneous machines into a unified, high-throughput runner mesh.

```
                                  +------------------------------------+
                                  |     GitHub Organization Queue      |
                                  |        (Labels: runner)         |
                                  +-----------------+------------------+
                                                    |
                                      Webhook Notification of Job
                                                    v
+-------------------------------------------------------------------------------------------------------+
|                                    LOCAL AREA NETWORK (LAN) MESH                                      |
|                                                                                                       |
|      +-----------------------------------------+   mDNS / Gossip    +------------------------------+  |
|      |        PRIMARY COORDINATOR              |<==================>|        WORKER NODE           |  |
|      |        (Workstation)                    |   Encrypted TLS    |        (Spare Laptop)        |  |
|      |                                         |                    |                              |  |
|      | - Evaluates mesh node capacity          |                    | - Specs: 8 Cores, 16GB RAM   |  |
|      | - Dispatches JIT config to Worker       |                    | - Monitors Thermal & Battery |  |
|      | - Runs heavy DB / integration tests     |                    | - Runs Lint, Security, SBOM  |  |
|      +--------------------+--------------------+                    +--------------+---------------+  |
|                           |                                                        |                  |
|                           +---------------------------+----------------------------+                  |
|                                                       |                                               |
|                                                       v                                               |
|                                     +-----------------------------------+                             |
|                                     |    Distributed LAN Cache Pool     |                             |
|                                     |    (ACTIONS_CACHE_URL Proxy)      |                             |
|                                     |  - Shared npm / pip / cargo cache |                             |
|                                     |  - P2P Docker image layer storage |                             |
|                                     +-----------------------------------+                             |
+-------------------------------------------------------------------------------------------------------+
```

### 5.1 The Coordinator-First JIT Dispatch Protocol
A major flaw in naive self-hosted runner pooling is having multiple machines long-poll GitHub under the same label (`runs-on: [self-hosted, runner]`). Under that model, GitHub's cloud broker assigns jobs randomly based on network latency, preventing local work-stealing or capability-aware routing once a job is leased.

**The runner Solution**:
1. **Single Point of Ingestion**: Only the **Primary Coordinator** node listens to GitHub (via webhook notifications `workflow_job.queued` or fast REST queue polling).
2. **Capability Matching**: When a job arrives, the Coordinator inspects the workflow metadata (e.g. `name: backend (postgresql)` vs `name: lint`) and matches it against current LAN node capacities.
3. **On-Demand JIT Generation**: The Coordinator calls GitHub's `generate-jitconfig` API, obtains a single-use JIT runner token, and securely pushes it over local TLS to the designated worker node.
4. **Instant Spin-Up**: The designated worker node instantiates an ephemeral runner sandbox, registers, executes the single job, and immediately tears down upon completion.

### 5.2 Workflow Capability Tags
Workflows can specify hardware hints directly in their GitHub Actions `runs-on` tags:
```yaml
runs-on: [self-hosted, runner, ram-8gb, cpu-4]
```
The Coordinator parses these tags and ensures the job is dispatched strictly to a mesh node meeting those minimum unreserved hardware thresholds.

### 5.3 Transparent LAN Cache Interception (`ACTIONS_CACHE_URL`)
In standard CI, every job repeatedly downloads dependencies from the internet (`npm install`, `pip install`, `cargo fetch`). runner provides transparent, zero-workflow-edit caching:

1. **`ACTIONS_CACHE_URL` Injection**: The GitHub Actions runner natively supports custom cache servers via environment variables. runner automatically injects `ACTIONS_CACHE_URL` and `ACTIONS_RUNTIME_TOKEN` pointing to its local LAN cache daemon.
   - Any standard `actions/cache@v4`, `actions/setup-node`, `actions/setup-python`, or `Swatinem/rust-cache` step automatically routes its save/restore operations to the local mesh at **100–120 MB/s** over Gigabit LAN.
2. **Transparent Pull-Through Mirrors**: runner injects `PIP_INDEX_URL`, `npm_config_registry`, and `DOCKER_REGISTRY_MIRROR` into the sandbox, caching popular packages locally across the entire mesh.

### 5.4 Thermal & Battery Guard for Laptops
Users frequently add older laptops to their home runner mesh. Running prolonged multi-core builds can cause battery swelling or thermal shutdown on older hardware.

runner continuously reads `/sys/class/thermal/` and `/sys/class/power_supply/` on worker nodes:
- **Thermal Threshold**: If CPU package temperature exceeds 85°C, runner lowers runner core allocations and CFS weights.
- **Battery Threshold**: If a laptop is running on battery power (discharging), runner automatically drains and halts runner jobs on that node to prevent battery exhaustion.

---

### 5.5 Deep Dive: The Federated Hybrid Mesh (Trusted Peers & Cloud Credit Bursting)

While local workstation and LAN pooling solves baseline CI needs, modern agentic development occasionally requires bursting across dozens of parallel jobs (e.g. running multiple database matrices, lint, security, and frontend suites across several PRs simultaneously). `runner` expands beyond a single home network into a **Federated Hybrid Mesh**:

```
+-------------------------------------------------------------------------------------------------------+
|                                        RUNNER COORDINATOR DAEMON                                      |
|                       Super Admin: Human User  |  Admin: AI Coding Agent (MCP)                        |
+-------------------------------------------------------------------------------------------------------+
                                                    |
                   +--------------------------------+--------------------------------+
                   |                                |                                |
       (High-Speed Local LAN)              (Secure Internet WAN)             (Cloud Credit Bursting)
                   v                                v                                v
+------------------------------------+ +--------------------------+ +-----------------------------------+
|          LOCAL HARDWARE            | | TRUSTED PEER (FRIENDS & FAMILY) | |       CLOUD PROVIDER FLEET        |
| - Primary Workstation (cgroups v2) | | - Encrypted P2P Tunnel   | | - DigitalOcean Droplet ($ credits)|
| - Spare PC / Mac mini in office    | | - Explicit Permission/Pin| | - Render.com Worker ($ credits)   |
| - mDNS Zero-Config Discovery       | | - Donor Resource Cap     | | - Ephemeral Auto Scale-to-Zero    |
+------------------------------------+ +--------------------------+ +-----------------------------------+
```

#### 1. Trusted Peer Federation over WAN (Friends & Family)
Users can securely pool compute with trusted peers, colleagues, and family across the internet:
- **Zero-Port-Forwarding P2P Overlay**: Uses embedded WireGuard tunnels with automated NAT traversal (STUN / interactive ICE / DERP relays), eliminating the need for dynamic DNS or public IP port forwarding.
- **Mutual Cryptographic Invitation**:
  - The Super Admin generates an invitation token:
    ```bash
    runner mesh invite --role=donor --max-cores=4 --max-ram=8G --ttl=7d --name="alice-desktop"
    ```
  - The peer runs:
    ```bash
    runner join <invite-token>
    ```
- **Donor Protection Guarantee**:
  - The peer computer runs the same unprivileged supervisor with local Linux cgroups v2 / macOS Darwin QoS and AFK Boost mode.
  - Foreign jobs running on the peer PC run at low CFS priority (`cpu.weight: 100` down to `1`), ensuring that if the local user plays a video game or browses the web, the donor's local apps receive 100% priority and never freeze.
  - The peer donor can set a strict donor cap (e.g., "only allow runner to use up to 4 cores and 8GB RAM, and pause jobs when battery is discharging").

#### 2. Ephemeral Cloud Credit Bursting (DigitalOcean, Render.com, Oracle Free Tier)
Developers often accumulate promotional cloud credits ($50 to $200 on DigitalOcean, student credits on Render.com, or permanent Oracle Cloud Always-Free ARM instances). `runner` turns these credits into an on-demand burst fleet:
- **Cloud Connectors**: Built-in cloud orchestrator supporting DigitalOcean API (`POST /v2/droplets`) and Render API (`POST /v1/services`).
- **JIT Worker Ingestion**: When the queue backlog exceeds local capacity, `runner` provisions a temporary droplet/worker pre-baked with Docker and `runner worker`.
- **Strict Scale-to-Zero Lifecycle**:
  - Cloud nodes continuously check their job leases.
  - When a cloud node remains idle for **5 consecutive minutes**, it automatically issues a self-terminate API call (`DELETE /v2/droplets/{id}`).
  - This guarantees that promotional cloud credits are preserved strictly for active test execution and never drained by forgotten idle virtual machines.

---

## 6. Pillar 4: Ephemeral Sandboxing, Service Containers & Security

Running self-hosted runners on a personal machine requires rigorous isolation to ensure that test suites or third-party dependencies can never compromise personal files, access host network services, or leave orphan processes behind.

```
+--------------------------------------------------------------------------------------+
|                                   HOST WORKSTATION                                   |
|                                                                                      |
|  Personal Files (/home/linux/*)         Local Network Services (Local DBs, NAS)      |
|  [BLOCKED BY SANDBOX MOUNTS]            [BLOCKED BY NETWORK ISOLATION NAMESPACE]     |
|              ^                                         ^                             |
|              |                                         |                             |
|  +-----------+-----------------------------------------+--------------------------+  |
|  |                             RUNNER SANDBOX BOUNDARY                            |  |
|  |                                                                                |  |
|  |  +--------------------------------------------------------------------------+  |  |
|  |  |                       Ephemeral Job Container / MicroVM                  |  |  |
|  |  |                                                                          |  |  |
|  |  |  - Rootless Execution (Unprivileged UID 1000 map)                        |  |  |
|  |  |  - Isolated Mount Namespace: Only job checkout mounted in tmpfs           |  |  |
|  |  |  - Filtered Network: Outbound GitHub/Package registries only              |  |  |
|  |  |  - Automatic Teardown: Cryptographic scrub of workspace upon exit         |  |  |
|  |  +--------------------------------------------------------------------------+  |  |
|  +--------------------------------------------------------------------------------+  |
+--------------------------------------------------------------------------------------+
```

### 6.1 Sandboxing & Service Container Architecture
Modern CI workflows frequently rely on Docker service containers (e.g. `services: postgres:15` or Testcontainers). Running nested containers inside an unprivileged user namespace on standard Linux distributions (such as Ubuntu 24.04+ with default AppArmor unprivileged user-namespace restrictions) requires careful architectural selection:

1. **Tier 1 (Database & Nested Container Workloads)**: **Firecracker / Cloud-Hypervisor MicroVMs**
   - Boots a lightweight Linux guest kernel in under 150 milliseconds using Linux KVM (`/dev/kvm`).
   - Provides complete hardware virtualization isolation.
   - Runs a dedicated, native Docker/Podman engine inside the guest VM, allowing `services: postgres` and Testcontainers to execute with 100% native compatibility without triggering host kernel AppArmor violations.
2. **Tier 2 (Standard Builds & Linting)**: **Rootless Podman / crun**
   - Extremely lightweight, zero KVM requirement.
   - Ideal for Python, Node.js, and Rust test jobs that do not require nested container engines.

### 6.2 Host File & LAN Protection
- **Filesystem Isolation**: CI jobs never receive access to `/home/linux` or any personal files. Each job executes in an isolated `tmpfs` or encrypted loopback mount (`/tmp/runner-jobs/<job-id>`) that is wiped immediately upon job completion.
- **RFC 1918 Network Firewalling**: `runner` establishes an isolated network namespace that blocks all traffic to private subnets (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`), preventing malicious dependencies or CI steps from probing home routers, NAS devices, or local IoT hardware.

### 6.3 Deep Dive: Tiered Virtualization Matrix (Firecracker MicroVMs vs. Rootless Containers)

Not all CI workloads require the overhead of a full virtual machine, but modern workflows that instantiate database services (e.g., PostgreSQL, Redis) or use Docker-in-Docker / Testcontainers hit severe constraints under pure container sandboxes. `runner` implements a dual-tier execution engine:

#### Virtualization Architecture Matrix:
| Dimension | Tier 1: MicroVM (Firecracker / Cloud-Hypervisor) | Tier 2: Rootless Container (crun / Podman) |
| :--- | :--- | :--- |
| **Primary Workloads** | Database integration suites (`services: postgres`), Testcontainers, Docker-in-Docker | Pure language unit tests, frontend builds (Jest/Vitest), linting, security scans |
| **Isolation Boundary** | Hardware virtualization via Linux KVM (`/dev/kvm`) + Jailer chroot | Linux namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWPID`) |
| **Boot Latency** | **120 ms – 150 ms** | **10 ms – 20 ms** |
| **Kernel Context** | Dedicated guest Linux kernel (ephemeral, single-job) | Shared host Linux kernel |
| **Docker-in-Docker** | **100% Native**: Runs internal dockerd/podman inside guest | Restricted (AppArmor / user namespace security limits) |
| **Disk Storage** | Ephemeral sparse ext4 loopback image with copy-on-write overlay | In-memory `tmpfs` mounted at `/workspace` |
| **Memory Overhead** | ~128 MB guest kernel memory footprint | Zero additional kernel memory footprint |

#### 1. Why MicroVMs Solve the Ubuntu 24.04+ AppArmor Trap
Modern Linux distributions (such as Ubuntu 24.04 LTS) restrict unprivileged user namespaces via AppArmor policies (`kernel.apparmor_restrict_unprivileged_userns = 1`). Running Docker-in-Docker or rootless Podman to execute database services inside standard containers requires either disabling host security knobs or running with insecure `--privileged` flags.

**The `runner` MicroVM Solution**:
- `runner` boots a dedicated, minimal Firecracker guest kernel using `/dev/kvm`.
- The guest kernel runs in its own unprivileged KVM user context on the host. Inside the guest VM, the runner has full kernel authority to spin up `services: postgres:15` or Docker containers without triggering host AppArmor restrictions or compromising host files.
- Upon job completion, the Firecracker process terminates and its ephemeral virtio-block disk is instantly discarded, providing zero residual state.

#### 2. Network Isolation & eBPF Egress Filtering
Both MicroVMs (via TAP devices) and Rootless Containers (via `pasta` / `slirp4netns`) run in dedicated network namespaces:
- **Egress Allowlist**: Outbound DNS (UDP 53), HTTP/HTTPS (TCP 80/443 to GitHub, npm, PyPI, Crates.io).
- **Internal LAN Deny**: eBPF bytecode attached to the egress veth/TAP interface immediately drops packets targeting RFC 1918 private IPv4 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and carrier-grade NAT (`100.64.0.0/10`).

---

## 7. Pillar 5: Direct GitHub Actions Integration

runner connects natively to GitHub's runner API using Just-In-Time (JIT) runner tokens:

### 7.1 JIT Runner Registration Flow
1. The runner Coordinator listens for workflow events via GitHub Webhooks or polling.
2. It requests a JIT configuration from GitHub REST API (`POST /orgs/{org}/actions/runners/generate-jitconfig`).
3. It passes the JIT config string to the isolated sandbox worker.
4. The worker executes the single assigned job and exits. The runner registration is automatically revoked by GitHub upon completion, ensuring zero stale runner registrations in the GitHub UI.

### 7.2 Hybrid Cloud Fallback Configuration
Workflows can easily specify fallback rules so that if the local runner cluster is powered off, jobs seamlessly execute on GitHub's cloud runners:
```yaml
runs-on: ${{ (vars.USE_LOCAL_RUNNER == 'true') && fromJSON('["self-hosted", "runner"]') || 'ubuntu-latest' }}
```

---

## 8. CLI Reference & MCP Tool Specification

### Core Management CLI
```bash
# Initialize runner configuration on host
runner init --org=resub-health --token=<github-pat>

# Start coordinator daemon
runner start --daemon

# Start as Model Context Protocol (MCP) server for AI agents
runner mcp --transport=stdio

# Stop daemon gracefully
runner stop --graceful
```

### Agent Inspection & Control CLI
```bash
# Query real-time machine health, slot availability, and job statuses
runner status --format=json

# Reserve hardware for agent local compilation
runner reserve --cores=4 --ram=8G --duration=10m --reason="codex-local-compilation"

# Release active reservation
runner release --reservation-id="res-7712"

# Temporarily throttle runner to minimum priority (cpu.weight: 1)
runner throttle --level=high --duration=15m

# Inspect failures from the last completed job
runner inspect-logs --job=<job_id> --format=json
```

### Multi-PC Mesh CLI
```bash
# Initialize local LAN mesh cluster (on primary coordinator)
runner mesh init

# Generate encrypted join token for a secondary machine
runner mesh token create --ttl=1h

# Join mesh cluster (on secondary machine)
runner join <mesh-token>

# List all connected nodes on the LAN
runner mesh list --format=json

# Inspect distributed cache hit rates
runner cache stats
```

---

## 9. Phased Implementation Roadmap

```
+-----------------------------------------------------------------------------------------+
|                               PHASED IMPLEMENTATION TIMELINE                            |
|                                                                                         |
|  [ Phase 1: Core Supervisor & Kernel Governor with Official Worker Wrapping ]           |
|  - Standalone Rust/Go supervisor daemon with GitHub JIT runner generation               |
|  - Linux cgroups v2 slice creation with CFS cpu.weight: 1 timer-safe throttling         |
|  - Linux Pressure Stall Information (PSI) background monitoring loop                    |
|  - Ephemeral unprivileged sandbox wrapping official actions/runner.worker binary        |
|                                    |                                                    |
|                                    v                                                    |
|  [ Phase 2: Autonomous AI Agent Interface & Model Context Protocol (MCP) ]              |
|  - Native Model Context Protocol (MCP) server implementation (stdio/SSE)                |
|  - Unix domain socket server (/run/runner.sock) and JSON CLI                       |
|  - Agent reservation primitives (reserve, release, throttle)                            |
|  - AFK Boost Mode (desktop idle / screen lock detection)                                |
|  - Deterministic stack trace and failure diagnostic parser                              |
|                                    |                                                    |
|                                    v                                                    |
|  [ Phase 3: Multi-PC LAN Mesh & Distributed Caching ]                                   |
|  - Coordinator-First JIT dispatch protocol over local mTLS                              |
|  - mDNS peer discovery protocol for zero-config machine joining                         |
|  - ACTIONS_CACHE_URL interception proxy and distributed P2P package cache               |
|  - Laptop thermal (/sys/class/thermal) and battery power guard                          |
|                                    |                                                    |
|                                    v                                                    |
|  [ Phase 4: Production Hardening, MicroVMs & Cross-Platform Release ]                   |
|  - MicroVM isolation engine (Firecracker / Cloud-Hypervisor) for services: containers    |
|  - macOS Apple Silicon support with Darwin QoS (Efficiency Core Pinning)                |
|  - Single-line installer script (`curl -fsSL https://... | sh`)                         |
|  - Starter GitHub Actions workflow templates and open-source release                    |
+-----------------------------------------------------------------------------------------+
```

---

## 10. Conclusion

By shifting CI workloads from costly, metered cloud environments to intelligent, kernel-governed local workstation hardware, runner Runner solves the fundamental economic and performance bottleneck of autonomous AI development.

Developers and autonomous coding agents gain **unlimited, zero-cost, high-parallelism continuous integration** without sacrificing a single millisecond of workstation responsiveness or risking system freezes.
