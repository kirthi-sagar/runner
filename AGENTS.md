# AGENTS.md — Instructions for Autonomous AI Coding Agents

> **Specification Standard**: [`agents.md`](https://agents.md/)  
> **Project**: `runner`  
> **Repository Purpose**: High-Performance, Zero-Freeze, AI-Agent-Native Local & Federated GitHub Actions Runner Mesh.

---

## 1. Project Context & Philosophy

`runner` is an unprivileged systems daemon written in Rust (2021 edition) that allows local workstations, spare LAN PCs, connected trusted peer nodes (friends & family) over WAN (WireGuard), and ephemeral cloud credit instances (DigitalOcean, Render.com) to execute official GitHub Actions CI jobs without starving foreground applications.

### Non-Negotiable Invariants:
1. **Never Hard-Freeze Active Tests (`cgroup.freeze` Hazard)**: Under high pressure, NEVER call `cgroup.freeze` on active test steps. Always drop `cpu.weight` to `1` ("trickle throttle") so test timers, database connections, and TCP sockets stay alive with ~0.5% CPU while yielding >99% throughput to foreground apps.
2. **100% GitHub Actions Compatibility via Official Worker Wrapping**: Do not emulate GitHub's workflow syntax. Wrap Microsoft's official `actions/runner.worker` binary launched via `./run.sh --jitconfig "<blob>"`.
3. **Strict Sandbox Isolation**: CI jobs execute in ephemeral tmpfs/namespaces. Never mount personal directories (`/home/*`). Block outbound traffic to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) via eBPF/nftables.
4. **Dual-Tier Governance**:
   - **Super Admin (Human User)**: Sovereign authority over spend caps, trusted peer approvals, emergency kill switches (`runner stop --force`).
   - **Admin (Autonomous AI Coding Agent via MCP)**: Operational fleet manager. Dispatches jobs based on hardware capabilities and dynamically throttles weights via MCP tools.

---

## 2. Standards & External References

When implementing, testing, or extending `runner`, align with the following ecosystem standards:
* **Model Context Protocol (MCP)**: [`https://modelcontextprotocol.io/`](https://modelcontextprotocol.io/) — Follow the official JSON-RPC 2.0 schema for stdio transport (`initialize`, `tools/list`, `tools/call`).
* **OpenSandbox (AAIF / Linux Foundation)**: [`https://open-sandbox.ai/`](https://open-sandbox.ai/) — Reference for Firecracker microVM lifecycle, sub-150ms boot times, and egress network filtering.
* **Goose (AAIF / Linux Foundation)**: [`https://goose-docs.ai/`](https://goose-docs.ai/) — Primary open-source Rust agent consumer of `runner mcp`.

---

## 3. Directory Layout & Key Modules

```
runner/
├── Cargo.toml                    # Rust 2021 crate definition
├── README.md                     # Human-facing architectural overview
├── AI_AGENT_RUNNER_SPECIFICATION.md # Authoritative technical blueprint
├── AGENTS.md                     # This file (agents.md specification)
├── src/
│   ├── lib.rs                    # Library root (exports modules for integration tests)
│   ├── main.rs                   # CLI entrypoint and subcommand dispatcher
│   ├── config.rs                 # Host configuration, spend caps, RBAC policies
│   ├── governor/                 # Kernel-level resource control & scheduling
│   │   ├── cgroup.rs             # /sys/fs/cgroup/runner.slice/ (weight 100/25/1)
│   │   ├── psi.rs                # /proc/pressure/{cpu,memory,io} poller (250ms)
│   │   ├── topology.rs           # SMT sibling detection, slot calculation formula (S)
│   │   └── afk.rs                # Wayland/X11 desktop idle state machine
│   ├── sandbox/                  # Ephemeral execution environment
│   │   ├── worker.rs             # ./run.sh --jitconfig lifecycle
│   │   ├── mounts.rs             # tmpfs mounts, /home/* rejection
│   │   └── network.rs            # RFC 1918 firewalling (nftables/eBPF)
│   ├── mesh/                     # Federated Hybrid Mesh
│   │   ├── discovery.rs          # mDNS discovery for local LAN nodes
│   │   ├── peer.rs               # WireGuard P2P overlay for trusted peer nodes (friends & family)
│   │   ├── invite.rs             # Cryptographic invite tokens with donor caps
│   │   └── cloud/                # DigitalOcean & Render.com scale-to-zero burst fleet
│   ├── github/                   # GitHub REST API & JIT token generator
│   └── mcp/                      # Model Context Protocol stdio server
└── tests/                        # Integration test suite (test_topology, test_psi, etc.)
```

---

## 4. Build, Test & Run Directives for AI Agents

### Check & Test
```bash
# Run full unit and integration test suite (all workspace crates)
cargo test --workspace

# Check code formatting and linter
cargo clippy --workspace --all-targets -- -D warnings
```

### Inspect Host Telemetry
```bash
# Query real-time machine health, slots, and PSI metrics in JSON
./target/debug/runner status --format=json
```

### Start MCP Server for Agent Integration
```bash
# Launch JSON-RPC 2.0 stdio server
./target/debug/runner mcp --transport=stdio
```

---

## 5. Coding Conventions for Agents

1. **Async Runtime**: Use `tokio` for all asynchronous tasks and I/O.
2. **Error Handling**: Use `anyhow` or `thiserror`. Return descriptive errors with structured context.
3. **No Unsafe Code**: Avoid `unsafe` blocks unless directly interfacing with libc / nix syscalls for cgroups and namespaces, and encapsulate them with clear invariants.
4. **Zero Residual State**: Ephemeral workspaces and cloud instances MUST have deterministic teardown logic (`tmpfs` unmount, `DELETE /v2/droplets/{id}`).
