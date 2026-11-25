# Roadmap

Streamlined direction for `runner`: harden what exists, then make the
LAN mesh cache-transparent. Identity guardrail: **zero-dependency
single static binary** — accepted work must not require new runtime
services or heavyweight frameworks.

## Shipped (v2.16.0 and prior)

- World-class hybrid web console & RBAC: `runner dashboard` / `runner ui`
  CLI (loopback serve, fail-open browser launch, pre-shared console
  token), authenticated SSE metrics streaming (`/api/v1/stream`),
  Viewer/Operator/Admin roles resolved from OIDC groups with HTTP
  401/403 enforcement (v2.16.0, Candidate K delivered).
- Air-gapped single-bundle console UI: zero-dependency embedded page
  with live PSI gauges, governor meters, jobs/OCI/swarm telemetry,
  fetch-streaming SSE consumer (reconnect, watchdog, session
  expiry), and role-gated action buttons with confirmations.
- RBAC-gated mutation endpoints: `POST /api/v1/jobs/:id/cancel`
  (administrative supervisor cancel + `job_cancel` IPC),
  `/api/v1/cache/prune` (dry-run capable, off-runtime), and
  `/api/v1/swarms/:id/kill`, plus `GET /api/v1/whoami` identity.
- Actor-attributed audit logging: every authorized mutation lands
  in the tamper-evident SHA-256 ledger (fail-open and loud), with
  `RUNNER_SOCK` / `RUNNER_AUDIT_LOG` overrides keeping tests hermetic.
- Hardware Copy-on-Write (CoW) Snapshots: zero-dependency cross-platform
  block cloning engine (`crates/runner-core/src/fs/cow.rs`), APFS `clonefile`,
  Linux `ioctl(FICLONE)` and `copy_file_range`, Windows ReFS
  `FSCTL_DUPLICATE_EXTENTS_TO_FILE`, empirical capability probe, and
  recursive tree cloner (v2.15.0 & v2.15.1, Candidate I delivered).
- OCI Image rootfs snapshot cache (`crates/runner-sandbox/src/oci/snapshot.rs`):
  atomic `.complete` sentinel, instant <5ms container rootfs provisioning,
  fail-open staging resilience, and snapshots-first storage GC eviction.
- AI Agent workspace snapshots and rollback (`runner snapshot` CLI + MCP
  `runner_snapshot` tool) with 4-phase scan-then-act recursive reconciler.
- `runner doctor` CoW storage capability probe and diagnostics reporting
  Native block cloning vs Fallback plain copy.
- Windows native snapshot test assertion fix for non-Unix exotic file clones
  achieving 100% green 6/6 CI on `main` (v2.15.1).

- Disk pressure-gated cache eviction & safety signpost: two-tier
  storage governor (90% high trigger, 80% low target), `runner image rm`,
  Plentiful Disk Invariant (<90% untouched), `runner doctor` storage check
  (v2.13.0, Candidate G delivered).
- Forge federation & universal device-code auth (`runner auth`):
  RFC 8628 OAuth device flow for GitHub, gitlab.com, and self-hosted GitLab,
  0600 POSIX / owner-only Win32 DACL store with cross-process flock,
  native git credential helper (`runner auth git-credential`) with
  line-injection defense, daemonless OCI cross-auth with realm SSRF
  defense and manifest byte hashing (v2.14.0, Candidate H delivered).
- Zero-freeze governor, JIT worker wrap, 4-provider matrix.
- 12 MCP tools, embedded dashboard, OIDC control plane.
- Mesh federation, cloud bursting + 5-minute scale-to-zero watchdog.
- eBPF egress, microVM tier, audit/policy, hooks, doctor.
- Spend ledger + budget stops, dynamic eBPF IHL walking, mock
  cloud lifecycle harness.
- Real `runner init` onboarding (config merge, token store, layout seed).
- Tier-1 vsock guest dispatch (`runner-guest-agent`, loopback-gated).
- Zero-flake spawn retry, zero doc warnings, opt-in live-KVM harness.
- WAN peer WireGuard execution transport (loopback-gated, direct peers).
- macOS Apple Silicon port (Darwin QoS pinning, launchd, CI matrix).
- NAT traversal for WAN peers (STUN reflexive discovery, observed-source
  routing through cone + symmetric NAT, JoinAccept).
- Per-repo cache isolation (`owner/repo` namespacing, legacy `global`
  fallback) + doctor NAT diagnostics.
- Supply-chain gates, pruned tokio, IPv6 eBPF walk, docs truth (v1.7.1).
- WSL2 supported path: preflights, smoke CI, doctor expectation (v1.7.2).
- Native Windows Tier-3 MVP: cross-compiled exe, shims, install.ps1 (v1.8.0).
- Native windows-latest CI: 6th green job, full suite on real Windows (v1.8.1).
- macOS Seatbelt Tier-2: sandbox_init FFI, job profiles, pre_exec hook (v1.9.0).
- Seatbelt TMPDIR carve-out + doctor Tier-2 verdict fix (v1.9.1).
- Native Windows Job Objects governor: Win32 sensing, weight ladder (v2.0.0).
- Firecracker HTTP framing fix: header/Content-Length reads (v2.0.1).
- Tier-1 in-guest dispatch: vsock suffix, musl agent, live success (v2.1.0).
- Windows hardening: Win32 topology, named-pipe IPC, stop/top (v2.2.0).
- Strict sandbox mode: fail-closed exec/start/doctor guardrails (v2.3.0).
- Strict everywhere + audit trail: daemon strict, DACLs, spend gate (v2.4.0).
- Mobile worker & hardware resilience: vsock drain, power engine, audit (v2.5.0).
- Windows WFP egress filtering & universal network boundary: dynamic
  session, parity suite, eBPF fixes, job-scoped guard (v2.6.0).
- MCP dynamic resource reservations: v2 envelopes, preemption,
  spend ledger, expiry watchdog (v2.7.0).
- Network boundary hardening follow-through: Seatbelt network
  verbs, per-job WFP app scoping, nftables attach, configurable
  reservation limits & pricing (v2.8.0).
- LAN mesh cache federation & peer streaming: background peer
  table, scatter-gather queries, verified chunk streaming, donor
  governance + `cache peers` CLI (v2.9.0, Candidate B delivered).
- Container runtime isolation tier: OCI probing, rootless
  lifecycle, egress/offline boundaries, CLI/doctor/MCP wire-up
  (v2.10.0, Candidate D delivered).
- Windows clippy patch: cfg-gated timeout const, platform-split
  exec-bit helper (v2.10.1).
- Standalone OCI image pull & layer assembly: registry client,
  verified layer cache, safe unpacker, auto-pull, `runner image`
  CLI, platform-aware doctor guidance (v2.11.0, Candidate E
  delivered).
- Windows symlink patch: portable container-absolute link
  resolution across Windows-MSVC and Windows-GNU (v2.11.1).
- Autonomous multi-agent swarms: session protocol, 0ms handover,
  priority preemption, spend ledger, multi-tier dispatch, event
  bus, `runner swarm` CLI, doctor integration (v2.12.0,
  Candidate F delivered).
- Supply-chain patch: `publish = false` workspace protection
  satisfying `cargo deny` under the commercial license (v2.12.1).

## Active Milestone: Candidate L ("Fortress Runner" Adversarial Pentest & Continuous Fuzzing)

### Candidate L: Internal Adversarial Pentest & Continuous Fuzzing ("Fortress Runner")
- **Stage 1: Internal Adversarial "Red Team" Exploit Suite** (`tests/test_adversarial_sandbox.rs`):
  - Sandbox escape & jailbreak defense (OCI rootless container and Firecracker microVM boundary checks).
  - Network egress boundary evasion testing (blocking raw sockets, DNS exfiltration, loopback redirects).
  - Filesystem boundary & containment enforcement (Tar-Slip traversal, symlink host leaks, ReFS/APFS CoW escapes).
  - Denial of Service & resource exhaustion resilience (fork bomb immunity via cgroups/Job Objects, zip bomb budget).
  - Credential store protection (0600 flock file integrity, zero-memory token exposure).
- **Stage 2: Continuous Fuzz Testing** (`cargo-fuzz` / `libFuzzer`):
  - OCI layer Tar unpacker and whiteout resolver fuzzing with corrupted byte streams.
  - Git credential helper protocol parser fuzzing (validating \r\n and injection defense).
  - JSON-RPC MCP server message dispatch fuzzing.
  - OCI registry manifest parser and HTTP chunk framing fuzzing.

### Candidate J: Peer-to-Peer Web Tunnels & Silicon GPU Acceleration
- Direct agent NAT-bypassing tunnels over WebRTC DataChannels with zero relay servers.
- Apple Silicon (Metal) and NVIDIA (CUDA) GPU acceleration pass-through for local AI coding agents.

## Shipped in v2.9.0: LAN Mesh Cache Federation & Peer Streaming

- Continuous mDNS peer table with 0ms miss-path snapshots.
- Scatter-gather first-responder streaming with cancellation.
- Digest-verified imports + donor concurrency governance.

## Shipped in v2.8.0: Network Boundary Hardening Follow-Through & Resource Governance

- Full cross-platform network egress boundary: Seatbelt verbs,
  app-scoped WFP, privileged nftables attach.
- Configurable reservation ceilings + transfer pricing.
- Per-request `-32602` enforcement of configured limits.

## Shipped in v2.7.0: MCP Dynamic Resource Reservations

- Versioned reservation envelopes with priority preemption.
- Budget-gated spend ledger + SHA-256 audit trail.
- Expiry watchdog with instant headroom reclamation.

## Shipped in v2.6.0: Windows WFP Egress Filtering & Universal Network Boundary

- Dynamic WFP session with 11 ALE connect filters on native Windows.
- Three-way egress parity suite; eBPF JEQ32 + v6 walk fixes.
- Job-scoped `EgressGuard` with fail-closed canary verification.

## Shipped in v2.5.0: Mobile Worker & Hardware Resilience

- MicroVM graceful teardown, cross-platform power interception.
- Pre-sleep quiesce, resume reconciliation, clamshell wake lock.

## Shipped in v2.4.0: Strict Everywhere, macOS Parity & Windows Security

- Full-chain strict, macOS coordinator Seatbelt, Windows DACLs.
- Double-start prevention, ledger spend gate, live audit trail.

## Shipped in v2.3.0: Strict Sandbox Mode

- `--strict` flag, config, and env override across exec/doctor/start.
- macOS Seatbelt detection fix for local execution.

## Shipped in v2.2.0: Windows Hardening

- Win32 topology, named-pipe IPC + doctor probe, native stop.
- Live `top` gauges with a console loop; zero doc warnings.

## Shipped in v2.1.0: Tier-1 In-Guest Dispatch

- Host listens on `<uds>_<port>`; agent runs as guest `/init`.
- Live harness executes in-guest and asserts exit 0 on real KVM.

## Shipped in v2.0.1: Firecracker Framing Fix

- `put_inner` frames responses; keep-alive no longer hangs Tier-1.
- Live KVM harness verified green on real hardware.

## Shipped in v2.0.0: Windows Job Objects Governor

- `governor::windows`: sensor, RAII job manager, 9/5/1 weights.
- Worker trees auto-contained; `doctor` reports governor active.

## Shipped in v1.9.1: Seatbelt TMPDIR + Doctor Verdict

- Profile allows writes to system temp dirs + `$TMPDIR`.
- `doctor` reports `active (Seatbelt)` when the facility probes working.

## Parked: macOS Tier-1 microVM (was v1.10.0)

Live Virtualization.framework guests are parked, not cancelled. Two
independent blockers, both verified against primary sources: GitHub
closed nested virtualization for Apple Silicon hosted runners as
not-planned (`actions/runner-images#13505`), so `kern.hv_support` is
0 on `macos-latest` and a VZ guest cannot boot in CI — shipping it
would violate "CI proves what ships"; and the framework mandates the
`com.apple.security.virtualization` entitlement, against the
zero-entitlements invariant. Re-entry when either GitHub enables
nested virt or the project accepts a self-hosted Mac for Tier-1
verification. The macOS track resumes at Tier-2 Seatbelt (✅) as the
isolation story; the Windows governor (v2.0.0) shipped first because
it is fully provable on hosted runners.

## Shipped in v1.9.0: macOS Seatbelt Tier-2

- `seatbelt.rs`: sandbox_check nesting guard, in-memory profile builder.
- Tier-2 on macOS: Seatbelt confinement with soft-fail (no entitlements).

## Shipped in v1.8.1: Native Windows CI

- `windows-native` job: fmt, clippy, full test suite, install.ps1 smoke.
- POSIX test triage (platform argv pairs, cfg gates), LF gitattributes.

## Shipped in v1.8.0: Native Windows Tier-3 MVP

- `cfg(windows)` shims with loud unsupported logging; MinGW cross job.
- `install.ps1`, `docs/windows.md`, platform badge + support table.

## Shipped in v1.7.2: WSL2 Supported Path

- `docs/windows.md`, installer preflights, `wsl2-smoke` CI job.
- `doctor` reports WSL2 identity + systemd readiness.

## Shipped in v1.7.1: Supply Chain, Hardening & Documentation Truth

- `deny.toml` + audit CI gate, `--locked` releases, minimal tokio.
- IPv6 extension-header walk, SAFETY docs, spec alignment.

## Shipped in v1.7.0: Per-Repo Cache Isolation & Doctor NAT Diagnostics

- Scoped proxy routes + store indices; slug injection on both paths.
- `doctor` reports reflexive address + NAT class (never fails offline).

## Shipped in v1.6.0: NAT Traversal for WAN Peers via STUN

- Zero-dependency RFC 5389 client; hole-punching via the WG handshake.
- Hermetic NAT simulation gates (cone + symmetric) in CI.

## Shipped in v1.5.0: macOS Apple Silicon & Darwin QoS Portability

- Workspace compiles for both Apple targets; QoS pins CI to E-cores.
- launchd installer, macOS CI + release assets, hermetic QoS tests.

## Shipped in v1.4.0: WAN Peer WireGuard Execution Transport

- Coordinator dispatches to `active` peers over Noise-encrypted UDP.
- Join-announce onboarding, donor caps, leases, loopback gates.

## Shipped in v1.3.1: Zero-Flake Hardening & Test Harness

- Transient spawn retry, zero doc warnings, opt-in live-KVM harness.
- No behavior change beyond reliability; patch release.

## Shipped in v1.3.0: Tier-1 vsock Guest Dispatch

- `exec --driver microvm` runs workloads via the in-guest agent over
  vsock (shared NDJSON protocol, streamed stdio, exit codes).
- UDS loopback tests are the CI gates; live KVM boots stay manual-only.

## Shipped in v1.2.0: Real `runner init` Onboarding

- `runner init` writes `config.toml`, merges idempotently, stores
  `--token` in the 0600 env file, and prints next steps.
- Unparsable configs fail closed; report text never contains secrets.

## Shipped in v1.1.0: Daemon IPC Convergence & Zero-Panic Hardening

- MCP tools converge onto live daemon state over IPC, with local
  fallback when the daemon is unreachable.
- Zero production panic paths under `panic = "abort"` (audited).
- Federation posture: the operator runs a single laptop plus
  GitHub Codespaces (cloud WAN); RFC 6762 mDNS does not cross
  WAN boundaries, so the loopback two-proxy seam tests in
  `tests/test_mesh_cache_federation.rs` are the authoritative
  federation gate in CI and development — physical multi-PC
  testing never blocks a release.

## v1.0.0 GA (shipped)

- Schema-freeze tests green with zero doc drift; asset smoke
  green on every tag (plus release-binary execution smoke).
- Doctor-clean install; zero known Fail-default doctor paths.
- Federation gate: two-proxy loopback seam tests are
  authoritative (single laptop + Codespaces WAN cannot route
  link-local mDNS; physical two-laptop Wi-Fi does not block GA).
- WAN peer WireGuard transport stays a post-v1.0 enterprise
  extension (shipped in v1.4.0); routing remains fail-closed.

## Shipped in v1.0.0: GA Hardening & Production Polish

- Release-binary execution smoke; CI OS matrix (22.04 + latest).
- Installer fail-closed checksums, `--uninstall`, macOS early exit.
- Panic elimination: forge skips, eBPF `Result`, signal fallback.
- `runner throttle` CLI + hidden-command docs + format-truth fix.

## Shipped in v0.9.0: v1.0 Release Candidate

- Hermetic test isolation (TempDir nonces); `auth status` masked.
- Provider rotation guidance; CLI/MCP JSON schema freeze.

## Shipped in v0.8.0: Production Diagnostics & GA Readiness

- `doctor` covers cache, workstation guards, and AFK (Pass/Warn only).
- Installer/asset smoke tests; MCP `diagnose` shares doctor output.
- ROADMAP reverse-chronological order + v1.0 horizon draft.

## Shipped in v0.7.0: Workstation Autonomy, Background Cache TTL & Routing Hardening

- AFK Boost: loginctl idle probing (auto/always/never) + status visibility.
- Background cache TTL sweep (creation-age eviction, hourly).
- WAN routing fail-closed with same-tick cloud fallback.

## Shipped in v0.6.0: Mesh Cache Federation & Workstation Safety

- mDNS P2P LAN cache sharing across machines on one network.
- Thermal guard (CPU throttle past 85°C) + battery drain guard.

## Shipped in v0.5.2: Daemon Resilience, Memory Safety & Doc Truth

- Bounded output capture + streaming cache downloads.
- Index persistence optimization + shutdown flush.
- README truth synchronization.

## Shipped in v0.5.1: MCP Cache Stats Patch

- `get_cache_stats` routed through daemon IPC (live counters).
- Hardened TCP reachability test against port-reuse races.

## Shipped in v0.5.0: Transparent LAN Cache Proxy

- `ACTIONS_CACHE_URL` proxy server + content-addressed store.
- Worker injection + `runner cache` operator CLI.
- Cache visibility across IPC/MCP/dashboard/health.

## Shipped in v0.4.5: Cloud Money Safety

- Fail-closed spend ledger enforcement.
- Startup orphan reconciliation + always-run watchdog.
- Provision-failure recovery + job cleanup.

## Shipped in v0.4.4: Multi-Forge Hardening

- Atomic slot reservation + namespaced job lifecycle.
- Broadcast wakeups for all forge loops.
- Sandboxed git checkout before forge scripts.
- Per-forge health over IPC/MCP/CLI + doc truth.

## Shipped in v0.4.3: Multi-Forge Daemon Wiring

- GitLab CI + Bitbucket Pipelines coordinator loops.
- Provider-namespaced in-flight deduplication.
- `runner auth` credentials for all forges.

## Shipped in v0.4.2: Stability & In-Flight Dedup

- Fixed coordinator startup abort with cloud bursting enabled.
- In-flight job deduplication across poll ticks.
- Dynamic cloud provider resolution (DigitalOcean / Render).
- Documentation synchronized with the shipped product.

## Shipped in v0.4.1: Spend Ledger, eBPF IHL & Mock Harness

- Persistent spend ledger with hard budget stops.
- Dynamic eBPF IHL walking (IP options correct).
- Mock cloud lifecycle harness (no credentials).

## Shipped in v0.4.0: MCP Expansion, Dashboard & Cloud Watchdog

- MCP expansion to 10 agent-native tools (`AgentTools` trait).
- Embedded web dashboard + enriched `/health`.
- 5-minute scale-to-zero cloud watchdog + `runner cloud` CLI.

## Explicit non-goals

Rejected to protect runner's core identity (see v0.4.1 planning):

- Tetragon runtime enforcement (external daemon dependency).
- AWS Nitro Enclaves / confidential-compute tiers.
- MCP Streamable HTTP transport (stdio stays the agent surface).
- Hosted control-plane SaaS; the control plane remains embeddable
  and self-hosted.
