# Roadmap

Streamlined direction for `runner`: harden what exists, then make the
LAN mesh cache-transparent. Identity guardrail: **zero-dependency
single static binary** — accepted work must not require new runtime
services or heavyweight frameworks.

## Shipped (v2.0.1 and prior)

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

## Current: v2.0.1 (Firecracker Framing Fix)

- `put_inner` frames responses; keep-alive no longer hangs Tier-1.
- Live KVM harness verified green on real hardware.

## Next: v2.1.0 (Tier-1 vsock In-Guest Dispatch Verification)

- Verify the Firecracker UDS direction contract on live KVM.
- Guest agent in-image; live harness asserts success end to end.

## Future: v2.2.0 (Windows Hardening)

- Win32 multi-core topology, named-pipe IPC, top telemetry.

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
