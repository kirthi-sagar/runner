# Roadmap

Streamlined direction for `runner`: harden what exists, then make the
LAN mesh cache-transparent. Identity guardrail: **zero-dependency
single static binary** — accepted work must not require new runtime
services or heavyweight frameworks.

## Shipped (v0.8.0 and prior)

- Zero-freeze governor, JIT worker wrap, 4-provider matrix.
- 12 MCP tools, embedded dashboard, OIDC control plane.
- Mesh federation, cloud bursting + 5-minute scale-to-zero watchdog.
- eBPF egress, microVM tier, audit/policy, hooks, doctor.
- Spend ledger + budget stops, dynamic eBPF IHL walking, mock
  cloud lifecycle harness.

## Next: v0.8.0 Production Diagnostics & v1.0 GA Readiness

- v0.8.0: `doctor` covers cache, workstation guards, and AFK;
  installer/asset smoke tests; roadmap truth.
- v1.0.0 GA criteria: doctor-clean fresh install on
  Ubuntu/Debian/Arch/Fedora; release-asset smoke green on every
  tag; zero known Fail-default doctor paths; WAN transport
  shipped or documented out-of-scope; two-machine LAN
  federation verified; `runner.*` API/error-shape freeze.

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

## Later: cache federation follow-ups

- Per-repo isolation once the protocol can carry repo identity
  (standard clients send none).

## Explicit non-goals

Rejected to protect runner's core identity (see v0.4.1 planning):

- Tetragon runtime enforcement (external daemon dependency).
- AWS Nitro Enclaves / confidential-compute tiers.
- MCP Streamable HTTP transport (stdio stays the agent surface).
- Hosted control-plane SaaS; the control plane remains embeddable
  and self-hosted.
