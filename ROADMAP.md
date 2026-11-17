# Roadmap

Streamlined direction for `runner`: harden what exists, then make the
LAN mesh cache-transparent. Identity guardrail: **zero-dependency
single static binary** — accepted work must not require new runtime
services or heavyweight frameworks.

## Shipped (v0.4.2 and prior)

- Zero-freeze governor, JIT worker wrap, 4-provider matrix.
- 11 MCP tools, embedded dashboard, OIDC control plane.
- Mesh federation, cloud bursting + 5-minute scale-to-zero watchdog.
- eBPF egress, microVM tier, audit/policy, hooks, doctor.
- Spend ledger + budget stops, dynamic eBPF IHL walking, mock
  cloud lifecycle harness.

## Current: v0.4.3 Multi-Forge Daemon Wiring

- GitLab CI + Bitbucket Pipelines coordinator loops.
- Provider-namespaced in-flight deduplication.
- `runner auth` credentials for all forges.

## Shipped in v0.4.2: Stability & In-Flight Dedup

- Fixed coordinator startup abort with cloud bursting enabled.
- In-flight job deduplication across poll ticks.
- Dynamic cloud provider resolution (DigitalOcean / Render).
- Documentation synchronized with the shipped product.

## Next: v0.5.0 Transparent LAN Cache Proxy

- `ACTIONS_CACHE_URL`-compatible cache endpoint served from LAN
  peers: cache hits stay on the local network instead of reaching
  the internet, cutting job setup time on warm meshes.
- Content-addressed store with TTL eviction and per-repo isolation.
- Mesh-advertised capability with graceful fallback when no cache
  peer is present.

## Explicit non-goals

Rejected to protect runner's core identity (see v0.4.1 planning):

- Tetragon runtime enforcement (external daemon dependency).
- AWS Nitro Enclaves / confidential-compute tiers.
- MCP Streamable HTTP transport (stdio stays the agent surface).
- Hosted control-plane SaaS; the control plane remains embeddable
  and self-hosted.
