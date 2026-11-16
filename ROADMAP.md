# Roadmap

Streamlined direction for `runner`: harden what exists, then make the
LAN mesh cache-transparent. Identity guardrail: **zero-dependency
single static binary** — accepted work must not require new runtime
services or heavyweight frameworks.

## Shipped (v0.4.0 and prior)

- Zero-freeze governor, JIT worker wrap, 4-provider matrix.
- 11 MCP tools, embedded dashboard, OIDC control plane.
- Mesh federation, cloud bursting + 5-minute scale-to-zero watchdog.
- eBPF egress, microVM tier, audit/policy, hooks, doctor.

## Next: v0.4.1 Hardening (in progress)

- Persistent spend ledger + coordinator budget stops.
- Dynamic eBPF IHL walking for IPv4.
- Mock cloud lifecycle test harness.
- CHANGELOG + ROADMAP hygiene (this release).

## Then: v0.5.0 Transparent LAN Cache Proxy

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
