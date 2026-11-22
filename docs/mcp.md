# Agent Integration via MCP

`runner` exposes its supervisor controls to AI coding agents (Cursor,
Claude Code, Antigravity, generic MCP clients) through a JSON-RPC 2.0
Model Context Protocol server on stdio. Agents query host health and
govern CI pressure without touching the terminal.

## One-command registration

```bash
# Cursor (writes ~/.cursor/mcp.json, merged, originals preserved)
runner mcp install --target cursor

# Claude Desktop (writes ~/.config/Claude/claude_desktop_config.json)
runner mcp install --target claude

# Anything else (prints the snippet; paste it into your client config)
runner mcp install --target generic
```

Registration is merge-only: existing servers are preserved, the previous
file is backed up to `<file>.json.bak`, and invalid JSON is never
touched (the snippet prints instead). For Claude Code's project scope,
paste the generic snippet into `.mcp.json`, or run
`claude mcp add runner -- <path-to-runner> mcp`. Restart the agent
client after installing.

## Daemon convergence (v1.1.0)

State-changing tools (`reserve_host_resources`,
`release_host_resources`, `throttle_runner`, `drain_node`,
`request_cloud_capacity`) and both status queries execute against
the LIVE daemon over the IPC socket — the same state `runner
status`, `runner throttle`, and the coordinator loop see. When the
daemon is unreachable, the server transparently falls back to local
in-process state (today's standalone behavior) and notes it on
stderr; stdio JSON-RPC is never polluted. Tool input/output
schemas are unchanged by this routing (see the frozen contracts
below and `tests/test_schema_freeze.rs`).

## What agents can do

The server speaks newline-delimited JSON-RPC on stdio
(`initialize`, `tools/list`, `tools/call`). Twelve tools are exposed:

| Tool | Purpose |
|---|---|
| `get_ci_status` | Host health, PSI pressure, slots, queues, reservations |
| `get_fleet_topology` | Local / trusted-peer / cloud compute split |
| `reserve_host_resources` | Hold CPU/RAM headroom for local agent work |
| `release_host_resources` | Release a reservation |
| `throttle_runner` | Force weights down (`warning`/`critical`) for a duration — never freezes |
| `request_cloud_capacity` | Burst to cloud within the pre-approved spend cap |
| `drain_node` | Stop dispatching new jobs to a node |
| `diagnose_system` | Host diagnostics (kernel, cgroups, KVM, eBPF, daemon, egress) as JSON |
| `test_provider` | Verify CI provider credentials and connectivity |
| `exec_command` | Run a command under zero-freeze governance; capture output |
| `manage_cloud_capacity` | List, terminate, or purge daemon cloud burst workers |
| `get_cache_stats` | LAN cache entries, size, hits, misses, bandwidth saved |

Example — check status, then throttle a noisy neighbor during a demo:

```jsonc
// tools/call get_ci_status (no arguments)
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "get_ci_status", "arguments": {}}}

// tools/call throttle_runner
{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
 "params": {"name": "throttle_runner",
           "arguments": {"level": "warning", "duration_minutes": 30}}}
```

Manual stdio smoke test without an agent client:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | runner mcp
```

## Frozen tool contracts (v1.0)

Input schemas are served verbatim by `tools/list`; results render as
JSON into the text content block. Errors use JSON-RPC codes:
`-32601` unknown tool, `-32602` invalid params, `-32603` internal.
`tests/test_schema_freeze.rs` pins every name and input schema —
changes must update this doc and that test together.

`get_ci_status` — input `{}`. Output: `status`, `version`, `host`
(same shape as `runner status`), `concurrency`, `governor`
(`last_weight`, `last_slots`, `afk_boost`, `afk_mode`),
`reservations` (`id`, `cores`, `ram_mb`, `reason`), `drained_nodes`,
`forges` (per-forge poll health).

`get_fleet_topology` — input `{}`. Output: `local`
(`total_cores`, `physical_cores`, `available_memory_bytes`,
`max_slots`, `cpu_level`), `wan_peers`, `cloud_nodes`,
`drained_nodes`.

`reserve_host_resources` — input: `cores` (number, required, finite
\> 0), `reason` (string, optional), plus memory from `memory_mb`
(integer, v2) or `ram_gb` (number, v1) and duration from
`duration_secs` (integer, v2) or `duration_minutes` (integer, v1);
v2 fields win when both are present. `priority` (v2, `low`|`normal`|
`high`|`critical`, default `normal`) ranks preemption. Output:
`reservation_id`, `cores`, `ram_mb`, `priority`, `duration_secs`,
`preempted` (evicted ids, empty when the table had room), `reason`.
When the table is full, a strictly higher priority evicts the lowest
leases whose headroom covers the request; otherwise a full table
denies with `-32603` (retryable). Live reservations scale batch
intake slots down until release or expiry. With
`[reservations] monthly_spend_cap_usd` set, grants whose estimated
cost exceeds the remaining budget deny fail-closed (`-32603`); every
grant, release, and preemption lands in the spend ledger and the
SHA-256 audit trail.

`release_host_resources` — input: `reservation_id` (string,
required). Output: `released`. Unknown id → `-32602`.

`throttle_runner` — input: `level` (required, `warning`|`critical`),
`duration_minutes` (integer, required, \> 0). Output: `level`,
`cpu_weight` (25 or 1), `duration_minutes`. Never freezes.

`request_cloud_capacity` — input: `provider` (required,
`digitalocean`|`render`), `max_instances` (integer, required, \> 0),
`duration_hours` (number, required, finite \> 0), `reason` (string,
required). Output when denied: `approved: false`, `reason` (zero
spend cap or missing provider token). Output when approved:
`approved: true`, `provider`, `node_id`, `node_status`,
`max_instances`, `duration_hours`, `budget_cap_usd`. One instance
per call; nodes self-terminate after 5 idle minutes.

`drain_node` — input: `node_id` (string, required, non-empty),
`reason` (string, required). Output: `drained`.

`diagnose_system` — input: `egress` (boolean, optional),
`enterprise` (boolean, optional). Output: the `runner doctor --format
json` report (`checks` with `name`/`status`/`detail`, plus `ok`) with
a `forges` health map merged in.

`test_provider` — input: `provider` (required,
`github`|`gitlab`|`bitbucket`|`local`). Output: `provider`, `ok`
(boolean), `lines` (human-readable diagnostics, including rotation
guidance on credential rejection).

`exec_command` — input: `command` (string array, required,
non-empty), `timeout_secs` (integer, optional, default 60, ≥ 1),
`env` (object, optional). Output on completion: `code`, `stdout`,
`stderr`, `elapsed_secs`, `timeout: false`. Output on timeout:
`timeout: true`, `elapsed_secs` (data, not an RPC error).

`manage_cloud_capacity` — input: `action` (required,
`list`|`terminate`|`purge`), `instance_id` (string, required for
`terminate`). Output for `list`: `action`, `active_nodes`, `nodes`,
`providers`, `spend_usd`, `max_monthly_spend_usd`, `spend_tracked`.
`terminate`/`purge` return the daemon result object. Requires a
running daemon.

`get_cache_stats` — input `{}`. Output when the proxy runs:
`enabled: true` plus `entries`, `size_bytes`, `hits`, `misses`,
`hit_ratio`, `bytes_served`, `bytes_uploaded`, `remote_hits`,
`remote_bytes_imported`, `remote_bytes_served`. Output otherwise:
`enabled: false`. Requires a running daemon.
