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

## What agents can do

The server speaks newline-delimited JSON-RPC on stdio
(`initialize`, `tools/list`, `tools/call`). Eleven tools are exposed:

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
