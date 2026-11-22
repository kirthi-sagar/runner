# Frozen CLI JSON contracts (v1.0)

Machine-readable output shapes for the four JSON CLI surfaces.
`tests/test_schema_freeze.rs` pins every key set — changes must
update this doc and that test together. All four accept
`--format json`: `doctor`, `cache stats`, and `cloud list` default
to `text`, while `status` defaults to a one-line human summary.

## `runner status --format json`

Prefers the daemon's state-enriched report over IPC; falls back to a
local kernel read when the daemon is down.

- `status`: `"healthy"` (fixed string).
- `version`: semver string (e.g. `"2.8.0"`).
- `host`: `total_cores`, `physical_cores`,
  `available_cores_for_ci`, `total_memory_bytes`,
  `available_memory_bytes`, `psi_pressure` (`cpu_some_avg10`,
  `memory_some_avg10`, `io_full_avg10`, `cpu_level`),
  `cgroup_weight` (number or null), `temperature_c` (number or
  null), `discharging` (boolean).
- `concurrency`: `max_slots`, `active_slots`,
  `queued_github_jobs`, `afk_boost` (boolean), `afk_mode`
  (`"auto"`|`"always"`|`"never"`).
- `active_jobs`: array, currently always empty (reserved).
- `mesh_nodes`: array, currently always empty (reserved).
- `governor_error`: optional string, present only when a kernel
  read failed (safe fallbacks used for the affected fields).
- `forges`: optional per-forge poll-health map, present only on
  daemon-enriched reports.

## `runner doctor --format json`

- `ok`: boolean — false iff any check has status `"fail"`
  (warnings keep `ok: true`; exit code mirrors it).
- `checks`: array of `name` (e.g. `kernel`, `cgroupsv2`, `userns`,
  `kvm`, `ebpf`, `daemon`, `mcp`, `cache`, `guards`, `afk`, `nat`, `wsl`,
  plus `policy`/`audit` with `--enterprise` and `egress:*` with
  `--egress`), `status` (`"pass"`|`"warn"`|`"fail"`), `detail`
  (human-readable string; the `nat` detail carries the reflexive
  address and class).

## `runner cache stats --format json`

Requires a running daemon (same `cache_stats` IPC method as the
`get_cache_stats` MCP tool, minus the `enabled` wrapper):
`entries`, `size_bytes`, `hits`, `misses`, `hit_ratio`,
`bytes_served`, `bytes_uploaded`, `remote_hits`,
`remote_bytes_imported`, `remote_bytes_served`.

## `runner cloud list --format json`

The spend surface (there is no separate `spend` command).
Requires a running daemon.

- `nodes`: array of `id`, `provider`, `status`, `uptime`
  (human duration string, e.g. `"3m"`).
- `spend_usd`: ledgered month spend (0.0 when untracked).
- `max_monthly_spend_usd`: Super Admin cap (0 disables bursting).
- `spend_tracked`: boolean — false when no ledger backs the pool.
- `spend_error`: string or null — set when the ledger exists but
  is unreadable (fail-closed signal; bursts refused).
