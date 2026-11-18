# Changelog

All notable releases of `runner`. Dates are release-tag dates (UTC).

> Version-note: the tree jumps 0.1.0 → 0.3.0. No 0.2.x was ever cut;
> the 0.3.0 number landed with the open-core workspace refactor while
> 0.1.0 was still the installed release.

## v0.6.0 — 2026-11-17

- Workstation guards: thermal throttle at 85°C (trickle weight +
  halved slots, 78°C release) and battery halt (zero slots while
  discharging), with temp/power in status surfaces.
- Cache auth hardening: per-boot random bearer token and
  HMAC-signed download URLs (401 on missing/tampered).
- mDNS LAN advertisement of cache capability with heartbeats.
- Peer fallback ingestion: local misses federate to LAN peers
  (streamed import, graceful 204 fallback).
- Abuse caps (32 MiB chunks, per-archive ceiling) and per-peer
  attribution counters across IPC/CLI/MCP.

## v0.5.2 — 2026-11-17

- Bounded CI output capture: 10 MiB ring per stream, tail wins on
  runaway output (daemon OOM-proof).
- Streaming cache downloads: archives stream from disk with HEAD /
  Range support instead of full-file RAM buffering.
- Cache index writes only on mutation and clean shutdown (no more
  per-lookup disk rewrites).
- README truth pass: version banner, 12 MCP tools, honest
  comparison-table calibration.

## v0.5.1 — 2026-11-17

- Fixed `get_cache_stats` MCP tool returning `{"enabled": false}` by routing queries through daemon IPC.
- Hardened doctor TCP port reachability test against ephemeral port reuse races.

## v0.5.0 — 2026-11-17

- Transparent LAN cache proxy: daemon-embedded `ACTIONS_CACHE_URL`
  server speaking the Actions Cache protocol (lookup with
  restore-key fallbacks, reserve/chunk/commit upload, HEAD +
  Range downloads), verified against the real client source.
- Content-addressed disk store (`~/.runner/cache/`, 10 GB LRU
  budget) with atomic commits and persisted hit/miss stats.
- Automatic `ACTIONS_CACHE_URL` + `ACTIONS_RUNTIME_TOKEN`
  injection into GitHub workers; graceful upstream fallback.
- `runner cache stats` / `runner cache clear`, IPC
  `cache_stats`/`cache_clear`, MCP `get_cache_stats`, dashboard
  KPI cards, and `/health.cache`.

## v0.4.5 — 2026-11-17

- Fail-closed spend ledger: corrupt/unreadable ledgers refuse new
  cloud provisioning (never $0.00 fail-open); the error surfaces
  in `cloud list` and `/health` instead of zero spend.
- Startup orphan reconciliation: live `runner-ci-*` droplets and
  workers are discovered, ledger-recorded, tracked, and reaped
  after the standard idle timeout.
- Standalone scale-to-zero watchdog task (30s cadence), decoupled
  from the GitHub loop; runs with any forge mix or none.
- Provision-failure recovery: failed bursts release the job
  record for retry; watchdog terminations clean up job records.

## v0.4.4 — 2026-11-17

- Atomic slot reservation across all three forge loops: concurrent
  polls can no longer over-dispatch a constrained host.
- Provider-namespaced job lifecycle: identical job IDs from
  different forges coexist; finishing never evicts another forge.
- Broadcast wakeups (`notify_waiters`) rouse every enabled forge.
- Sandboxed git checkout before GitLab/Bitbucket script execution
  (shallow clone with forge token auth; failures stream + fail).
- Per-forge poll health (`last_poll`, `queue_depth`, `last_error`)
  over IPC `status`, MCP `get_ci_status`/`diagnose_system`, and
  `runner status --format json`.
- Doc truth: `[gitlab]`/`[bitbucket]` config reference, `runner
  auth` for all forges, starter TOMLs, cache marked v0.5.0.

## v0.4.3 — 2026-11-17

- Multi-forge daemon wiring: the coordinator supervises GitLab CI
  and Bitbucket Pipelines (poll → claim → sandbox-execute → stream
  logs → report) alongside GitHub, with per-forge loops, capacity-
  first polling, and provider-namespaced in-flight dedup.
- `runner auth gitlab` / `runner auth bitbucket` credential
  management (0600 env file) with config environment overlay.

## v0.4.2 — 2026-11-17

- Fixed fatal daemon abort on startup whenever cloud bursting was
  enabled (`blocking_write` inside the tokio runtime; the
  coordinator spawn path is now fully async).
- In-flight job deduplication: each unique queued job dispatches
  or provisions exactly once across poll ticks.
- Cloud routing resolves the burst provider dynamically
  (DigitalOcean preferred, Render fallback) instead of hardcoding
  DigitalOcean.
- Documentation synchronized with the shipped product (release
  close-out, 11-tool MCP catalog, ledger-backed spend samples).

## v0.4.1 — 2026-11-17

- Persistent cloud spend ledger (`~/.runner/spend_ledger.json`) with
  hard budget stops in the coordinator.
- Dynamic eBPF IHL walking for IPv4 port checks (correct with IP
  options; malformed IHL < 5 drops).
- Mock cloud lifecycle harness proving
  `provision → watchdog poll → terminate` without credentials.
- `runner cloud list`, MCP `manage_cloud_capacity`, and `/health`
  report real spend (`spend_tracked: true`).

## v0.4.0 — 2026-11-16

- Phase 8: MCP expansion to 10 agent-native tools
  (`diagnose_system`, `test_provider`, `exec_command`) via
  dependency-injected `AgentTools` trait.
- Phase 9: embedded zero-dependency web dashboard (`/`, `/dashboard`)
  with host PSI gauges, KPI cards, fleet table, and cloud badge;
  `/health` enriched with PSI, governor level, cloud count.
- Phase 10: scale-to-zero cloud watchdog (5-minute idle reap),
  `runner cloud list|terminate|purge` CLI, MCP tool #11
  (`manage_cloud_capacity`), `CloudNode.launched_at` uptimes.
- 252 tests green; multi-arch (x86_64 + aarch64) release assets.

## v0.3.2 — 2026-11-16

- `runner doctor` host diagnostics (+ `--enterprise`, `--egress`,
  `--format json`) and `runner provider test <name>` credential
  validation.
- Root `--version`/`-V` flag.
- `runner hook install|uninstall`: zero-freeze pre-commit hooks with
  auto-detection (`cargo`/`npm`/`pytest`), `.bak` backups.
- Fix: `runner exec` direct mode inherits the caller's cwd.

## v0.3.1 — 2026-11-15

- `runner top` live terminal monitor (PSI gauges, governor, jobs).
- Webhook listener for sub-second dispatch (`RUNNER_WEBHOOK_SECRET`).
- MCP install helper + audit export; ETXTBSY spawn fix.

## v0.3.0 — 2026-11-15

- Dual-track open-core Cargo workspace (`runner-*` crates).
- Auth/audit/policy CLI, token store, tag release workflow.
- Zero-dependency install via release tarball fallback + one-liner.
- Enterprise hardening: native eBPF egress, Firecracker microVM
  tier, OIDC control plane (`runner server`).

## v0.1.0 — 2026-11-14

- Initial release: zero-freeze cgroups v2 governor (100/25/1 weight
  ladder, PSI poller, AFK boost), JIT-wrapped official worker,
  GitLab/Bitbucket/local provider matrix, 7 MCP tools, WireGuard
  mesh invite/join, DigitalOcean/Render bursting, systemd service.
