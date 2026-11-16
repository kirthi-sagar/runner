# Changelog

All notable releases of `runner`. Dates are release-tag dates (UTC).

> Version-note: the tree jumps 0.1.0 → 0.3.0. No 0.2.x was ever cut;
> the 0.3.0 number landed with the open-core workspace refactor while
> 0.1.0 was still the installed release.

## Unreleased (v0.4.1)

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
