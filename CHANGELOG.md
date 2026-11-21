# Changelog

All notable releases of `runner`. Dates are release-tag dates (UTC).

> Version-note: the tree jumps 0.1.0 → 0.3.0. No 0.2.x was ever cut;
> the 0.3.0 number landed with the open-core workspace refactor while
> 0.1.0 was still the installed release.

## v2.0.1 — 2026-11-21

- Fix Firecracker API client hang: frame HTTP responses by headers
  + Content-Length instead of waiting for EOF (the server answers
  keep-alive and never closes). Bounded 30s reads, fail-closed caps.
- Live KVM harness proven green on real hardware for the first time.

## v2.0.0 — 2026-11-21

- Native Windows governor via Job Objects: Win32 pressure sensing
  (`GlobalMemoryStatusEx` + `GetSystemTimes`) feeding the shared
  pressure ladder with Windows `%` bands.
- RAII job manager: post-spawn worker assignment, memory ceilings,
  weight-based CPU control (9/5/1, never-freeze), kill-on-close.
- Supervisor loop runs on Windows (250ms cadence, `ctrl_c`
  shutdown); `runner doctor` reports governor `active (Job Objects)`.
- macOS Tier-1 microVM parked (no nested virt on hosted runners,
  entitlement mandate); Windows track advanced first.

## v1.9.1 — 2026-11-21

- Seatbelt profile allows writes to `/private/tmp`, `/private/var/tmp`,
  and the canonicalized `$TMPDIR` (linker tempfiles and build caches
  no longer fail under Tier-2).
- `runner doctor` Tier-2 verdict reports `active (Seatbelt)` on macOS
  when the facility probe passes, degraded warning otherwise.

## v1.9.0 — 2026-11-21

- macOS Tier-2 sandbox via Apple Seatbelt: `sandbox_init` FFI in the
  `pre_exec` child hook, no entitlements required.
- In-memory job profiles: credentials/config unreadable, writes
  confined to the job workspace, network outbound open.
- Nesting guard (`sandbox_check`) and soft-fail on apply errors;
  `sandbox_init` deprecation documented as future-removal risk.

## v1.8.1 — 2026-11-21

- Native `windows-latest` CI (6th green job): the full hermetic suite now
  runs on real Windows alongside Linux, closing the CI parity gap.
- POSIX-only tests triaged for Windows: per-platform argv pairs in the
  local-exec suite, `#[cfg(unix)]` gates on shell-fixture unit tests,
  platform-aware worker argv/asset assertions.
- `.gitattributes` pins LF checkouts on every platform (CRLF class fix).
- `install.ps1` smoke runs for the first time in CI (native install path).

## v1.8.0 — 2026-11-20

- Native Windows Tier-3 MVP (degraded-but-honest): the workspace
  cross-compiles to `x86_64-pc-windows-gnu` via a MinGW CI job, and
  releases ship `runner-windows-x86_64.exe` (+ sha256). Every
  Linux-only subsystem carries a `cfg(windows)` stub that logs its
  feature name and fails loudly — governor, Tier-2 sandbox, Tier-1
  microVMs, IPC, `top` — while Tier-3 dispatch, mesh transport, and
  STUN work unchanged. New `install.ps1` (no admin), `docs/windows.md`
  native section, platform badge, and per-OS support table.

## v1.7.2 — 2026-11-20

- WSL2 supported path: new `docs/windows.md` (systemd, NAT-vs-mirrored,
  `/home` rule, Vmmem limits), installer preflights that fail closed on
  missing systemd or `/mnt` checkouts, a `wsl2-smoke` CI job on
  `windows-latest`, and a `doctor` WSL identity/readiness check. The
  platform badge claim is now verified instead of asserted.

## v1.7.1 — 2026-11-20

- Supply-chain gates: `deny.toml` policy (duplicate bans, permissive
  licenses, advisories, crates.io-only sources) enforced by a new CI
  step, releases build with `--locked`, and the tokio `full` feature
  shrinks to the 10 actually-used features. Dependencies unified
  where possible (nix 0.31, base64 0.23); the syn 2/3 proc-macro
  split and the base64 ecosystem split stay documented skips.
- eBPF egress hardening: the IPv6 filter walks up to 4 extension
  headers (Hop-by-Hop, Routing, Fragment, Destination Options)
  instead of assuming a fixed 40-byte header, closing the
  header-chaining port-smuggling bypass; non-first fragments and
  unwalkable headers drop. Packet-level tests pin the walk.
- Documentation truth: new `docs/cache-isolation.md`, spec §8/§9
  aligned with the shipped CLI and release history, `// SAFETY:`
  comments on the terminal handling in `top.rs`.

## v1.7.0 — 2026-11-20

- Per-repo cache isolation: the transparent proxy namespaces entries
  by `owner/repo` scope (`/repos/:owner/:repo/_apis/...` routes,
  `(scope, version, key)` store indices), so multi-tenant meshes never
  share or collide dependency caches across repositories. Workers get
  a scoped `ACTIONS_CACHE_URL` on local dispatch and WAN peers (via
  the peer's own loopback proxy); legacy unscoped clients and
  pre-v1.7.0 index rows fall back to a `global` namespace with no
  wipe. Federation imports only the requesting scope.
- WAN wire note: `JobOffer` gains an optional `repo` slug — old peers
  reject v1.7.0 offers (same one-directional pattern as v1.6.0), with
  safe same-tick fallback; upgrade peers first.
- Doctor NAT diagnostics: `runner doctor` reports the STUN reflexive
  address and NAT class (`direct`/`cone`/`symmetric`) in text and
  `--format json`, warning (never failing) when offline or symmetric.

## v1.6.0 — 2026-11-20

- NAT traversal for WAN peers: friends-and-family donors behind home
  routers federate with no public IPs or port forwarding. The
  coordinator routes via the observed announce source (the NAT binding
  the announce itself opened — valid through symmetric NAT), prefers
  same-subnet LAN candidates, and hole-punches with the WireGuard
  handshake itself; a new encrypted `JoinAccept` confirms acceptance.
- Zero-dependency RFC 5389 STUN client (`mesh::stun`): reflexive
  discovery over the shared transport socket (pump intercepts
  responses by shape + transaction id), `[mesh] stun_servers`
  (default Google + Cloudflare, empty list disables), a log-only
  symmetric heuristic, and a one-shot `runner join` NAT diagnostic.
- Wire compat is one-directional: v1.6.0 coordinators serve older
  peers, but older coordinators reject v1.6.0 announces — upgrade
  coordinators first. Hermetic `test_mesh_stun` (mock STUN + cone /
  symmetric NAT simulation) is the CI gate.

## v1.5.0 — 2026-11-20

- macOS Apple Silicon port (spec §3.5): the workspace compiles for
  `aarch64`/`x86_64-apple-darwin` (Linux-only namespaces + eBPF
  probes cfg-gated with graceful fallbacks; no dependency changes).
- Darwin QoS pinning (`governor::darwin`): worker children background
  themselves via `setpriority(PRIO_DARWIN_BG)` + pthread QoS FFI
  (`QOS_CLASS_BACKGROUND`, SDK-verified) through a mockable seam, so
  XNU schedules CI onto Efficiency cores; slots from
  `available_parallelism` + `sysconf` memory.
- Installer macOS support: Apple Silicon detection (Intel refused),
  `runner-darwin-arm64.tar.gz` asset, `com.runner.coordinator.plist`
  launchd agent/daemon with `load`/`unload` lifecycle and uninstall
  parity; CI + release matrices gain `macos-latest`, with a live
  Darwin syscall test job.
- `docs/macos.md`: design, install, and the v1 limitation list (no
  mac sandbox isolation, pressure feedback, AFK/thermal guards).

## v1.4.0 — 2026-11-20

- WAN peer WireGuard execution transport: the coordinator dispatches
  jobs to `active` trusted peers over Noise-encrypted UDP (no TUN, no
  privileges), with join-announce onboarding, offer/accept handshake,
  result reporting, and lease expiry with same-tick cloud/Wait
  fallback. `runner join` takes `--coordinator` + `--coordinator-pubkey`;
  `[mesh] peer_port` gates the listener (default off).
- Two-sided donor protection: routing checks caps, label minimums
  (`cpu-N`/`ram-Ngb`), and per-peer load; peers re-validate caps and
  slots, execute in their cgroup slice, and never receive the
  coordinator's LAN cache endpoint.
- `docs/wan-federation.md`: protocol, donor model, NAT limits.
  Loopback `test_wan_dispatch` (incl. a full coordinator-loop run
  against a stub GitHub API) is the CI gate; no multi-machine
  network needed.

## v1.3.1 — 2026-11-20

- Zero-flake hardening: `execute_process` retries transient spawn errors
  once (10ms backoff), covering the observed `pre_exec` unshare-race
  ENOENT plus EAGAIN/ENOMEM/EBUSY/ETXTBSY; genuine failures surface
  unchanged. Stress: 20/20 process-tier runs green.
- Zero doc warnings: fixed the `agent.rs` redundant doc link and set
  `doc = false` on the `runner` binary target (bin/lib filename
  collision); `cargo doc --workspace --no-deps` is clean.
- Opt-in live-KVM harness: `live_kvm_boot_dispatch_and_shutdown` runs a
  real Firecracker boot → dispatch → shutdown behind `RUNNER_LIVE_KVM=1`
  (plus kernel/rootfs/firecracker inputs); skips silently in standard CI.

## v1.3.0 — 2026-11-20

- Tier-1 MicroVM guest dispatch: the engine boots the guest, serves one
  exec session over vsock to the in-guest agent, streams its stdio, and
  tears the VM down (`runner exec --driver microvm` runs workloads now).
- New `runner-guest-agent` crate (blocking std, zero non-workspace deps):
  shared NDJSON protocol (`ExecRequest`/`ExecChunk`/`ExecResult`, base64
  stdio), raw-libc vsock dial, timeout kills with exit `124`, plus a
  `--uds` loopback seam for testing without vsock.
- Host dispatcher rejects oversized lines, unknown streams, and bad
  base64; the socket file is removed on every path; no-KVM and
  no-image failures stay clean errors with zero host execution.
- `docs/microvm-tier.md`: protocol, rootfs-baking recipe, vsock
  assumptions. Live KVM boots stay manual-only; UDS loopback tests
  (`test_vsock_dispatch`, guest `test_uds_smoke`) are the CI gates.

## v1.2.0 — 2026-11-20

- Real `runner init` onboarding: writes `~/.config/runner/config.toml`
  (0600), merging `--org` / `--repo owner/name` into existing configs
  without touching other sections; stores `--token` via the 0600 env
  store (never printed); seeds the cache dir; prints next steps.
- Fail-closed: unparsable configs and malformed slugs are refused
  before any write; re-runs are idempotent ("already up to date").
- New `RunnerConfig::load_from` / `save_to` path-explicit helpers and
  `tests/test_init.rs` (merge, perms, secrecy, idempotency).

## v1.1.0 — 2026-11-18

- MCP-over-daemon-IPC convergence: state-changing tools and both
  status queries execute against live daemon state over new IPC
  methods (`reserve`, `release`, `drain`, `cloud_capacity`,
  `ci_status`, `fleet_topology`, plus existing `throttle_set`),
  falling back to local state only when the daemon is
  unreachable. Schemas unchanged (freeze holds).
- Zero production panic paths: HMAC signing returns `Result`,
  provider claim/bearer paths bail instead of `expect`, audit
  append returns owned entries, and all three signal sites share
  an `Option`-based wait helper with no `unreachable!`.
- Docs record the single-laptop federation posture (loopback
  seam tests authoritative) and the MCP convergence model.

## v1.0.0 — 2026-11-18

- General Availability. Release workflow executes the built
  binary (`--version` + `doctor` JSON assertion) before
  packaging; CI runs on Ubuntu 22.04 and latest.
- Installer fails closed without a SHA-256 verifier, gains
  `--uninstall`, and exits cleanly on macOS.
- Panic elimination under `panic = "abort"`: per-forge skips on
  missing tokens, eBPF assembler returns `Result`, and signal
  registration degrades to no-signal-handling in containers.
- New `runner throttle --level=<warning|critical|high>
  --duration=<mins>` over a `throttle_set` daemon IPC method.
- README documents the hidden lifecycle/service/compliance
  commands; `cli-json.md` default-format claim corrected.

## v0.9.0 — 2026-11-18

- Hermetic test isolation: `TempDir` paths carry a 64-bit random
  nonce and stale directories are removed before creation.
- New `runner auth status`: per-forge credential presence with
  masked tokens (full values never printed).
- Provider credential rejections now name the rotation command;
  error classifiers covered by unit tests.
- v1.0 schema freeze: `docs/mcp.md` documents all 12 tool
  contracts, `docs/cli-json.md` documents the four JSON CLI
  surfaces, and `tests/test_schema_freeze.rs` pins them.
- ROADMAP carries Shipped v0.8.0, `Next: v0.9.0`, v1.0.0 GA
  criteria, and the post-v1.0 WAN enterprise marking.

## v0.8.0 — 2026-11-18

- `runner doctor` covers cache (proxy reachability, store
  writability, TTL state), workstation guards (temp/power with
  85°C latch note), and AFK (mode + idle-detector presence).
- New checks are Pass/Warn only; MCP `diagnose_system` inherits
  them via the shared `run_all`.
- ROADMAP normalized to reverse-chronological order with a
  v1.0 GA-readiness horizon; README doctor flags documented.
- Release smoke tests pin installer asset naming, checksum flow,
  and version-literal consistency.

## v0.7.0 — 2026-11-18

- AFK Boost wiring: `loginctl` desktop-idle probing (5s throttle on the
  250ms tick) with `auto`/`always`/`never` modes and a configurable
  idle threshold; headless hosts fail safe to Active. Boost state and
  mode surface in `runner status`, IPC snapshot, and MCP `get_ci_status`.
- Background cache TTL sweep: creation-age eviction (`ttl_secs`,
  default 7 days) on an hourly cadence, counters preserved.
- WAN routing fail-closed: jobs route to a peer only while its
  handshake status reads `active`; the dispatch arm falls back to
  cloud burst or wait in the same tick when handoff is unavailable.
- Config reference documents `[governor]` and the new `[cache]` keys.

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
