# macOS Apple Silicon Port (`docs/macos.md`)

`runner` runs on Apple Silicon Macs (arm64 only; Intel macs are refused
by the installer): CI workloads execute at background QoS so XNU
schedules them onto Efficiency cores, leaving Performance cores to
interactive apps (spec §3.5).

## What works

- **Background QoS pinning** (`governor::darwin`): worker children call
  `setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG)` in `pre_exec`,
  and `pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0)` is
  available for threads. Constants verified against Apple SDK headers.
- **Slot detection** from `available_parallelism` + `sysconf` memory
  (no `/proc` on macOS).
- **Install + service**: `install.sh` fetches `runner-darwin-arm64.tar.gz`,
  installs a `com.runner.coordinator.plist` launchd agent
  (`~/Library/LaunchAgents`, `/Library/LaunchDaemons` for system
  installs), and manages it with `launchctl load` / `unload`.
- **Mesh + providers**: invite/join, Noise-encrypted WAN dispatch,
  GitHub/GitLab/Bitbucket polling, MCP, and the control plane are
  platform-independent and work unchanged.

## Known macOS limitations (v1)

- **No sandbox isolation**: no user namespaces, no tmpfs mounts, no
  eBPF/socket-filter egress rules. Tier-2 degrades to governed direct
  spawning plus QoS; the probes report unsupported and every layer
  fails closed to that mode.
- **No pressure feedback**: without PSI the governor holds static
  slots; QoS pinning (static E-core scheduling) is the whole thermal
  story on macOS v1.
- **No AFK boost** (no loginctl) and **no thermal guards** (no sysfs);
  macOS power management owns both.
- **`runner doctor` stays red** on Linux-only checks (kernel,
  cgroups, userns) by design; mac-aware checks are a follow-up.
- **No Linux guests**: spec §3.5's Virtualization.framework guests are
  future work; macOS runners execute mac-native steps only.

## Test posture

- Hermetic on Linux CI: `governor::darwin` unit tests (mock seam,
  hook placement through real spawns, constant pins), plus the full
  suite unchanged.
- `cargo check --target {aarch64,x86_64}-apple-darwin --workspace
  --all-targets` must stay clean (the portability gate).
- The macOS CI job runs fmt, clippy, a full native build (link check),
  and `cargo test -p runner-core --lib governor::darwin` — whose
  `cfg(macos)` cases invoke the real syscalls on a real Mac.
