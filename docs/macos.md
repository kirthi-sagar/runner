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

## Tier-2 sandbox: Seatbelt (v1.9.0+)

Job processes on macOS run under an Apple Seatbelt profile applied
with `sandbox_init` in the `pre_exec` child hook — the same choke
point as QoS, and the same mechanism Chrome, Homebrew, Claude Code,
Codex CLI, and Cursor use for macOS sandboxing. No entitlements are
required (ad-hoc Seatbelt profiles need none, unlike the App Sandbox
container).

What it protects (filesystem isolation for job processes):

- `~/.ssh`, `~/.gnupg`, `~/.config/runner`, `~/.runner`: neither
  readable nor writable from inside a job.
- Writes anywhere outside the job workspace and the temp roots
  (`/private/tmp`, `/private/var/tmp`, canonicalized `$TMPDIR`):
  denied.

What it allows:

- Full read/write to the job workspace (parameterized per job).
- Writes to the temp roots (linker tempfiles, build caches).
- Reads of system directories (`/usr`, `/System`, `/Library`,
  `/private/tmp`).
- Unrestricted outbound network (CI jobs fetch dependencies;
  egress filtering arrives in v1.10.0).

Behavioral notes:

- **Nesting**: if the job child is already sandboxed (detected via
  the non-deprecated `sandbox_check` probe), the profile is skipped
  with a log line — nested `sandbox_init` would fail, and the outer
  sandbox stays in force.
- **Soft-fail**: if `sandbox_init` itself fails, the error message is
  logged and the job continues unsandboxed (same posture as the
  Linux userns probe). `--strict` will convert this to a hard
  failure in a future milestone.
- **Deprecation risk**: `sandbox_init` is marked deprecated by Apple
  (in favor of the entitled App Sandbox, which cannot confine
  arbitrary CLI job processes). It remains functional on current
  macOS with no announced removal; if Apple ever removes it, Tier-2
  on macOS falls back to governed-direct spawning. The FFI is
  hand-rolled Rust with no `<sandbox.h>`, so no C deprecation
  warning is involved.

## Known macOS limitations (v1)

- **No pressure feedback**: without PSI the governor holds static
  slots; QoS pinning (static E-core scheduling) is the whole thermal
  story on macOS v1.
- **No AFK boost** (no loginctl) and **no thermal guards** (no sysfs);
  macOS power management owns both.
- **`runner doctor` stays red** on Linux-only checks (kernel,
  cgroups, userns) by design; mac-aware checks are a follow-up.
- **No Linux guests (parked, was v1.10.0)**: Virtualization.framework
  guests cannot boot on hosted runners (no nested virt, closed
  not-planned upstream) and mandate an entitlement. macOS runners
  execute mac-native steps only; see ROADMAP "Parked" for the
  re-entry conditions.

## Test posture

- Hermetic on Linux CI: `governor::darwin` unit tests (mock seam,
  hook placement through real spawns, constant pins), plus the full
  suite unchanged.
- `cargo check --target {aarch64,x86_64}-apple-darwin --workspace
  --all-targets` must stay clean (the portability gate).
- The macOS CI job runs fmt, clippy, a Seatbelt availability probe,
  a full native build (link check),
  `cargo test -p runner-core --lib governor::darwin`, and
  `cargo test -p runner-sandbox --lib seatbelt` — whose `cfg(macos)`
  cases invoke the real syscalls on a real Mac.
