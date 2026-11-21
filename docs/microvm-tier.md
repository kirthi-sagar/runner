# Tier-1 MicroVM Execution (`docs/microvm-tier.md`)

Hardware-isolated CI execution: Firecracker boots an ephemeral guest per
command, the host dispatches the workload over vsock to the in-guest
agent, streams its stdio, and tears the VM down. Without KVM, the
Firecracker binary, or kernel/rootfs images, Tier-1 fails closed with a
clean error (never silent host execution).

## Prerequisites

- `/dev/kvm` readable (bare metal or nested virtualization).
- `firecracker` binary (`sandbox.firecracker_bin` or `PATH`).
- Guest kernel (`vmlinux`) + ext4 rootfs image (`sandbox.kernel_path`,
  `sandbox.rootfs_path`).
- `runner-guest-agent` baked into the rootfs (below).

```toml
# ~/.config/runner/runner.toml (or [sandbox] in config.toml)
mode = "enterprise"  # defaults the driver to microvm
[sandbox]
kernel_path = "/srv/microvm/vmlinux"
rootfs_path = "/srv/microvm/rootfs.ext4"
```

```bash
runner exec --driver microvm -- make test
```

## Wire protocol (newline-delimited JSON, base64 stdio)

Both sides share `runner-guest-agent`'s types, so the format cannot drift:

1. Host sends one `ExecRequest {argv, cwd, env, timeout_secs}`.
2. Guest replies with `ExecChunk {stream: 1|2, data_b64}*`
   (8 KiB reads; 1 = stdout, 2 = stderr).
3. Guest sends exactly one `ExecResult {exit_code}` and exits.

The host rejects oversized lines (> 256 KiB), unknown streams, and bad
base64; either side timing out kills the command (the agent reports the
conventional exit code `124` for overruns it kills itself).

vsock assumptions: the agent dials host CID `2`, port `5000`
(`HOST_CID` / `GUEST_VSOCK_PORT`).

> **Firecracker UDS direction contract (verified live on v1.18.0):**
> for host-initiated connections Firecracker itself binds/listens on
> `uds_path` (host connects); guest-initiated dials surface at
> `<uds_path>_<PORT>` on a host-listening socket. The dispatcher
> binds the suffixed path. Verified end to end with a live guest
> agent dialing host CID 2 port 5000.

## Baking the agent into the rootfs

Build a static binary (musl target; no musl toolchain needed —
self-contained link via the toolchain's `rust-lld`):

```bash
rustup target add x86_64-unknown-linux-musl
RUSTFLAGS="-C link-self-contained=yes -C linker=<toolchain>/bin/rust-lld" \
  cargo build --release -p runner-guest-agent --target x86_64-unknown-linux-musl
```

Inject without root via `debugfs` (no loop mount needed):

```bash
debugfs -w -f inject.txt rootfs.ext4  # mkdir /bin; write agent /init;
                                      # write busybox /bin/busybox; link echo;
                                      # mknod /dev/{null,zero,console}; sif modes
```

Run the agent as `/init` (kernel needs `init=/init`, shipped in the
harness boot args). Notes: the agent serves one session per
connection and exits, so multi-dispatch guests need supervision (a
one-shot harness plus the `panic=1` reboot loop suffices for tests);
spawned commands need `/dev/null`, so the image must carry device
nodes. Firecracker floor is v1.18.0 — v1.7.0 silently skips
virtio-mmio enumeration on modern kernels.

## Test posture

Live KVM boots are manual-only (CI has no `/dev/kvm`). The authoritative
gates are the loopback seams, which run everywhere:

- `tests/test_vsock_dispatch.rs` — host dispatcher vs. mock guests over
  UDS, plus the real agent loop vs. a mock host (real `sh` execution,
  stream splitting, exit codes, timeout kills).
- `crates/runner-guest-agent/tests/test_uds_smoke.rs` — the real
  `runner-guest-agent` binary over `--uds`.
- `microvm_tier_fails_closed_without_kvm_or_config` — no-KVM and
  no-image paths stay clean errors with zero host execution.
