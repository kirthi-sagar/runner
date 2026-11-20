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

> **Firecracker UDS direction contract (unverified live):** per the
> Firecracker API model docs, for host-initiated connections Firecracker
> itself binds/listens on `uds_path`, and the host connects and sends
> `CONNECT <port>\n`; guest-initiated dials surface at
> `<uds_path>_<PORT>` on a host-listening socket. Our dispatcher
> currently binds the bare `vsock_path`, which likely mismatches a live
> Firecracker (expect a clean bind/timeout error, never silent
> misbehavior). Tracked for a targeted v1.3.2 patch once a live
> Firecracker environment is available; the UDS loopback contract used
> by the CI gates is unchanged.

## Baking the agent into the rootfs

Build a static binary (musl target + a `*-musl` toolchain, e.g. via
`rustup target add x86_64-unknown-linux-musl`):

```bash
cargo build --release -p runner-guest-agent --target x86_64-unknown-linux-musl
```

Copy it into the image and start it on guest boot:

```bash
mount -o loop rootfs.ext4 /mnt/guest
cp target/x86_64-unknown-linux-musl/release/runner-guest-agent /mnt/guest/usr/local/bin/
umount /mnt/guest
```

Guest boot hook (run once per boot, before jobs arrive; the agent serves
one session per connection and exits, so supervise or loop it):

```bash
#!/bin/sh
# /usr/local/bin/runner-guest.sh
while true; do /usr/local/bin/runner-guest-agent; sleep 1; done
```

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
