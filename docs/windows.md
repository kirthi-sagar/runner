# Windows support (`docs/windows.md`)

Two supported paths, pick one:

- **Native Windows (Tier-3 + governor)**: `runner.exe`, direct
  unprivileged subprocess dispatch governed by Job Objects (v2.0.0).
  See below.
- **Windows via WSL2**: full Linux guest with governor + sandbox.
  See "Windows via WSL2" further down.

## Native Windows (Tier-3 + governor)

Supported: Tier-3 dispatch (direct unprivileged subprocess), the
WireGuard mesh transport (UDP + STUN work unchanged on Windows),
and the Job Objects governor (v2.0.0 — see "Windows governor").

`runner top` renders live frames: system CPU/memory gauges come
from Win32 (`GetSystemTimes`, `GlobalMemoryStatusEx`), and daemon
state flows over the named-pipe snapshot when a daemon runs.
Daemon IPC runs over Windows named pipes (`\\.\pipe\runner-*`).

Unsupported — every item logs loudly at the point of use, never
silently: Tier-2 sandboxing (no Linux namespaces) and Tier-1
microVMs (no Firecracker/KVM).

## Windows governor (Job Objects, v2.0.0)

Unprivileged Win32 throughout: no entitlements, no drivers, no
hypervisor. Three layers, mirroring the Linux governor:

- **Sensor.** Memory pressure from `GlobalMemoryStatusEx` (load
  percentage plus commit-limit headroom); CPU utilization from
  `GetSystemTimes` deltas across two samples. Readings map onto the
  existing `Normal`/`Warning`/`Critical` ladder and feed the shared
  `tick_weight` policy unchanged — only the numbers are Windows'.
- **Actuator.** A single daemon-wide job all worker trees join
  (mirroring the Linux system slice): processes are assigned
  post-spawn (grandchildren inherit membership), memory ceilings
  ride `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`, and CPU share rides
  weight-based rate control. Throttling model:
  Normal → weight 9, Warning → weight 5, Critical → weight 1
  (trickle, never zero — the never-freeze invariant holds: weights
  only matter under contention and can never starve a job the way
  a hard cap could). `KILL_ON_JOB_CLOSE` guarantees no orphaned
  workers when the runner exits.
- **Supervisor loop.** Same 250ms cadence as Linux: sample,
  classify, apply, publish. Shutdown via `ctrl_c`.

Two invariants worth knowing. First, nesting: if the runner itself
runs inside a job (CI agents, services), worker assignment nests by
default on Windows 8+ — no breakaway flags needed — provided we
never set UI restrictions (we don't, ever). Second, failure posture:
a failed assignment or limit logs loudly and the job continues
governed-direct, exactly like the Linux userns soft-fail; nothing
in the governor path can fail a healthy job.

Install (no admin rights required):

```powershell
irm https://raw.githubusercontent.com/kirthi-sagar/runner/main/install.ps1 | iex
```

Then restart the terminal and run `runner doctor`. Expected output
marks the unsupported subsystems explicitly — `kernel` reports
`feature unavailable on Windows`, `cgroupsv2` reports the governor
`active (Job Objects)`, and daemon IPC shows absent. Those entries
are normal on this tier, not defects.

Known limitations:

- `runner start` (daemon) refuses to start: without IPC sockets
  there is nothing useful to supervise. `runner exec` is the
  supported entry point.

Future (v2.1+): WFP egress filtering and a native sandbox backend.
Every remaining stub logs its feature name so the work can be
harvested by grep.

## Windows via WSL2

Full Linux guest support: `runner` installs and runs inside WSL2
with governor, sandbox, and systemd service. WSL1 is not supported
(no systemd, no cgroup v2).

### Prerequisites

- Windows 10 2004+ (Build 19041+) or Windows 11; WSL 0.67.6+.
- A Linux distro (Ubuntu recommended): `wsl --install` from an admin
  PowerShell, then reboot.
- systemd enabled (WSL2 only; off by default):
  `[boot] systemd=true` in `/etc/wsl.conf`, then `wsl --shutdown`
  from Windows and reopen the distro.
- Kernel ≥ 5.8 with cgroups v2 (current WSL2 kernels qualify).

The installer enforces all of this: running `install.sh` under WSL2
without systemd, or with cgroups v1, fails closed with the fix.

### Install

From inside the distro (not `/mnt/c` — see below):

```sh
git clone https://github.com/kirthi-sagar/runner.git ~/runner
cd ~/runner
./install.sh
runner doctor
```

`doctor` reports a `wsl` check: pass names the distro and confirms
systemd; a warning means systemd is off (see above). The installer
refuses to run from `/mnt/*`: checkouts, caches, and the install
itself must live inside the distro filesystem (`/home/...`).

### Filesystem rule: stay inside the distro

Never check out or run `runner` from `/mnt/c`. The 9P bridge is an
order of magnitude slower than the distro's ext4 disk on
many-small-file workloads (`git status`, `node_modules`, caches),
and synthesized permissions + CRLF silently break Linux tooling
(shebang `\r` failures, lost `+x` bits).

### Networking: NAT vs mirrored

WSL2 defaults to NAT: localhost works both directions, but LAN hosts
cannot reach the distro without a manual `netsh interface portproxy`
rule (fragile — the distro IP changes). For mesh participation
(peers dialing this node), prefer mirrored mode
(`networkingMode=mirrored` in `%USERPROFILE%\.wslconfig`, Windows 11
22H2+), which gives direct LAN access, IPv6, and VPN/multicast.

### Resources and governor scope

WSL2 defaults to 50% host RAM and all host logical processors, shown
opaquely as `Vmmem`/`VmmemWSL`; bound them explicitly in
`.wslconfig` if the host is shared. The governor sees **only the
VM**: it throttles the distro's cgroup slice against in-VM pressure
and cannot see host Windows load. `zero-freeze` on WSL2 therefore
means VM-local stability, not host-aware scheduling — size the
`.wslconfig` limits so the host keeps headroom.

### Known limitations

- Tier-1 microVMs unavailable: no `/dev/kvm` under WSL2
  (Tier-2 sandbox and Tier-3 dispatch work normally).
- No LAN reachability under default NAT (see above); mDNS
  federation needs mirrored mode.
- AFK boost keys off Linux idle signals inside the distro, not
  Windows lock state; thermal/power guards read distro sysfs.
- `install.sh` manages the systemd user service; Windows-side
  auto-start (Task Scheduler) is out of scope.
