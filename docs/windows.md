# Windows via WSL2 (`docs/windows.md`)

Native Windows is not supported: there is no Windows binary, no
`install.ps1`, and the governor/sandbox stack is Linux-only. The
supported Windows path is **WSL2**, where `runner` installs and runs
as a Linux guest. WSL1 is not supported (no systemd, no cgroup v2).

## Prerequisites

- Windows 10 2004+ (Build 19041+) or Windows 11; WSL 0.67.6+.
- A Linux distro (Ubuntu recommended): `wsl --install` from an admin
  PowerShell, then reboot.
- systemd enabled (WSL2 only; off by default):
  `[boot] systemd=true` in `/etc/wsl.conf`, then `wsl --shutdown`
  from Windows and reopen the distro.
- Kernel ≥ 5.8 with cgroups v2 (current WSL2 kernels qualify).

The installer enforces all of this: running `install.sh` under WSL2
without systemd, or with cgroups v1, fails closed with the fix.

## Install

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

## Filesystem rule: stay inside the distro

Never check out or run `runner` from `/mnt/c`. The 9P bridge is an
order of magnitude slower than the distro's ext4 disk on
many-small-file workloads (`git status`, `node_modules`, caches),
and synthesized permissions + CRLF silently break Linux tooling
(shebang `\r` failures, lost `+x` bits).

## Networking: NAT vs mirrored

WSL2 defaults to NAT: localhost works both directions, but LAN hosts
cannot reach the distro without a manual `netsh interface portproxy`
rule (fragile — the distro IP changes). For mesh participation
(peers dialing this node), prefer mirrored mode
(`networkingMode=mirrored` in `%USERPROFILE%\.wslconfig`, Windows 11
22H2+), which gives direct LAN access, IPv6, and VPN/multicast.

## Resources and governor scope

WSL2 defaults to 50% host RAM and all host logical processors, shown
opaquely as `Vmmem`/`VmmemWSL`; bound them explicitly in
`.wslconfig` if the host is shared. The governor sees **only the
VM**: it throttles the distro's cgroup slice against in-VM pressure
and cannot see host Windows load. `zero-freeze` on WSL2 therefore
means VM-local stability, not host-aware scheduling — size the
`.wslconfig` limits so the host keeps headroom.

## Known limitations

- Tier-1 microVMs unavailable: no `/dev/kvm` under WSL2
  (Tier-2 sandbox and Tier-3 dispatch work normally).
- No LAN reachability under default NAT (see above); mDNS
  federation needs mirrored mode.
- AFK boost keys off Linux idle signals inside the distro, not
  Windows lock state; thermal/power guards read distro sysfs.
- `install.sh` manages the systemd user service; Windows-side
  auto-start (Task Scheduler) is out of scope.
