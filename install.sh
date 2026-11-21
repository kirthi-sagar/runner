#!/bin/sh
# install.sh — idempotent installer for `runner`.
#   ./install.sh              install for the current user (~/.local/bin)
#   sudo ./install.sh         install system-wide (/usr/local/bin)
#   ./install.sh --dry-run    print planned actions without changing anything
#   ./install.sh --help       show help
set -eu

VERSION="1.9.0"
MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=8

MODE="auto"
DRY_RUN=0
UNINSTALL=0

usage() {
    cat <<'EOF'
Usage: ./install.sh [OPTIONS]

Install the `runner` supervisor binary, default configuration, and a
systemd service unit. Idempotent: safe to re-run.

Options:
  --user      force unprivileged install (~/.local/bin, user service)
  --system    force privileged install (/usr/local/bin, system service)
  --dry-run   print what would be done without changing anything
  --uninstall remove the service, binary, and unit (keeps config + data)
  --help      show this help

Without flags, root installs system-wide and everyone else installs
per-user. The installer prefers ./target/release/runner, then
./target/debug/runner, then builds with cargo when available, and
finally downloads a prebuilt release tarball (curl/wget) with
SHA-256 verification.
EOF
}

log() { printf '%s\n' "$*"; }
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*";
    else
        "$@";
    fi
}

for arg in "$@"; do
    case "$arg" in
        --user) MODE="user" ;;
        --system) MODE="system" ;;
        --dry-run) DRY_RUN=1 ;;
        --uninstall|uninstall) UNINSTALL=1 ;;
        --help|-h) usage; exit 0 ;;
        *) log "unknown option: $arg"; usage; exit 2 ;;
    esac
done

if [ "$MODE" = "auto" ]; then
    if [ "$(id -u)" -eq 0 ]; then MODE="system"; else MODE="user"; fi
fi

# --- Uninstall (before pre-flight: must work on broken hosts too) --------------
if [ "$UNINSTALL" -eq 1 ]; then
    if [ "$(uname -s)" = "Darwin" ]; then
        if [ "$MODE" = "system" ]; then
            BIN_DST="/usr/local/bin/runner"
            UNIT_FILE="/Library/LaunchDaemons/com.runner.coordinator.plist"
        else
            HOME_DIR="${HOME:-$HOME}"
            BIN_DST="$HOME_DIR/.local/bin/runner"
            UNIT_FILE="$HOME_DIR/Library/LaunchAgents/com.runner.coordinator.plist"
        fi
        log "uninstalling runner ($MODE mode; config and data are kept)"
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] launchctl unload $UNIT_FILE"
        elif command -v launchctl >/dev/null 2>&1; then
            launchctl unload "$UNIT_FILE" 2>/dev/null || true
        fi
        run rm -f "$BIN_DST" "$UNIT_FILE"
        log "runner uninstalled from $BIN_DST"
        exit 0
    fi
    if [ "$MODE" = "system" ]; then
        BIN_DST="/usr/local/bin/runner"
        UNIT_FILE="/etc/systemd/system/runner.service"
        STOP="systemctl stop runner"
        DISABLE="systemctl disable runner"
        RELOAD="systemctl daemon-reload"
    else
        HOME_DIR="${HOME:-$HOME}"
        BIN_DST="$HOME_DIR/.config/systemd/user/runner.service"
        STOP="systemctl --user stop runner"
        DISABLE="systemctl --user disable runner"
        RELOAD="systemctl --user daemon-reload"
    fi
    log "uninstalling runner ($MODE mode; config and data are kept)"
    if command -v systemctl >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] $STOP; $DISABLE"
        else
            $STOP 2>/dev/null || true
            $DISABLE 2>/dev/null || true
        fi
    fi
    run rm -f "$BIN_DST" "$UNIT_FILE"
    if command -v systemctl >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] $RELOAD"
        else
            $RELOAD 2>/dev/null || log "warning: systemd reload failed; run manually: $RELOAD"
        fi
    fi
    log "runner uninstalled from $BIN_DST"
    exit 0
fi

# --- Platform dispatch ---------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS-$ARCH" in
    Darwin-arm64) log "macOS Apple Silicon detected" ;;
    Darwin-*) log "error: macOS support requires Apple Silicon (arm64); Intel macs are not supported"; exit 1 ;;
    Linux-*) ;;
    *) log "error: unsupported OS: $OS (want Linux or macOS)"; exit 1 ;;
esac

# --- Pre-flight checks -------------------------------------------------------
if [ "$OS" = "Darwin" ]; then
    if command -v launchctl >/dev/null 2>&1; then
        log "launchd available OK"
    else
        log "error: launchctl not found; cannot manage the runner service"
        exit 1
    fi
    if command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1; then
        log "checksum tool available OK"
    else
        log "error: shasum (or sha256sum) required for secure release verification"
        exit 1
    fi
else
KERNEL="$(uname -r)"
KMAJOR="$(printf '%s' "$KERNEL" | cut -d. -f1)"
KMINOR="$(printf '%s' "$KERNEL" | cut -d. -f2 | cut -d- -f1)"
if [ "$KMAJOR" -lt "$MIN_KERNEL_MAJOR" ] 2>/dev/null || \
   { [ "$KMAJOR" -eq "$MIN_KERNEL_MAJOR" ] && [ "${KMINOR:-0}" -lt "$MIN_KERNEL_MINOR" ]; }; then
    log "error: Linux kernel >= 5.8 required for cgroups v2 + PSI (found $KERNEL)"
    exit 1
fi
log "kernel $KERNEL OK"

if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    log "cgroups v2 mounted OK"
else
    log "error: cgroups v2 not mounted (/sys/fs/cgroup/cgroup.controllers missing)"
    exit 1
fi

# --- WSL2 preflights ---------------------------------------------------------
# WSL2 reports Linux to uname, so detect it explicitly and fail closed on
# the known-bad configurations (see docs/windows.md). A hard error (not a
# warning) is deliberate here: unlike bare Linux without systemd (rare,
# expert), WSL-without-systemd is the default/novice case, and the user
# service the installer exists to create can never start there.
IS_WSL=0
if [ -n "${WSL_DISTRO_NAME:-}" ]; then
    IS_WSL=1
elif grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=1
fi
if [ "$IS_WSL" -eq 1 ]; then
    log "WSL2 environment detected (${WSL_DISTRO_NAME:-unknown distro})"
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        log "systemd active under WSL2 OK"
    else
        log "error: WSL2 without systemd; set [boot] systemd=true in /etc/wsl.conf and run: wsl --shutdown"
        exit 1
    fi
    case "$(pwd -P 2>/dev/null || pwd)" in
        /mnt/*)
            log "error: running from $PWD: install and check out runner inside the distro (/home/...) — /mnt/c is 9P (slow) and breaks Linux tooling (CRLF/permissions). See docs/windows.md"
            exit 1
            ;;
    esac
fi

if command -v nft >/dev/null 2>&1; then
    log "nftables available OK"
else
    log "warning: nft not found; sandbox egress rules cannot be applied by the host"
fi

if unshare -Urm true >/dev/null 2>&1; then
    log "unprivileged user namespaces OK"
else
    log "warning: unprivileged user namespaces blocked; Tier-2 sandboxes fall back to plain spawn"
fi
fi

# --- Locate or build the binary ----------------------------------------------
BIN_SRC=""
if [ -x ./target/release/runner ]; then
    BIN_SRC="./target/release/runner"
elif [ -x ./target/debug/runner ]; then
    BIN_SRC="./target/debug/runner"
elif command -v cargo >/dev/null 2>&1; then
    log "no prebuilt binary; running cargo build --locked --release"
    if [ "$DRY_RUN" -eq 0 ]; then cargo build --locked --release -p runner-cli; fi
    BIN_SRC="./target/release/runner"
else
    # Zero-dependency fallback: fetch a prebuilt release tarball.
    case "$OS-$ARCH" in
        Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
        Linux-aarch64|Linux-arm64) TARGET="aarch64-unknown-linux-gnu" ;;
        Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
        *)
            log "error: no local binary, no cargo, and unsupported platform $OS-$ARCH"
            exit 1
            ;;
    esac
    if command -v curl >/dev/null 2>&1; then
        downloader="curl -fsSL -o"
    elif command -v wget >/dev/null 2>&1; then
        downloader="wget -qO"
    else
        log "error: no local binary, no cargo, and neither curl nor wget available"
        exit 1
    fi
    TARBALL="runner-v$VERSION-$TARGET.tar.gz"
    if [ "$OS" = "Darwin" ]; then
        TARBALL="runner-darwin-arm64.tar.gz"
    fi
    BASE_URL="https://github.com/kirthi-sagar/runner/releases/download/v$VERSION"
    TMP_DL="$(mktemp -d)"
    log "fetching prebuilt $TARBALL"
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] $downloader $TMP_DL/$TARBALL $BASE_URL/$TARBALL"
        BIN_SRC="./target/release/runner"
    else
        # Word-split $downloader into command + flags (POSIX sh).
        $downloader "$TMP_DL/$TARBALL" "$BASE_URL/$TARBALL"
        $downloader "$TMP_DL/$TARBALL.sha256" "$BASE_URL/$TARBALL.sha256"
        if command -v sha256sum >/dev/null 2>&1; then
            (cd "$TMP_DL" && sha256sum -c "$TARBALL.sha256") || {
                log "error: checksum mismatch for $TARBALL"
                exit 1
            }
        elif command -v shasum >/dev/null 2>&1; then
            (cd "$TMP_DL" && shasum -a 256 -c "$TARBALL.sha256") || {
                log "error: checksum mismatch for $TARBALL"
                exit 1
            }
        else
            log "error: sha256sum required for secure release verification"
            exit 1
        fi
        tar -xzf "$TMP_DL/$TARBALL" -C "$TMP_DL"
        BIN_SRC="$TMP_DL/runner-v$VERSION-$TARGET/runner"
        if [ "$OS" = "Darwin" ]; then
            BIN_SRC="$TMP_DL/runner-darwin-arm64/runner"
        fi
    fi
fi
log "binary: $BIN_SRC"

# --- Paths per mode ----------------------------------------------------------
if [ "$MODE" = "system" ]; then
    BIN_DST="/usr/local/bin/runner"
    CONF_DIR="/etc/runner"
    CONF_FILE="$CONF_DIR/config.toml"
    ENV_FILE="$CONF_DIR/env"
    UNIT_FILE="/etc/systemd/system/runner.service"
    EXEC_START="/usr/local/bin/runner start"
    ENV_LINE="EnvironmentFile=-/etc/runner/env"
    PATH_LINE='Environment="PATH=/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin"'
    WANTED_BY="multi-user.target"
    RELOAD="systemctl daemon-reload"
else
    HOME_DIR="${HOME:-$HOME}"
    BIN_DST="$HOME_DIR/.local/bin/runner"
    CONF_DIR="$HOME_DIR/.config/runner"
    CONF_FILE="$CONF_DIR/config.toml"
    ENV_FILE="$CONF_DIR/env"
    UNIT_FILE="$HOME_DIR/.config/systemd/user/runner.service"
    EXEC_START="%h/.local/bin/runner start"
    ENV_LINE="EnvironmentFile=-%h/.config/runner/env"
    PATH_LINE='Environment="PATH=%h/.cargo/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin"'
    WANTED_BY="default.target"
    RELOAD="systemctl --user daemon-reload"
fi
if [ "$OS" = "Darwin" ]; then
    if [ "$MODE" = "system" ]; then
        UNIT_FILE="/Library/LaunchDaemons/com.runner.coordinator.plist"
    else
        UNIT_FILE="$HOME_DIR/Library/LaunchAgents/com.runner.coordinator.plist"
    fi
fi
log "mode: $MODE"

# --- Install -----------------------------------------------------------------
run mkdir -p "$(dirname "$BIN_DST")" "$CONF_DIR" "$(dirname "$UNIT_FILE")"
run install -m 0755 "$BIN_SRC" "$BIN_DST"

if [ -f "$CONF_FILE" ]; then
    log "config exists, keeping: $CONF_FILE"
else
    log "writing default config: $CONF_FILE"
    if [ "$DRY_RUN" -eq 0 ]; then
        cat >"$CONF_FILE" <<EOF
# runner configuration — Super Admin controls.
# See README.md (Configuration Reference) for all fields.

# GitHub organization for org-level JIT issuance (optional).
# org = "my-org"

[cloud]
# Maximum monthly cloud spend in USD. 0 disables bursting.
max_monthly_spend = 0
# digitalocean_token = "..."
# render_token = "..."
# render_owner_id = "..."

[coordinator]
# repo_owner = "octocat"
# repo_name = "hello-world"
poll_secs = 15
auto_dispatch = false
runner_group_id = 1
worker_version = "2.338.2"
job_timeout_mins = 60
EOF
        chmod 0600 "$CONF_FILE"
    fi
fi

if [ -f "$ENV_FILE" ]; then
    log "env file exists, keeping: $ENV_FILE"
else
    log "writing env template: $ENV_FILE"
    if [ "$DRY_RUN" -eq 0 ]; then
        cat >"$ENV_FILE" <<'EOF'
# runner environment (sourced by the daemon; keep secret).
# GitHub token with administration:write (classic PAT: repo scope,
# or fine-grained PAT with Administration read & write).
RUNNER_GITHUB_TOKEN=
EOF
        chmod 0600 "$ENV_FILE"
    fi
fi

if [ "$OS" = "Darwin" ]; then
    if [ "$MODE" = "system" ]; then
        LOG_DIR="/var/log/runner"
    else
        LOG_DIR="$HOME_DIR/Library/Logs/runner"
    fi
    run mkdir -p "$LOG_DIR"
    log "writing launchd plist: $UNIT_FILE"
    if [ "$DRY_RUN" -eq 0 ]; then
        cat >"$UNIT_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.runner.coordinator</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_DST</string>
    <string>start</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/stdout.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/stderr.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
</dict>
</plist>
EOF
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        log "[dry-run] launchctl load $UNIT_FILE"
    elif launchctl load "$UNIT_FILE" 2>/dev/null; then
        log "launchd agent loaded"
    else
        log "warning: launchctl load failed; run manually: launchctl load $UNIT_FILE"
    fi
else
    log "writing service unit: $UNIT_FILE"
    if [ "$DRY_RUN" -eq 0 ]; then
        cat >"$UNIT_FILE" <<EOF
[Unit]
Description=runner - Zero-Freeze Local & Federated GitHub Actions Runner
After=network.target

[Service]
Type=simple
ExecStart=$EXEC_START
Restart=on-failure
RestartSec=5s
$ENV_LINE
$PATH_LINE
Slice=runner.slice
KillMode=mixed
TimeoutStopSec=15s

[Install]
WantedBy=$WANTED_BY
EOF
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
            log "[dry-run] $RELOAD"
        elif $RELOAD 2>/dev/null; then
            log "systemd reloaded"
        else
            log "warning: systemd reload failed (no user bus?); run manually: $RELOAD"
        fi
    else
        log "warning: systemctl not found; start the daemon manually"
    fi
fi

log ""
log "runner $VERSION installed to $BIN_DST"
if [ "$MODE" = "system" ]; then
    log "configure: $CONF_FILE + $ENV_FILE"
    if [ "$OS" = "Darwin" ]; then
        log "start:     launchctl load $UNIT_FILE"
    else
        log "start:     systemctl enable --now runner"
    fi
else
    log "configure: $CONF_FILE + $ENV_FILE"
    if [ "$OS" = "Darwin" ]; then
        log "start:     launchctl load $UNIT_FILE   (or: runner start)"
    else
        log "start:     systemctl --user enable --now runner   (or: runner start)"
    fi
    case ":$PATH:" in
        *":$HOME_DIR/.local/bin:"*) ;;
        *) log "note: add $HOME_DIR/.local/bin to PATH" ;;
    esac
fi
