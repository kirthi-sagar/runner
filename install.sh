#!/bin/sh
# install.sh — idempotent installer for `runner`.
#   ./install.sh              install for the current user (~/.local/bin)
#   sudo ./install.sh         install system-wide (/usr/local/bin)
#   ./install.sh --dry-run    print planned actions without changing anything
#   ./install.sh --help       show help
set -eu

VERSION="1.3.0"
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
    if [ "$MODE" = "system" ]; then
        BIN_DST="/usr/local/bin/runner"
        UNIT_FILE="/etc/systemd/system/runner.service"
        STOP="systemctl stop runner"
        DISABLE="systemctl disable runner"
        RELOAD="systemctl daemon-reload"
    else
        HOME_DIR="${HOME:-$HOME}"
        BIN_DST="$HOME_DIR/.local/bin/runner"
        UNIT_FILE="$HOME_DIR/.config/systemd/user/runner.service"
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

if [ "$(uname -s)" = "Darwin" ]; then
    log "error: macOS is not supported: the supervisor requires Linux cgroups v2; macOS support is planned post-v1.0"
    exit 1
fi

# --- Pre-flight checks -------------------------------------------------------
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

# --- Locate or build the binary ----------------------------------------------
BIN_SRC=""
if [ -x ./target/release/runner ]; then
    BIN_SRC="./target/release/runner"
elif [ -x ./target/debug/runner ]; then
    BIN_SRC="./target/debug/runner"
elif command -v cargo >/dev/null 2>&1; then
    log "no prebuilt binary; running cargo build --release"
    if [ "$DRY_RUN" -eq 0 ]; then cargo build --release -p runner-cli; fi
    BIN_SRC="./target/release/runner"
else
    # Zero-dependency fallback: fetch a prebuilt release tarball.
    case "$(uname -m)" in
        x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
        *)
            log "error: no local binary, no cargo, and unsupported architecture $(uname -m)"
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
# runner environment (sourced by systemd; keep secret).
# GitHub token with administration:write (classic PAT: repo scope,
# or fine-grained PAT with Administration read & write).
RUNNER_GITHUB_TOKEN=
EOF
        chmod 0600 "$ENV_FILE"
    fi
fi

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

log ""
log "runner $VERSION installed to $BIN_DST"
if [ "$MODE" = "system" ]; then
    log "configure: $CONF_FILE + $ENV_FILE"
    log "start:     systemctl enable --now runner"
else
    log "configure: $CONF_FILE + $ENV_FILE"
    log "start:     systemctl --user enable --now runner   (or: runner start)"
    case ":$PATH:" in
        *":$HOME_DIR/.local/bin:"*) ;;
        *) log "note: add $HOME_DIR/.local/bin to PATH" ;;
    esac
fi
