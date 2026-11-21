//! First-class systemd user service management (`runner service ...`).
//!
//! User-mode only: the unit lives at `~/.config/systemd/user/runner.service`
//! and mirrors the `install.sh` user template. System-wide installs remain
//! owned by `install.sh` run as root.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

/// Systemd user unit path (`~/.config/systemd/user/runner.service`).
pub fn user_unit_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user")
            .join("runner.service")
    })
}

/// Render the user service unit. Must stay in sync with the `install.sh`
/// user-mode template (same directives, same ordering).
pub fn unit_file_contents(exec_start: &str) -> String {
    format!(
        "[Unit]\n\
         Description=runner - Zero-Freeze Local & Federated GitHub Actions Runner\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec_start}\n\
         Restart=on-failure\n\
         RestartSec=5s\n\
         EnvironmentFile=-%h/.config/runner/env\n\
         Environment=\"PATH=%h/.cargo/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin\"\n\
         Slice=runner.slice\n\
         KillMode=mixed\n\
         TimeoutStopSec=15s\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// Resolve the current binary path for `ExecStart`.
pub fn current_binary_path() -> Result<String> {
    let exe = std::env::current_exe().context("resolve current binary path")?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    exe.into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("binary path is not valid UTF-8"))
}

fn systemctl(args: &[&str]) -> Result<std::process::ExitStatus> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .with_context(|| format!("run systemctl --user {}", args.join(" ")))
}

fn systemctl_checked(args: &[&str]) -> Result<()> {
    let status = systemctl(args)?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("systemctl --user {} failed with {status}", args.join(" "))
    }
}

/// Write the user unit, reload systemd, then enable and start the service.
pub fn install() -> Result<()> {
    let unit_path = user_unit_path().context("no HOME for service unit path")?;
    let exec = current_binary_path()?;
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&unit_path, unit_file_contents(&format!("{exec} start")))?;
    println!("wrote {}", unit_path.display());
    systemctl_checked(&["daemon-reload"])?;
    systemctl_checked(&["enable", "runner"])?;
    systemctl_checked(&["start", "runner"])?;
    println!("runner service installed, enabled, and started");
    Ok(())
}

/// Show `systemctl --user status runner`, streaming output to the terminal.
/// Never fails on nonzero exit: systemd encodes service state in it.
pub fn status() -> Result<()> {
    Command::new("systemctl")
        .arg("--user")
        .args(["status", "runner"])
        .status()
        .context("run systemctl --user status runner")?;
    Ok(())
}

/// Stop the user service.
pub fn stop() -> Result<()> {
    systemctl_checked(&["stop", "runner"])?;
    println!("runner service stopped");
    Ok(())
}

/// Start the user service.
pub fn start() -> Result<()> {
    systemctl_checked(&["start", "runner"])?;
    println!("runner service started");
    Ok(())
}

/// Stop, disable, delete the unit file, and reload systemd.
/// Stop/disable are best-effort so uninstall works on a half-removed service.
pub fn uninstall() -> Result<()> {
    let unit_path = user_unit_path().context("no HOME for service unit path")?;
    let _ = systemctl(&["stop", "runner"]);
    let _ = systemctl(&["disable", "runner"]);
    match std::fs::remove_file(&unit_path) {
        Ok(()) => println!("removed {}", unit_path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("unit file already absent");
        }
        Err(e) => return Err(e).context("remove service unit"),
    }
    systemctl_checked(&["daemon-reload"])?;
    println!("runner service uninstalled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_contents_mirror_installer_template() {
        let text = unit_file_contents("/home/u/.local/bin/runner start");
        for directive in [
            "Description=runner - Zero-Freeze Local & Federated GitHub Actions Runner",
            "After=network.target",
            "Type=simple",
            "ExecStart=/home/u/.local/bin/runner start",
            "Restart=on-failure",
            "RestartSec=5s",
            "EnvironmentFile=-%h/.config/runner/env",
            "Environment=\"PATH=%h/.cargo/bin:%h/.local/bin:/usr/local/bin:/usr/bin:/bin\"",
            "Slice=runner.slice",
            "KillMode=mixed",
            "TimeoutStopSec=15s",
            "WantedBy=default.target",
        ] {
            assert!(text.contains(directive), "missing {directive}");
        }
    }

    #[test]
    fn unit_path_lands_in_user_systemd_dir() {
        // HOME is set under Unix cargo test; Windows CI leaves it
        // unset, and the path must be absent exactly then.
        match user_unit_path() {
            Some(path) => assert!(path.ends_with(".config/systemd/user/runner.service")),
            None => assert!(
                std::env::var_os("HOME").is_none(),
                "unit path missing while HOME is set"
            ),
        }
    }

    #[test]
    fn binary_path_resolves_to_test_binary() {
        let exe = current_binary_path().unwrap();
        assert!(!exe.is_empty());
        assert!(std::path::Path::new(&exe).exists());
    }
}
