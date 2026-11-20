//! `runner-guest-agent`: Tier-1 in-guest exec agent (vsock client).
//!
//! Baked into the guest rootfs: dials the host, serves one exec session
//! per connection, and exits. See `docs/microvm-tier.md`.

use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("runner-guest-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    run_inner()
}

/// Windows stub: a `main` must exist (a missing `main` is E0601), so
/// this errors loudly and the process exits non-zero via `main`.
#[cfg(windows)]
fn run() -> Result<(), String> {
    eprintln!("[runner] unsupported on Windows: guest-agent (vsock)");
    Err("unsupported on Windows: guest-agent (vsock)".to_string())
}

#[cfg(unix)]
fn run_inner() -> Result<(), String> {
    // Manual arg parsing keeps clap out of the guest binary.
    let mut args = std::env::args().skip(1);
    if let Some(flag) = args.next() {
        if flag != "--uds" {
            return Err(format!("unknown argument {flag:?} (want --uds <PATH>)"));
        }
        let path = args.next().ok_or("--uds needs a socket path")?;
        if args.next().is_some() {
            return Err("unexpected extra arguments".to_string());
        }
        let stream = std::os::unix::net::UnixStream::connect(&path)
            .map_err(|e| format!("connect {path}: {e}"))?;
        return runner_guest_agent::run_agent(stream);
    }
    let stream = runner_guest_agent::connect_host(
        runner_guest_agent::HOST_CID,
        runner_guest_agent::GUEST_VSOCK_PORT,
    )
    .map_err(|e| format!("connect host vsock: {e}"))?;
    runner_guest_agent::run_agent(stream)
}
