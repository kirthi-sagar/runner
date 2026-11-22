//! Tier-1 guest agent: runs inside the Firecracker guest, executes one
//! command per connection, and streams output back to the host over vsock.
//!
//! Protocol (newline-delimited JSON, base64 stdio): host sends one
//! [`ExecRequest`]; the guest replies with [`ExecChunk`]s and a final
//! [`ExecResult`]. Both sides share these types, so the wire format can
//! never drift.
//!
//! The agent is blocking std (no async runtime) so the guest binary stays
//! tiny. vsock connect uses raw libc syscalls instead of a vsock crate.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::io::FromRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Well-known vsock port the guest dials. Firecracker's UDS-backed vsock
/// forwards guest connections to the host listener; the port is a
/// convention both sides agree on.
pub const GUEST_VSOCK_PORT: u32 = 5000;
/// Host context id (always 2 in vsock).
pub const HOST_CID: u32 = 2;
/// Exit code reported after killing an overrunning command.
pub const EXIT_TIMEOUT: i32 = 124;
/// Stdio read size per chunk (matches the daemon's 8 KiB capture chunks).
pub const CHUNK_READ_BYTES: usize = 8 * 1024;
/// [`ExecChunk::stream`] value for stdout.
pub const STREAM_STDOUT: u8 = 1;
/// [`ExecChunk::stream`] value for stderr.
pub const STREAM_STDERR: u8 = 2;

/// One command to run (host -> guest).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub timeout_secs: u64,
}

/// One stdio fragment (guest -> host, base64 so lines never break).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecChunk {
    pub stream: u8,
    pub data_b64: String,
}

/// Final exit status (guest -> host, exactly one per session).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecResult {
    pub exit_code: i32,
}

/// Serialize one protocol line, newline-terminated.
pub fn encode_line<T: Serialize>(value: &T) -> Result<String, String> {
    let mut line =
        serde_json::to_string(value).map_err(|e| format!("encode protocol line: {e}"))?;
    line.push('\n');
    Ok(line)
}

/// Parse one protocol line (trailing newline tolerated).
pub fn decode_line<T: serde::de::DeserializeOwned>(line: &str) -> Result<T, String> {
    serde_json::from_str(line.trim_end_matches('\n'))
        .map_err(|e| format!("decode protocol line: {e}"))
}

/// Connect to the host over vsock, returning the stream as a file.
///
/// Raw syscalls with the kernel `sockaddr_vm` layout (no vsock crate, so
/// the guest binary keeps zero non-workspace dependencies). The fd is
/// closed on every error path and owned by the returned `File` on success.
#[cfg(unix)]
pub fn connect_host(cid: u32, port: u32) -> std::io::Result<File> {
    #[repr(C)]
    struct SockAddrVm {
        family: u16,
        reserved1: u16,
        port: u32,
        cid: u32,
        flags: u8,
        zero: [u8; 3],
    }
    const AF_VSOCK: libc::c_int = 40;
    // SAFETY: single-purpose socket/connect/close sequence; the address
    // struct matches the kernel layout (16 bytes) and the fd never leaks.
    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let addr = SockAddrVm {
            family: AF_VSOCK as u16,
            reserved1: 0,
            port,
            cid,
            flags: 0,
            zero: [0; 3],
        };
        let rc = libc::connect(
            fd,
            &addr as *const SockAddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockAddrVm>() as libc::socklen_t,
        );
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        Ok(File::from_raw_fd(fd))
    }
}

/// Windows has no vsock; the guest agent cannot dial the host.
#[cfg(windows)]
pub fn connect_host(_cid: u32, _port: u32) -> std::io::Result<File> {
    eprintln!("[runner] unsupported on Windows: guest-agent (vsock)");
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported on Windows: guest-agent (vsock)",
    ))
}

fn pump_pipe<R: Read, W: Write>(
    mut reader: R,
    stream: u8,
    writer: &std::sync::Mutex<W>,
) -> Result<(), String> {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut buf = vec![0u8; CHUNK_READ_BYTES];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read guest stdio: {e}"))?;
        if n == 0 {
            break;
        }
        let line = encode_line(&ExecChunk {
            stream,
            data_b64: engine.encode(&buf[..n]),
        })?;
        writer
            .lock()
            .map_err(|_| "chunk writer lock poisoned".to_string())?
            .write_all(line.as_bytes())
            .map_err(|e| format!("send chunk: {e}"))?;
    }
    Ok(())
}

/// Orderly write-side shutdown for session streams: the vsock
/// `File` via libc (UnixStream has it natively). Draining the final
/// frame before close is what keeps Firecracker's host epoll loop
/// from losing the result under load.
pub trait ShutdownWrite {
    fn shutdown_write(&self) -> std::io::Result<()>;
}

#[cfg(unix)]
impl ShutdownWrite for std::fs::File {
    fn shutdown_write(&self) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        // SAFETY: live fd from our own stream; SHUT_WR only.
        let rc = unsafe { libc::shutdown(self.as_raw_fd(), libc::SHUT_WR) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
impl ShutdownWrite for std::os::unix::net::UnixStream {
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// Serve one exec session on an established stream: read the request, run
/// it, stream chunks, send the result. Blocking; call on a thread.
pub fn run_agent<S: Read + Write + ShutdownWrite + Send + 'static>(
    mut stream: S,
) -> Result<(), String> {
    let request: ExecRequest = {
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("read request: {e}"))?;
        if line.is_empty() {
            return Err("host closed the stream before sending a request".to_string());
        }
        decode_line(&line)?
    };
    if request.argv.is_empty() {
        return Err("empty argv in exec request".to_string());
    }
    let mut child = Command::new(&request.argv[0])
        .args(&request.argv[1..])
        .current_dir(&request.cwd)
        .envs(request.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", request.argv[0]))?;

    let writer = std::sync::Arc::new(std::sync::Mutex::new(stream));
    let stdout = child.stdout.take().ok_or("stdout was not piped")?;
    let stderr = child.stderr.take().ok_or("stderr was not piped")?;
    let out_writer = std::sync::Arc::clone(&writer);
    let pump_out = std::thread::spawn(move || pump_pipe(stdout, STREAM_STDOUT, &out_writer));
    let err_writer = std::sync::Arc::clone(&writer);
    let pump_err = std::thread::spawn(move || pump_pipe(stderr, STREAM_STDERR, &err_writer));

    let deadline = Instant::now() + Duration::from_secs(request.timeout_secs.max(1));
    let exit_code = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("wait for guest command: {e}"))?
        {
            break status.code().unwrap_or(1);
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            let _ = child.wait();
            break EXIT_TIMEOUT;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    pump_out
        .join()
        .map_err(|_| "stdout pump panicked".to_string())??;
    pump_err
        .join()
        .map_err(|_| "stderr pump panicked".to_string())??;

    let line = encode_line(&ExecResult { exit_code })?;
    let mut guard = writer
        .lock()
        .map_err(|_| "result writer lock poisoned".to_string())?;
    guard
        .write_all(line.as_bytes())
        .map_err(|e| format!("send result: {e}"))?;
    guard.flush().map_err(|e| format!("flush result: {e}"))?;
    // Orderly shutdown plus a drain pause: the host epoll loop gets
    // CPU cycles to pull the final frame before we exit. Without
    // this, PID-1 exit can halt the virtio queues first and the
    // result frame never arrives (observed live under host load).
    guard
        .shutdown_write()
        .map_err(|e| format!("shutdown result stream: {e}"))?;
    std::thread::sleep(Duration::from_millis(50));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ExecRequest {
        ExecRequest {
            argv: vec!["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
            cwd: "/".to_string(),
            env: vec![("A".to_string(), "b=c".to_string())],
            timeout_secs: 60,
        }
    }

    #[test]
    fn protocol_round_trips() {
        let request = sample_request();
        let line = encode_line(&request).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(decode_line::<ExecRequest>(&line).unwrap(), request);

        let chunk = ExecChunk {
            stream: STREAM_STDERR,
            data_b64: "aGk=".to_string(),
        };
        let line = encode_line(&chunk).unwrap();
        assert_eq!(decode_line::<ExecChunk>(&line).unwrap(), chunk);

        let result = ExecResult { exit_code: 7 };
        let line = encode_line(&result).unwrap();
        assert_eq!(decode_line::<ExecResult>(&line).unwrap(), result);
    }

    #[test]
    fn protocol_rejects_malformed_and_foreign_lines() {
        assert!(decode_line::<ExecRequest>("not json\n").is_err());
        assert!(decode_line::<ExecChunk>("{\"stream\":1}\n").is_err());
        // Unknown fields are rejected so wire drift fails loudly.
        assert!(decode_line::<ExecResult>("{\"exit_code\":0,\"extra\":1}\n").is_err());
        // Message kinds are unambiguous: a chunk never parses as a result.
        let chunk = encode_line(&ExecChunk {
            stream: STREAM_STDOUT,
            data_b64: "eA==".to_string(),
        })
        .unwrap();
        assert!(decode_line::<ExecResult>(&chunk).is_err());
    }

    // Full session over a socket pair: the result frame arrives with
    // the child's exit code, then an orderly EOF (no RST, no loss).
    // Pins the serve-chunks-then-result-then-shutdown mechanism; the
    // vsock race itself is proven by the live KVM harness.
    #[cfg(unix)]
    #[test]
    fn session_result_precedes_orderly_shutdown() {
        use std::os::unix::net::UnixStream;

        let (host, guest) = UnixStream::pair().unwrap();
        let agent = std::thread::spawn(move || run_agent(guest));
        let request = ExecRequest {
            argv: vec!["/bin/echo".to_string(), "hi".to_string()],
            cwd: "/".to_string(),
            env: Vec::new(),
            timeout_secs: 10,
        };
        let mut host_write = host.try_clone().unwrap();
        std::io::Write::write_all(&mut host_write, encode_line(&request).unwrap().as_bytes())
            .unwrap();
        let mut lines = std::io::BufReader::new(host).lines();
        let mut saw_chunk = false;
        let mut saw_result = false;
        for line in lines.by_ref() {
            let line = line.unwrap();
            if let Ok(result) = decode_line::<ExecResult>(&line) {
                assert_eq!(result.exit_code, 0);
                saw_result = true;
                break;
            }
            let chunk = decode_line::<ExecChunk>(&line).unwrap();
            assert_eq!(chunk.stream, STREAM_STDOUT);
            saw_chunk = true;
        }
        assert!(saw_chunk, "expected at least one stdout chunk");
        assert!(saw_result, "expected a final result frame");
        assert!(lines.next().is_none(), "expected EOF after result");
        agent.join().unwrap().unwrap();
    }
}
