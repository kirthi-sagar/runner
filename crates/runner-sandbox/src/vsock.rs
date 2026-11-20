//! Host side of Tier-1 guest dispatch: serve one exec session over the
//! Firecracker UDS-backed vsock socket.
//!
//! The guest agent dials out; the host binds `uds_path`, waits for the
//! connection, sends the [`ExecRequest`],
//! streams stdio chunks into the caller's writers, and returns the exit
//! code. The socket file is removed on every path.

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use runner_guest_agent::{
    decode_line, encode_line, ExecChunk, ExecRequest, ExecResult, STREAM_STDERR, STREAM_STDOUT,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

/// Maximum protocol line accepted from the guest (8 KiB chunks land near
/// 11 KiB base64; anything larger is a runaway or hostile guest).
const MAX_LINE_BYTES: usize = 256 * 1024;

/// Dispatch one command to the guest agent and return its exit code.
/// `timeout` bounds both the guest connect wait and the whole session.
pub async fn dispatch<W1, W2>(
    uds_path: &Path,
    request: &ExecRequest,
    timeout: Duration,
    stdout: &mut W1,
    stderr: &mut W2,
) -> Result<i32, String>
where
    W1: tokio::io::AsyncWrite + Unpin,
    W2: tokio::io::AsyncWrite + Unpin,
{
    let outcome = dispatch_inner(uds_path, request, timeout, stdout, stderr).await;
    let _ = std::fs::remove_file(uds_path);
    outcome
}

async fn dispatch_inner<W1, W2>(
    uds_path: &Path,
    request: &ExecRequest,
    timeout: Duration,
    stdout: &mut W1,
    stderr: &mut W2,
) -> Result<i32, String>
where
    W1: tokio::io::AsyncWrite + Unpin,
    W2: tokio::io::AsyncWrite + Unpin,
{
    if request.argv.is_empty() {
        return Err("no command to execute".to_string());
    }
    let _ = std::fs::remove_file(uds_path);
    let listener = tokio::net::UnixListener::bind(uds_path)
        .map_err(|e| format!("bind {}: {e}", uds_path.display()))?;
    let (stream, _) = tokio::time::timeout(timeout, listener.accept())
        .await
        .map_err(|_| {
            format!(
                "vsock dispatch timed out after {}s waiting for the guest",
                timeout.as_secs()
            )
        })?
        .map_err(|e| format!("accept guest connection: {e}"))?;
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(encode_line(request)?.as_bytes())
        .await
        .map_err(|e| format!("send exec request: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("send exec request: {e}"))?;

    let mut lines = tokio::io::BufReader::new(reader).lines();
    let session = async {
        loop {
            let line = lines
                .next_line()
                .await
                .map_err(|e| format!("read guest output: {e}"))?
                .ok_or_else(|| "guest disconnected before sending a result".to_string())?;
            if line.len() > MAX_LINE_BYTES {
                return Err("guest sent an oversized protocol line".to_string());
            }
            if let Ok(result) = decode_line::<ExecResult>(&line) {
                stdout
                    .flush()
                    .await
                    .map_err(|e| format!("flush stdout: {e}"))?;
                stderr
                    .flush()
                    .await
                    .map_err(|e| format!("flush stderr: {e}"))?;
                return Ok(result.exit_code);
            }
            let chunk: ExecChunk =
                decode_line(&line).map_err(|e| format!("guest protocol error: {e}"))?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(&chunk.data_b64)
                .map_err(|e| format!("guest sent invalid base64: {e}"))?;
            match chunk.stream {
                STREAM_STDOUT => stdout
                    .write_all(&data)
                    .await
                    .map_err(|e| format!("write stdout: {e}"))?,
                STREAM_STDERR => stderr
                    .write_all(&data)
                    .await
                    .map_err(|e| format!("write stderr: {e}"))?,
                other => return Err(format!("guest sent unknown stream {other}")),
            }
        }
    };
    tokio::time::timeout(timeout, session)
        .await
        .map_err(|_| format!("vsock dispatch timed out after {}s", timeout.as_secs()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> ExecRequest {
        ExecRequest {
            argv: vec!["id".to_string()],
            cwd: "/".to_string(),
            env: Vec::new(),
            timeout_secs: 60,
        }
    }

    #[tokio::test]
    async fn empty_argv_is_rejected_before_binding() {
        let dir = runner_core::test_support::TempDir::new("vsock-empty").unwrap();
        let path = dir.path().join("vsock.sock");
        let mut request = sample_request();
        request.argv.clear();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let msg = dispatch(&path, &request, Duration::from_secs(5), &mut out, &mut err)
            .await
            .unwrap_err();
        assert!(msg.contains("no command"), "error: {msg}");
        assert!(!path.exists());
    }
}
