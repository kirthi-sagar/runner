//! Tier-1 vsock dispatch without KVM: the host dispatcher against mock
//! guests, and the real guest agent loop against a mock host.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use base64::Engine;
use runner::guest_agent::{
    decode_line, encode_line, run_agent, ExecChunk, ExecRequest, ExecResult, STREAM_STDERR,
    STREAM_STDOUT,
};
use runner::sandbox::vsock::dispatch;
use runner::test_support::TempDir;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn request() -> ExecRequest {
    ExecRequest {
        argv: vec!["echo".to_string(), "hi".to_string()],
        cwd: "/".to_string(),
        env: Vec::new(),
        timeout_secs: 30,
    }
}

fn connect_retry(path: &std::path::Path, attempts: u32) -> UnixStream {
    for _ in 0..attempts {
        if let Ok(stream) = UnixStream::connect(path) {
            return stream;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("mock guest could not connect to {}", path.display());
}

fn chunk_line(stream: u8, data: &[u8]) -> String {
    encode_line(&ExecChunk {
        stream,
        data_b64: b64(data),
    })
    .unwrap()
}

#[tokio::test]
async fn dispatcher_streams_chunks_and_returns_exit_code() {
    let dir = TempDir::new("vsock-happy").unwrap();
    let path = dir.path().join("vsock.sock");
    // The mock guest runs on its own thread (blocking std I/O) while the
    // test future drives the dispatcher; `#[tokio::test]` is
    // single-threaded, so the guest must not share the test thread.
    let guest_path = path.clone();
    let guest = std::thread::spawn(move || {
        let mut guest = connect_retry(&guest_path, 200);
        let mut reader = BufReader::new(guest.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let seen: ExecRequest = decode_line(&line).unwrap();
        guest
            .write_all(chunk_line(STREAM_STDOUT, b"hello\n").as_bytes())
            .unwrap();
        guest
            .write_all(chunk_line(STREAM_STDERR, b"oops\n").as_bytes())
            .unwrap();
        guest
            .write_all(
                encode_line(&ExecResult { exit_code: 3 })
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        seen
    });

    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = dispatch(
        &path,
        &request(),
        Duration::from_secs(10),
        &mut out,
        &mut err,
    )
    .await;

    let seen = guest.join().unwrap();
    assert_eq!(seen.argv, vec!["echo".to_string(), "hi".to_string()]);
    assert_eq!(code.unwrap(), 3);
    assert_eq!(out, b"hello\n");
    assert_eq!(err, b"oops\n");
}

#[tokio::test]
async fn dispatcher_rejects_malformed_guest_output() {
    let dir = TempDir::new("vsock-malformed").unwrap();
    let path = dir.path().join("vsock.sock");
    let guest_path = path.clone();
    let guest = std::thread::spawn(move || {
        let mut guest = connect_retry(&guest_path, 200);
        // Drain the request first so the dispatcher reaches its read phase.
        let mut reader = BufReader::new(guest.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        guest.write_all(b"this is not json\n").unwrap();
    });

    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = dispatch(
        &path,
        &request(),
        Duration::from_secs(10),
        &mut out,
        &mut err,
    )
    .await;

    guest.join().unwrap();
    let msg = result.unwrap_err();
    assert!(msg.contains("guest"), "error: {msg}");
}

#[tokio::test]
async fn dispatcher_times_out_when_no_guest_connects() {
    let dir = TempDir::new("vsock-timeout").unwrap();
    let path = dir.path().join("vsock.sock");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = dispatch(
        &path,
        &request(),
        Duration::from_millis(100),
        &mut out,
        &mut err,
    )
    .await;
    let msg = result.unwrap_err();
    assert!(msg.contains("timed out"), "error: {msg}");
    assert!(!path.exists(), "stale socket file left behind");
}

#[tokio::test]
async fn dispatcher_errors_when_guest_disconnects_early() {
    let dir = TempDir::new("vsock-eof").unwrap();
    let path = dir.path().join("vsock.sock");
    let guest_path = path.clone();
    let guest = std::thread::spawn(move || {
        let guest = connect_retry(&guest_path, 200);
        // Drain the request so the drop lands in the read phase.
        let mut reader = BufReader::new(guest.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        drop(guest);
    });

    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = dispatch(
        &path,
        &request(),
        Duration::from_secs(10),
        &mut out,
        &mut err,
    )
    .await;

    guest.join().unwrap();
    let msg = result.unwrap_err();
    assert!(msg.contains("disconnected"), "error: {msg}");
}

/// Drive the real agent loop over a UDS pair; collect chunks + exit code.
fn run_agent_against(argv: Vec<String>, timeout_secs: u64) -> (Vec<u8>, Vec<u8>, i32) {
    let dir = TempDir::new("vsock-agent").unwrap();
    let path = dir.path().join("vsock.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let agent_path = path.clone();
    let agent = std::thread::spawn(move || {
        let stream = connect_retry(&agent_path, 100);
        run_agent(stream)
    });

    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let req = ExecRequest {
        argv,
        cwd: "/tmp".to_string(),
        env: vec![("RUNNER_TIER".to_string(), "microvm".to_string())],
        timeout_secs,
    };
    writer
        .write_all(encode_line(&req).unwrap().as_bytes())
        .unwrap();

    let mut out = Vec::new();
    let mut err = Vec::new();
    let engine = base64::engine::general_purpose::STANDARD;
    let exit_code = loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "agent closed the stream without a result");
        if let Ok(result) = decode_line::<ExecResult>(&line) {
            break result.exit_code;
        }
        let chunk: ExecChunk = decode_line(&line).unwrap();
        let data = engine.decode(&chunk.data_b64).unwrap();
        match chunk.stream {
            STREAM_STDOUT => out.extend_from_slice(&data),
            STREAM_STDERR => err.extend_from_slice(&data),
            other => panic!("unknown stream {other}"),
        }
    };
    agent.join().unwrap().unwrap();
    (out, err, exit_code)
}

#[test]
fn agent_runs_command_and_splits_streams() {
    let (out, err, code) = run_agent_against(
        vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo out && echo err >&2".to_string(),
        ],
        30,
    );
    assert_eq!(code, 0);
    assert_eq!(out, b"out\n");
    assert_eq!(err, b"err\n");
}

#[test]
fn agent_propagates_exit_codes() {
    let (_, _, code) = run_agent_against(
        vec!["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
        30,
    );
    assert_eq!(code, 7);
}

#[test]
fn agent_kills_overruns_with_timeout_code() {
    let (_, _, code) = run_agent_against(
        vec!["sh".to_string(), "-c".to_string(), "sleep 30".to_string()],
        1,
    );
    assert_eq!(code, 124);
}
