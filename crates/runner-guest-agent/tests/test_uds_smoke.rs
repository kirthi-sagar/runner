//! End-to-end smoke: the real `runner-guest-agent` binary serves one
//! session over a loopback UDS socket (`--uds` seam for hosts without
//! vsock, mirroring the repo's loopback-seam testing posture).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;

use base64::Engine;
use runner_guest_agent::{
    decode_line, encode_line, ExecChunk, ExecRequest, ExecResult, STREAM_STDOUT,
};

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("guest-smoke-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn guest_binary_serves_one_uds_session() {
    let dir = scratch("session");
    let sock = dir.join("guest.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_runner-guest-agent"))
        .arg("--uds")
        .arg(&sock)
        .stdin(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let (stream, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    let request = ExecRequest {
        argv: vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo smoked".to_string(),
        ],
        cwd: "/tmp".to_string(),
        env: Vec::new(),
        timeout_secs: 30,
    };
    writer
        .write_all(encode_line(&request).unwrap().as_bytes())
        .unwrap();

    let engine = base64::engine::general_purpose::STANDARD;
    let mut out = Vec::new();
    let exit_code = loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "agent exited without a result");
        if let Ok(result) = decode_line::<ExecResult>(&line) {
            break result.exit_code;
        }
        let chunk: ExecChunk = decode_line(&line).unwrap();
        assert_eq!(chunk.stream, STREAM_STDOUT);
        out.extend_from_slice(&engine.decode(&chunk.data_b64).unwrap());
    };
    assert_eq!(exit_code, 0);
    assert_eq!(out, b"smoked\n");
    assert!(child.wait().unwrap().success());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn guest_binary_rejects_bad_arguments() {
    for args in [vec!["--bogus"], vec!["--uds"], vec!["a", "b", "c"]] {
        let status = Command::new(env!("CARGO_BIN_EXE_runner-guest-agent"))
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "args {args:?} must fail");
    }
}
