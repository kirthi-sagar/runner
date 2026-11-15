//! One-shot loopback HTTP stub for client tests (std only, no deps).
//! Serves exactly one response, then exits. Never blocks longer than the
//! client's own timeout: reads headers only, ignores any body.

use std::io::{Read, Write};
use std::net::TcpListener;

/// Serve one fixed response; returns the base URL (no trailing path).
/// `headers` are extra `Name: value` lines (status line + content-length
/// are automatic).
pub fn serve_once(
    status: u16,
    reason: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("stub bind");
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        // Drain headers (single read suffices for small test requests).
        let mut buf = [0u8; 65536];
        let mut seen = 0;
        loop {
            match stream.read(&mut buf[seen..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    seen += n;
                    if seen >= 4 && buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if seen == buf.len() {
                        break;
                    }
                }
            }
        }
        let mut head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body.as_bytes());
        let _ = stream.flush();
    });
    (base, handle)
}
