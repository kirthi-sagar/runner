//! High-speed ring-buffer stdout/stderr capture and structured JSON log
//! events shared by community and enterprise editions.

use std::collections::VecDeque;
use std::io::Write;

use serde::{Deserialize, Serialize};

/// Fixed-capacity byte ring: oldest bytes are evicted first, so a runaway
/// job can never grow capture memory without bound.
#[derive(Debug, Clone)]
pub struct RingBuffer {
    buf: VecDeque<u8>,
    cap: usize,
}

impl RingBuffer {
    /// Create a ring holding at most `capacity` bytes (minimum 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            cap: capacity.max(1),
        }
    }

    /// Append bytes, evicting the oldest when over capacity.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.buf.len() >= self.cap {
                self.buf.pop_front();
            }
            self.buf.push_back(b);
        }
    }

    /// Oldest-first snapshot of retained bytes.
    pub fn contents(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    /// Retained bytes as lossy UTF-8 (log-friendly).
    pub fn contents_utf8(&self) -> String {
        String::from_utf8_lossy(&self.contents()).into_owned()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }
}

impl Write for RingBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.push_bytes(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Log severity for structured events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// One structured, JSON-serializable log event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEvent {
    /// Milliseconds since the Unix epoch.
    pub ts_unix_ms: u64,
    pub level: LogLevel,
    /// Emitting subsystem (`governor`, `worker`, `audit`, ...).
    pub source: String,
    pub message: String,
}

impl LogEvent {
    pub fn now(level: LogLevel, source: impl Into<String>, message: impl Into<String>) -> Self {
        let ts_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            ts_unix_ms,
            level,
            source: source.into(),
            message: message.into(),
        }
    }

    /// Compact single-line JSON (JSONL-friendly).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_evicts_oldest_first() {
        let mut ring = RingBuffer::new(4);
        ring.push_bytes(b"abcdef");
        assert_eq!(ring.contents(), b"cdef");
        assert_eq!(ring.len(), 4);
        assert!(!ring.is_empty());
    }

    #[test]
    fn ring_implements_write_for_streaming_capture() {
        let mut ring = RingBuffer::new(64);
        let (job, status) = (7, "ok");
        write!(ring, "job-{job}: {status}").unwrap();
        ring.flush().unwrap();
        assert_eq!(ring.contents_utf8(), "job-7: ok");
    }

    #[test]
    fn log_event_json_round_trip() {
        let event = LogEvent::now(LogLevel::Warn, "governor", "throttled to 25");
        let json = event.to_json();
        assert!(json.contains("\"level\":\"warn\""));
        assert!(json.contains("\"source\":\"governor\""));
        let back: LogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }
}
