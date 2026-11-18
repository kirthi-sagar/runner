//! Tamper-evident audit trail: every entry embeds the SHA-256 hash of
//! its predecessor, so any insertion, deletion, or edit breaks the chain
//! and is detected by [`AuditLog::verify`]. Entries persist as JSONL.

use std::path::{Path, PathBuf};

use runner_telemetry::{LogEvent, LogLevel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One chained audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub event: LogEvent,
    pub hash: String,
}

fn entry_hash(seq: u64, prev_hash: &str, event_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(event_json.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Append-only audit log backed by a JSONL file.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Open (creating parent dirs); replays and verifies any existing chain.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("audit dir: {e}"))?;
        }
        let mut log = Self {
            path: path.to_path_buf(),
            entries: Vec::new(),
        };
        if path.exists() {
            let text = std::fs::read_to_string(path).map_err(|e| format!("audit read: {e}"))?;
            for (line_no, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: AuditEntry = serde_json::from_str(line)
                    .map_err(|e| format!("audit line {}: {e}", line_no + 1))?;
                log.entries.push(entry);
            }
            if !log.verify() {
                return Err("audit chain verification failed on open".to_string());
            }
        }
        Ok(log)
    }

    /// Append an event, chaining it to its predecessor. Returns the
    /// owned entry: no `expect`/`Option` dereference anywhere, so this
    /// can never abort the daemon under `panic = "abort"`.
    pub fn append(&mut self, level: LogLevel, source: &str, message: &str) -> AuditEntry {
        let seq = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "genesis".to_string());
        let event = LogEvent::now(level, source, message);
        let hash = entry_hash(seq, &prev_hash, &event.to_json());
        let entry = AuditEntry {
            seq,
            prev_hash,
            event,
            hash,
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(file, "{json}");
            }
        }
        self.entries.push(entry.clone());
        entry
    }

    /// Recompute the full chain; false on any gap, reorder, or edit.
    pub fn verify(&self) -> bool {
        let mut prev = "genesis".to_string();
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != prev {
                return false;
            }
            if entry.hash != entry_hash(entry.seq, &entry.prev_hash, &entry.event.to_json()) {
                return false;
            }
            prev = entry.hash.clone();
        }
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Default audit trail (`~/.config/runner/audit.jsonl`).
pub fn default_audit_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("runner")
            .join("audit.jsonl")
    })
}

/// Structured outcome of [`verify_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// No trail file exists yet — nothing to verify, not tampering.
    Absent { path: PathBuf },
    /// Chain recomputed cleanly over `entries` entries.
    Intact { path: PathBuf, entries: usize },
    /// Tamper detected: broken hash, gap, reorder, or unreadable entry.
    Tampered { path: PathBuf, reason: String },
}

impl VerifyOutcome {
    /// True unless tampering was detected (absent trails pass).
    pub fn ok(&self) -> bool {
        !matches!(self, Self::Tampered { .. })
    }

    /// Human-readable one-paragraph report for CLI output.
    pub fn report(&self) -> String {
        match self {
            Self::Absent { path } => format!(
                "no audit trail at {} yet — nothing to verify (run jobs to start the chain)",
                path.display()
            ),
            Self::Intact { path, entries } => format!(
                "audit trail intact: {entries} entries verified, SHA-256 chain clean ({})",
                path.display()
            ),
            Self::Tampered { path, reason } => {
                format!("AUDIT TAMPER DETECTED at {}: {reason}", path.display())
            }
        }
    }
}

/// Verify the JSONL trail at `path`: replays entries in order, recomputes
/// every link, and reports gaps, reorders, edits, or parse failures.
pub fn verify_file(path: &Path) -> VerifyOutcome {
    if !path.exists() {
        return VerifyOutcome::Absent {
            path: path.to_path_buf(),
        };
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            return VerifyOutcome::Tampered {
                path: path.to_path_buf(),
                reason: format!("unreadable trail file: {e}"),
            }
        }
    };
    let mut entries = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                return VerifyOutcome::Tampered {
                    path: path.to_path_buf(),
                    reason: format!("line {} is not a valid entry: {e}", line_no + 1),
                }
            }
        }
    }
    let log = AuditLog {
        path: path.to_path_buf(),
        entries,
    };
    if log.verify() {
        VerifyOutcome::Intact {
            path: path.to_path_buf(),
            entries: log.len(),
        }
    } else {
        VerifyOutcome::Tampered {
            path: path.to_path_buf(),
            reason: "hash chain broken: gap, reorder, or edited entry".to_string(),
        }
    }
}

/// Export failure modes for [`export_trail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// No trail file: nothing to export (not tampering).
    Absent(PathBuf),
    /// Chain failed verification: export refused (fail closed).
    Tampered(String),
    /// Trail unreadable.
    Io(String),
}

/// Export the trail as canonical JSONL (one entry per line) for SIEM /
/// compliance ingestion. The chain is verified first: any gap, reorder,
/// edit, or malformed line refuses the export with [`ExportError::Tampered`]
/// — partial or suspicious segments are never silently emitted.
pub fn export_trail(path: &Path) -> Result<String, ExportError> {
    match verify_file(path) {
        VerifyOutcome::Absent { path } => Err(ExportError::Absent(path)),
        VerifyOutcome::Tampered { reason, .. } => Err(ExportError::Tampered(reason)),
        VerifyOutcome::Intact { .. } => {
            let text = std::fs::read_to_string(path).map_err(|e| ExportError::Io(e.to_string()))?;
            let mut out = String::new();
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                // Re-parse + re-serialize so output is canonical JSONL.
                let entry: AuditEntry = serde_json::from_str(line).map_err(|e| {
                    ExportError::Tampered(format!("entry changed during export: {e}"))
                })?;
                out.push_str(
                    &serde_json::to_string(&entry)
                        .map_err(|e| ExportError::Io(format!("serialize entry: {e}")))?,
                );
                out.push('\n');
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_verify_and_replay_round_trip() {
        let dir = runner_core::test_support::TempDir::new("audit").unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(&path).unwrap();
        assert!(log.is_empty());
        log.append(LogLevel::Info, "fleet", "runner-1 registered");
        log.append(LogLevel::Warn, "governor", "throttled to 25");
        assert_eq!(log.len(), 2);
        assert!(log.verify());

        // Tampering with any entry breaks the chain.
        let mut tampered = AuditLog::open(&path).unwrap();
        tampered.entries[0].event.message = "forged".to_string();
        assert!(!tampered.verify());

        // Reloading the untouched file verifies cleanly.
        let reloaded = AuditLog::open(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.verify());
    }
}
