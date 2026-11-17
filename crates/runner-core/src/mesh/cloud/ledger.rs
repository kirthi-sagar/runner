//! Persistent cloud spend ledger (`~/.runner/spend_ledger.json`).
//!
//! Records node launches/terminations so `max_monthly_spend` is enforced
//! against real accrual instead of wishful thinking. Design notes:
//!
//! * [`SpendLedger`] is a path-only handle: every op load-mutate-stores.
//!   `CloudPool` is cloned per call site, so in-struct entries would
//!   diverge; the file is the single source of truth.
//! * Writes are atomic (temp file + rename). Concurrent provisions can
//!   still interleave read-modify-write cycles; worst case is a missed
//!   entry, never a corrupt file.
//! * Billing: whole hours rounded UP per node (cloud convention) times
//!   the provider's standard hourly rate. Cost attributes to the
//!   launch month; running nodes accrue through `now_secs`.
//! * No chrono/time dependency: month math is a few lines of civil-date
//!   arithmetic (Howard Hinnant's days-to-civil algorithm).

use std::path::{Path, PathBuf};

/// Standard hourly rate, USD, for DigitalOcean Basic workers.
pub const RATE_DIGITALOCEAN_PER_HOUR: f64 = 0.009;
/// Standard hourly rate, USD, for Render background workers.
pub const RATE_RENDER_PER_HOUR: f64 = 0.01;

/// Hourly rate for a provider id. Unknown providers bill 0.0 (tracked
/// as nodes, never as spend) rather than failing the ledger.
pub fn hourly_rate(provider: &str) -> f64 {
    match provider {
        "digitalocean" => RATE_DIGITALOCEAN_PER_HOUR,
        "render" => RATE_RENDER_PER_HOUR,
        _ => 0.0,
    }
}

/// One node's billable lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerEntry {
    pub node_id: String,
    pub provider: String,
    pub launched_at: u64,
    /// Unix epoch seconds, or `None` while the node runs.
    #[serde(default)]
    pub terminated_at: Option<u64>,
}

impl LedgerEntry {
    /// Billable whole hours (rounded up) through `now_secs`.
    pub fn billable_hours(&self, now_secs: u64) -> u64 {
        let end = self.terminated_at.unwrap_or(now_secs);
        let secs = end.saturating_sub(self.launched_at);
        secs.div_ceil(3_600)
    }

    /// Accrued USD through `now_secs`.
    pub fn cost_usd(&self, now_secs: u64) -> f64 {
        self.billable_hours(now_secs) as f64 * hourly_rate(&self.provider)
    }
}

/// Convert Unix epoch seconds to (year, month). Proleptic Gregorian;
/// valid for all non-negative inputs.
pub fn year_month(epoch_secs: u64) -> (i32, u32) {
    let days = (epoch_secs / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = if month_prime < 10 {
        (month_prime + 3) as u32
    } else {
        (month_prime - 9) as u32
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month)
}

/// Days since the Unix epoch for a civil date (Hinnant's
/// days-from-civil; inverse of [`year_month`]).
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year } as i64;
    let era = year.div_euclid(400);
    let year_of_era = (year - era * 400) as u64;
    let month_prime = ((month as u64 + 9) % 12) as i64;
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year as u64;
    era * 146_097 + day_of_era as i64 - 719_468
}

/// Parse a provider `created_at` timestamp (`YYYY-MM-DDTHH:MM:SSZ`,
/// fractional seconds tolerated) into Unix epoch seconds. Returns
/// `None` for anything else rather than guessing.
pub fn parse_rfc3339_utc(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let time = time.split('.').next()?;
    let parse2 = |s: &str| s.parse::<u32>().ok().filter(|_| s.len() == 2);
    let parse4 = |s: &str| s.parse::<i32>().ok().filter(|_| s.len() == 4);
    let mut date = date.split('-');
    let (year, month, day) = (
        parse4(date.next()?)?,
        parse2(date.next()?)?,
        parse2(date.next()?)?,
    );
    if date.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut time = time.split(':');
    let (hour, min, sec) = (
        parse2(time.next()?)?,
        parse2(time.next()?)?,
        parse2(time.next()?)?,
    );
    if time.next().is_some() || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour as i64 * 3_600 + min as i64 * 60 + sec as i64;
    u64::try_from(secs).ok()
}

/// Default ledger location (`~/.runner/spend_ledger.json`).
pub fn default_ledger_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".runner")
            .join("spend_ledger.json")
    })
}

/// Path-only spend ledger handle (see module docs).
#[derive(Debug, Clone)]
pub struct SpendLedger {
    path: PathBuf,
}

impl SpendLedger {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load entries; a missing file means an empty ledger (created on
    /// first write), a corrupt file is an error.
    pub fn load(&self) -> Result<Vec<LedgerEntry>, String> {
        match std::fs::read_to_string(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("cannot read ledger {}: {e}", self.path.display())),
            Ok(text) => {
                if text.trim().is_empty() {
                    return Ok(Vec::new());
                }
                serde_json::from_str(&text)
                    .map_err(|e| format!("cannot parse ledger {}: {e}", self.path.display()))
            }
        }
    }

    /// Persist entries atomically (temp file + rename), creating parent
    /// directories on first write.
    pub fn store(&self, entries: &[LedgerEntry]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create ledger dir {}: {e}", parent.display()))?;
        }
        let text = serde_json::to_string_pretty(entries)
            .map_err(|e| format!("cannot encode ledger: {e}"))?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)
            .map_err(|e| format!("cannot write ledger {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("cannot commit ledger {}: {e}", self.path.display()))?;
        Ok(())
    }

    /// Record a launch (idempotent per node id).
    pub fn record_launch(
        &self,
        node_id: &str,
        provider: &str,
        launched_at: u64,
    ) -> Result<(), String> {
        let mut entries = self.load()?;
        if !entries.iter().any(|e| e.node_id == node_id) {
            entries.push(LedgerEntry {
                node_id: node_id.to_string(),
                provider: provider.to_string(),
                launched_at,
                terminated_at: None,
            });
            self.store(&entries)?;
        }
        Ok(())
    }

    /// Record a termination (no-op for unknown ids).
    pub fn record_termination(&self, node_id: &str, terminated_at: u64) -> Result<(), String> {
        let mut entries = self.load()?;
        if let Some(entry) = entries.iter_mut().find(|e| e.node_id == node_id) {
            entry.terminated_at = Some(terminated_at);
            self.store(&entries)?;
        }
        Ok(())
    }

    /// Total USD accrued by entries launched in (year, month).
    pub fn month_spend(&self, year: i32, month: u32, now_secs: u64) -> Result<f64, String> {
        Ok(self
            .load()?
            .iter()
            .filter(|e| year_month(e.launched_at) == (year, month))
            .map(|e| e.cost_usd(now_secs))
            .sum())
    }

    /// Spend for the calendar month containing `now_secs`.
    pub fn current_month_spend(&self, now_secs: u64) -> Result<f64, String> {
        let (year, month) = year_month(now_secs);
        self.month_spend(year, month, now_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-11-16T00:00:00Z.
    const NOV_16: u64 = 1_794_787_200;

    #[test]
    fn year_month_matches_known_dates() {
        assert_eq!(year_month(0), (1970, 1));
        assert_eq!(year_month(NOV_16), (2026, 11));
        // Leap day 2024-02-29.
        assert_eq!(year_month(1_709_164_800), (2024, 2));
        // Year boundary: 2025-12-31 23:59:59Z vs 2026-01-01.
        assert_eq!(year_month(1_767_225_599), (2025, 12));
        assert_eq!(year_month(1_767_225_600), (2026, 1));
    }

    #[test]
    fn rfc3339_round_trips_known_dates() {
        assert_eq!(parse_rfc3339_utc("2026-11-16T00:00:00Z"), Some(NOV_16));
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
        // Fractional seconds tolerated.
        assert_eq!(
            parse_rfc3339_utc("2026-11-16T00:00:00.123456Z"),
            Some(NOV_16)
        );
        // Round-trip through year_month for a leap day.
        let leap = parse_rfc3339_utc("2024-02-29T12:30:00Z").unwrap();
        assert_eq!(year_month(leap), (2024, 2));
        // Garbage rejected, never guessed.
        for bad in [
            "",
            "2026-11-16",
            "2026-13-01T00:00:00Z",
            "2026-11-32T00:00:00Z",
            "2026-11-16T25:00:00Z",
            "2026-11-16T00:00:00+00:00",
            "2026-11-16 00:00:00",
        ] {
            assert_eq!(parse_rfc3339_utc(bad), None, "input: {bad}");
        }
    }

    #[test]
    fn billing_rounds_up_to_whole_hours() {
        let entry = LedgerEntry {
            node_id: "i".to_string(),
            provider: "digitalocean".to_string(),
            launched_at: 1_000,
            terminated_at: Some(1_001),
        };
        assert_eq!(entry.billable_hours(9_999), 1);
        assert!((entry.cost_usd(9_999) - 0.009).abs() < 1e-9);
        // Unknown providers accrue nodes, never spend.
        let unknown = LedgerEntry {
            provider: "mystery".to_string(),
            ..entry.clone()
        };
        assert_eq!(unknown.cost_usd(9_999), 0.0);
        // Running nodes accrue through now.
        let running = LedgerEntry {
            terminated_at: None,
            ..entry
        };
        assert_eq!(running.billable_hours(1_000 + 3_600), 1);
        assert_eq!(running.billable_hours(1_000 + 3_601), 2);
    }

    fn temp_ledger(name: &str) -> (SpendLedger, PathBuf) {
        let dir = std::env::temp_dir().join(format!("runner-ledger-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ledger = SpendLedger::new(dir.join("spend_ledger.json"));
        (ledger, dir)
    }

    #[test]
    fn missing_file_is_empty_and_first_write_creates_it() {
        let (ledger, dir) = temp_ledger("create");
        assert_eq!(ledger.load().unwrap(), Vec::new());
        assert!(!ledger.path().exists());
        ledger.record_launch("i-1", "render", NOV_16).unwrap();
        assert!(ledger.path().exists());
        // Idempotent relaunch, then termination.
        ledger.record_launch("i-1", "render", NOV_16).unwrap();
        assert_eq!(ledger.load().unwrap().len(), 1);
        ledger.record_termination("i-1", NOV_16 + 60).unwrap();
        ledger.record_termination("ghost", NOV_16).unwrap();
        let entries = ledger.load().unwrap();
        assert_eq!(entries[0].terminated_at, Some(NOV_16 + 60));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn month_spend_attributes_to_launch_month() {
        let (ledger, dir) = temp_ledger("month");
        // October node (2026-10-15): 1 billable hour.
        ledger
            .record_launch("oct", "render", 1_792_022_400)
            .unwrap();
        ledger
            .record_termination("oct", 1_792_022_400 + 60)
            .unwrap();
        // November node: still running at NOV_16 + 30min.
        ledger.record_launch("nov", "digitalocean", NOV_16).unwrap();
        assert!((ledger.month_spend(2026, 10, NOV_16).unwrap() - 0.01).abs() < 1e-9);
        let nov = ledger.current_month_spend(NOV_16 + 1_800).unwrap();
        assert!((nov - 0.009).abs() < 1e-9, "{nov}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_file_errors_loudly() {
        let (ledger, dir) = temp_ledger("corrupt");
        std::fs::create_dir_all(dir.clone()).unwrap();
        std::fs::write(ledger.path(), "{nope").unwrap();
        assert!(ledger.load().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
