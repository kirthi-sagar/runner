//! Workstation thermal & battery guards (Spec §5.4).
//!
//! Older laptops in a home mesh must not cook or drain themselves on
//! prolonged multi-core builds: past 85°C package temperature the
//! governor throttles to a trickle, and on battery power the node
//! stops taking new jobs until AC returns. All readers take an
//! injected sysfs root (the `topology.rs` fixture pattern) so unit
//! tests never touch the live host.

use std::fs;
use std::path::Path;

/// Engage the thermal throttle at or above this package temp (°C).
pub const THERMAL_THROTTLE_C: f64 = 85.0;
/// Release the throttle once temp drops below this (°C hysteresis).
pub const THERMAL_RELEASE_C: f64 = 78.0;

/// Package-temp zone types, preferred first. Matching is by `type`
/// string, never by zone index (numbering varies per board).
const PACKAGE_ZONE_TYPES: [&str; 3] = ["x86_pkg_temp", "coretemp", "package_id_0"];

/// Host power source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// On AC (or no battery sensor exists: desktops, VMs, containers).
    Ac,
    /// Running on battery: halt new job intake.
    Discharging,
}

/// Highest CPU package temperature (°C) under a
/// `/sys/class/thermal`-shaped directory. Prefers package-temp zones;
/// falls back to the max across all zones; `None` when unreadable.
pub fn read_package_temp_c(thermal_root: &Path) -> Option<f64> {
    let mut package_max: Option<f64> = None;
    let mut global_max: Option<f64> = None;
    let mut index = 0u32;
    loop {
        let zone = thermal_root.join(format!("thermal_zone{index}"));
        let temp_path = zone.join("temp");
        if !temp_path.exists() {
            break;
        }
        index += 1;
        let Ok(text) = fs::read_to_string(&temp_path) else {
            continue;
        };
        let Ok(millidegrees) = text.trim().parse::<i64>() else {
            continue;
        };
        let celsius = millidegrees as f64 / 1000.0;
        global_max = Some(global_max.map_or(celsius, |m: f64| m.max(celsius)));
        let zone_type = fs::read_to_string(zone.join("type"))
            .map(|t| t.trim().to_string())
            .unwrap_or_default();
        if PACKAGE_ZONE_TYPES.contains(&zone_type.as_str()) {
            package_max = Some(package_max.map_or(celsius, |m: f64| m.max(celsius)));
        }
    }
    package_max.or(global_max)
}

/// Live host package temperature.
pub fn package_temp_c() -> Option<f64> {
    read_package_temp_c(Path::new("/sys/class/thermal"))
}

/// Power source under a `/sys/class/power_supply`-shaped directory.
/// Any `BAT*` reporting `Discharging` means battery; anything else
/// (including no battery sensor at all) means AC.
pub fn read_power_state(power_root: &Path) -> PowerState {
    let mut index = 0u32;
    loop {
        // `BAT0`, `BAT1`, ... (some vendors use `battery` — covered below).
        let candidates = [
            power_root.join(format!("BAT{index}")),
            power_root.join(format!("battery{index}")),
        ];
        if candidates.iter().all(|p| !p.join("status").exists()) {
            // No BAT<n> at this index: keep scanning a little further in
            // case numbering is sparse, then stop.
            if index > 3 {
                break;
            }
            index += 1;
            continue;
        }
        for supply in candidates.iter().filter(|p| p.join("status").exists()) {
            if let Ok(status) = fs::read_to_string(supply.join("status")) {
                if status.trim() == "Discharging" {
                    return PowerState::Discharging;
                }
            }
        }
        index += 1;
    }
    PowerState::Ac
}

/// Live host power source.
pub fn power_state() -> PowerState {
    read_power_state(Path::new("/sys/class/power_supply"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn thermal_fixture(zones: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new("thermal").unwrap();
        for (i, (kind, temp)) in zones.iter().enumerate() {
            let zone = dir.path().join(format!("thermal_zone{i}"));
            fs::create_dir_all(&zone).unwrap();
            fs::write(zone.join("type"), kind).unwrap();
            fs::write(zone.join("temp"), temp).unwrap();
        }
        dir
    }

    #[test]
    fn package_temp_prefers_package_zones() {
        let dir = thermal_fixture(&[("acpitz", "90000"), ("x86_pkg_temp", "81000")]);
        assert_eq!(read_package_temp_c(dir.path()), Some(81.0));
    }

    #[test]
    fn package_temp_falls_back_to_hottest_zone() {
        let dir = thermal_fixture(&[("acpitz", "45000"), ("iwlwifi", "52000")]);
        assert_eq!(read_package_temp_c(dir.path()), Some(52.0));
    }

    #[test]
    fn package_temp_skips_garbage_and_missing() {
        let dir = thermal_fixture(&[("x86_pkg_temp", "not-a-number")]);
        assert_eq!(read_package_temp_c(dir.path()), None);
        let empty = TempDir::new("thermal-empty").unwrap();
        assert_eq!(read_package_temp_c(empty.path()), None);
    }

    fn power_fixture(statuses: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new("power").unwrap();
        for (name, status) in statuses {
            let supply = dir.path().join(name);
            fs::create_dir_all(&supply).unwrap();
            fs::write(supply.join("status"), status).unwrap();
        }
        dir
    }

    #[test]
    fn discharging_battery_halts_intake() {
        let dir = power_fixture(&[("BAT0", "Discharging\n")]);
        assert_eq!(read_power_state(dir.path()), PowerState::Discharging);
        // Second battery pack discharging also counts.
        let dir = power_fixture(&[("BAT0", "Full\n"), ("BAT1", "Discharging\n")]);
        assert_eq!(read_power_state(dir.path()), PowerState::Discharging);
    }

    #[test]
    fn charging_or_absent_battery_means_ac() {
        let dir = power_fixture(&[("BAT0", "Charging\n")]);
        assert_eq!(read_power_state(dir.path()), PowerState::Ac);
        let dir = power_fixture(&[("BAT0", "Full\n")]);
        assert_eq!(read_power_state(dir.path()), PowerState::Ac);
        let empty = TempDir::new("power-empty").unwrap();
        assert_eq!(read_power_state(empty.path()), PowerState::Ac);
    }
}
