//! cgroup weight transitions (100 / 25 / 1 ladder, never freeze).

use runner::governor::cgroup::{weight_for_cpu_psi, CgroupSlice};
use std::fs;

#[test]
fn weight_ladder() {
    assert_eq!(weight_for_cpu_psi(0.0), 100);
    assert_eq!(weight_for_cpu_psi(20.0), 25);
    assert_eq!(weight_for_cpu_psi(40.01), 1);
}

#[test]
fn pressure_drives_weight_file() {
    let dir = runner::test_support::TempDir::new("cgroup-it").unwrap();
    let slice = CgroupSlice::new(dir.path().join("runner.slice"));
    slice.ensure().unwrap();
    fs::write(slice.path().join("cpu.weight"), "100").unwrap();

    assert_eq!(slice.apply_pressure(45.0).unwrap(), 1);
    assert_eq!(slice.weight().unwrap(), 1);
    assert_eq!(slice.apply_pressure(30.0).unwrap(), 25);
    assert_eq!(slice.apply_pressure(5.0).unwrap(), 100);
}
