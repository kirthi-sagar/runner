//! PSI threshold parsing (spec section 3.3 governor table).

use runner::governor::psi::{
    cpu_level, io_level, mem_level, parse_psi_file, read_snapshot_from, PressureLevel,
};

#[test]
fn parses_proc_pressure_shape() {
    let file = parse_psi_file(
        "some avg10=20.00 avg60=10.00 avg300=5.00 total=100\n\
         full avg10=5.00 avg60=2.00 avg300=1.00 total=50\n",
    )
    .unwrap();
    assert_eq!(file.some.avg10, 20.0);
    assert_eq!(file.full.total, 50);
    assert!(parse_psi_file("garbage").is_err());
}

#[test]
fn governor_table_boundaries() {
    assert_eq!(cpu_level(19.99), PressureLevel::Normal);
    assert_eq!(cpu_level(20.0), PressureLevel::Warning);
    assert_eq!(cpu_level(40.01), PressureLevel::Critical);
    assert_eq!(mem_level(15.01), PressureLevel::Critical);
    assert_eq!(io_level(10.01), PressureLevel::Critical);
}

#[test]
fn snapshot_reads_from_directory() {
    let dir = runner::test_support::TempDir::new("psi").unwrap();
    std::fs::write(
        dir.path().join("cpu"),
        "some avg10=30.00 avg60=0 avg300=0 total=1\nfull avg10=0.00 avg60=0 avg300=0 total=0\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("memory"),
        "some avg10=1.00 avg60=0 avg300=0 total=1\nfull avg10=0.00 avg60=0 avg300=0 total=0\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("io"),
        "some avg10=0.00 avg60=0 avg300=0 total=0\nfull avg10=1.00 avg60=0 avg300=0 total=1\n",
    )
    .unwrap();
    let snapshot = read_snapshot_from(dir.path()).unwrap();
    assert_eq!(snapshot.cpu_some_avg10(), 30.0);
    assert_eq!(snapshot.cpu_pressure(), PressureLevel::Warning);
}
