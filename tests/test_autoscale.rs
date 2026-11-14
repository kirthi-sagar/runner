//! Scale-to-zero idle detection (5 consecutive minutes).

use runner::mesh::cloud::autoscale::IdleTracker;
use std::time::{Duration, Instant};

#[test]
fn five_minutes_idle_triggers_termination() {
    let start = Instant::now();
    let tracker = IdleTracker::new(start);
    assert!(!tracker.should_terminate(start + Duration::from_secs(299)));
    assert!(tracker.should_terminate(start + Duration::from_secs(300)));
}

#[test]
fn jobs_in_flight_never_terminate() {
    let start = Instant::now();
    let mut tracker = IdleTracker::new(start);
    tracker.set_jobs_active(3, start);
    assert!(!tracker.should_terminate(start + Duration::from_secs(3600)));
}

#[test]
fn watchdog_fires_provider_termination_at_five_minutes() {
    use runner::mesh::cloud::autoscale::{AutoscaleController, ScaleAction, Terminator};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct RecordingTerminator {
        calls: Rc<RefCell<Vec<String>>>,
    }

    impl Terminator for RecordingTerminator {
        fn terminate(&mut self, instance_id: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(instance_id.to_string());
            Ok(())
        }
    }

    let calls = Rc::new(RefCell::new(Vec::new()));
    let start = Instant::now();
    let mut controller = AutoscaleController::new(
        "droplet-1",
        start,
        RecordingTerminator { calls: calls.clone() },
    );
    // Empty queue inside the grace period: keep.
    assert_eq!(
        controller.poll(start + Duration::from_secs(299), 0).unwrap(),
        ScaleAction::Keep
    );
    assert!(calls.borrow().is_empty());
    // Empty queue at 5 minutes: provider termination fires exactly once.
    assert_eq!(
        controller.poll(start + Duration::from_secs(300), 0).unwrap(),
        ScaleAction::Terminate { instance_id: "droplet-1".to_string() }
    );
    assert_eq!(*calls.borrow(), vec!["droplet-1".to_string()]);
}
