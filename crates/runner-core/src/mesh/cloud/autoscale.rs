//! 5-minute idle scale-to-zero supervisor.
//!
//! Neither DigitalOcean nor Render natively self-terminates a paid
//! instance after 5 idle minutes, so the supervisor tracks idleness and
//! calls the provider delete API itself.

use std::time::{Duration, Instant};

/// Idle duration before self-termination (credit preservation).
pub const IDLE_TERMINATE_SECS: u64 = 300;

/// Tracks node idleness against the terminate threshold.
#[derive(Debug, Clone)]
pub struct IdleTracker {
    last_active: Instant,
    jobs_active: u32,
}

impl IdleTracker {
    pub fn new(now: Instant) -> Self {
        Self {
            last_active: now,
            jobs_active: 0,
        }
    }

    pub fn mark_active(&mut self, now: Instant) {
        self.last_active = now;
    }

    pub fn set_jobs_active(&mut self, jobs: u32, now: Instant) {
        self.jobs_active = jobs;
        if jobs > 0 {
            self.last_active = now;
        }
    }

    pub fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_active)
    }

    /// Terminate only when idle for 5 consecutive minutes with zero jobs.
    pub fn should_terminate(&self, now: Instant) -> bool {
        self.jobs_active == 0 && self.idle_for(now) >= Duration::from_secs(IDLE_TERMINATE_SECS)
    }
}

/// Watchdog decision for one poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScaleAction {
    /// Keep running (queue non-empty or grace period unelapsed).
    Keep,
    /// Idle 5 minutes with an empty queue: terminate to preserve credits.
    Terminate { instance_id: String },
}

/// Provider teardown behind the watchdog (mockable for tests).
pub trait Terminator {
    fn terminate(&mut self, instance_id: &str) -> Result<(), String>;
}

/// 5-minute idle watchdog over one cloud instance.
pub struct AutoscaleController<T: Terminator> {
    tracker: IdleTracker,
    instance_id: String,
    terminator: T,
}

impl<T: Terminator> AutoscaleController<T> {
    pub fn new(instance_id: impl Into<String>, now: Instant, terminator: T) -> Self {
        Self {
            tracker: IdleTracker::new(now),
            instance_id: instance_id.into(),
            terminator,
        }
    }

    /// Reset the idle clock (webhook wakeup: activity is imminent even
    /// though the queue has not been re-polled yet).
    pub fn mark_active(&mut self, now: Instant) {
        self.tracker.mark_active(now);
    }

    /// Poll once: any queued depth resets the idle clock; an empty queue
    /// for 5 consecutive minutes triggers provider termination.
    pub fn poll(&mut self, now: Instant, queue_depth: u32) -> Result<ScaleAction, String> {
        if queue_depth > 0 {
            self.tracker.set_jobs_active(1, now);
            return Ok(ScaleAction::Keep);
        }
        self.tracker.set_jobs_active(0, now);
        if self.tracker.should_terminate(now) {
            self.terminator.terminate(&self.instance_id)?;
            return Ok(ScaleAction::Terminate {
                instance_id: self.instance_id.clone(),
            });
        }
        Ok(ScaleAction::Keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTerminator {
        terminated: Vec<String>,
    }

    impl Terminator for MockTerminator {
        fn terminate(&mut self, instance_id: &str) -> Result<(), String> {
            self.terminated.push(instance_id.to_string());
            Ok(())
        }
    }

    #[test]
    fn watchdog_terminates_after_five_idle_minutes() {
        let start = Instant::now();
        let mut controller =
            AutoscaleController::new("i-1", start, MockTerminator { terminated: vec![] });
        assert_eq!(
            controller
                .poll(start + Duration::from_secs(299), 0)
                .unwrap(),
            ScaleAction::Keep
        );
        assert_eq!(
            controller
                .poll(start + Duration::from_secs(300), 0)
                .unwrap(),
            ScaleAction::Terminate {
                instance_id: "i-1".to_string()
            }
        );
        assert_eq!(controller.terminator.terminated, vec!["i-1".to_string()]);
    }

    #[test]
    fn queued_work_resets_watchdog() {
        let start = Instant::now();
        let mut controller =
            AutoscaleController::new("i-1", start, MockTerminator { terminated: vec![] });
        assert_eq!(
            controller
                .poll(start + Duration::from_secs(299), 3)
                .unwrap(),
            ScaleAction::Keep
        );
        assert_eq!(
            controller
                .poll(start + Duration::from_secs(598), 0)
                .unwrap(),
            ScaleAction::Keep
        );
    }

    #[test]
    fn terminates_after_five_idle_minutes() {
        let start = Instant::now();
        let tracker = IdleTracker::new(start);
        assert!(!tracker.should_terminate(start + Duration::from_secs(299)));
        assert!(tracker.should_terminate(start + Duration::from_secs(300)));
    }

    #[test]
    fn active_jobs_block_termination() {
        let start = Instant::now();
        let mut tracker = IdleTracker::new(start);
        tracker.set_jobs_active(1, start + Duration::from_secs(1000));
        assert!(!tracker.should_terminate(start + Duration::from_secs(10_000)));
    }

    #[test]
    fn activity_resets_idle_clock() {
        let start = Instant::now();
        let mut tracker = IdleTracker::new(start);
        tracker.mark_active(start + Duration::from_secs(299));
        assert!(!tracker.should_terminate(start + Duration::from_secs(300)));
        assert!(tracker.should_terminate(start + Duration::from_secs(599)));
    }
}
