//! Backwards wall-clock steps (spec 8.4.3-8.4.4, D21).
//!
//! Freshness is judged on the wall clock, but a replay store forgets pairs on
//! its own clock (the monotonic clock for [`crate::MemoryStore`], Redis' clock
//! for the Redis store). If the wall clock steps back by more than the store's
//! margin, `retention - (max_age + allowed_skew)`, a forgotten nonce could look
//! fresh again. [`StepGuard`] compares `wall - monotonic` with its previous
//! value on every request that reaches the replay check; a drop larger than the
//! margin opens a fail-closed window of `retention`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A clock reading in nanoseconds.
pub(crate) type ClockNs = Box<dyn Fn() -> u64 + Send + Sync>;

#[derive(Default)]
struct State {
    offset: i128,
    until: Option<u64>,
    last_step: u64,
}

pub(crate) struct StepGuard {
    margin: u64,
    hold: u64,
    wall_ns: ClockNs,
    mono_ns: ClockNs,
    state: Mutex<State>,
}

impl StepGuard {
    pub(crate) fn new(
        margin: Duration,
        hold: Duration,
        wall_ns: ClockNs,
        mono_ns: ClockNs,
    ) -> Self {
        let as_ns = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        let offset = i128::from(wall_ns()) - i128::from(mono_ns());
        Self {
            margin: as_ns(margin),
            hold: as_ns(hold),
            wall_ns,
            mono_ns,
            state: Mutex::new(State { offset, ..State::default() }),
        }
    }

    /// Measure now; whether the fail-closed window is open.
    pub(crate) fn check(&self) -> bool {
        let mono = (self.mono_ns)();
        let offset = i128::from((self.wall_ns)()) - i128::from(mono);
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let step = state.offset - offset;
        state.offset = offset;
        if step > i128::from(self.margin) {
            state.until = Some(mono.saturating_add(self.hold));
            state.last_step = u64::try_from(step).unwrap_or(u64::MAX);
        }
        state.until.is_some_and(|until| mono < until)
    }

    /// The size of the last step that opened the window (0 before the first).
    pub(crate) fn last_step(&self) -> Duration {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Duration::from_nanos(state.last_step)
    }
}

/// A monotonic clock in nanoseconds since the call.
pub(crate) fn monotonic_ns() -> ClockNs {
    let start = Instant::now();
    Box::new(move || u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;

    #[test]
    fn forward_and_small_steps_only_move_the_baseline() {
        let wall = Arc::new(AtomicI64::new(1_000_000_000_000));
        let w = Arc::clone(&wall);
        let g = StepGuard::new(
            Duration::from_secs(48),
            Duration::from_secs(60),
            Box::new(move || u64::try_from(w.load(Ordering::SeqCst)).unwrap_or(0)),
            Box::new(|| 0),
        );
        for step in [3_600_i64, -48, -1] {
            wall.fetch_add(step * 1_000_000_000, Ordering::SeqCst);
            assert!(!g.check(), "step {step} s opened the window");
        }
        assert_eq!(g.last_step(), Duration::ZERO);
    }
}
