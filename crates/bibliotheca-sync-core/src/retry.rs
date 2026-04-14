//! Exponential backoff helper with jitter.

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    base: Duration,
    factor: f64,
    max: Duration,
    jitter: f64,
    current: Duration,
}

impl ExponentialBackoff {
    pub fn new(base: Duration, factor: f64, max: Duration, jitter: f64) -> Self {
        Self {
            base,
            factor,
            max,
            jitter,
            current: base,
        }
    }

    pub fn reset(&mut self) {
        self.current = self.base;
    }

    /// Returns the next delay and advances the internal state.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.current;
        let next =
            Duration::from_secs_f64((d.as_secs_f64() * self.factor).min(self.max.as_secs_f64()));
        self.current = next;
        let j = 1.0 + rand::thread_rng().gen_range(-self.jitter..=self.jitter);
        Duration::from_secs_f64((d.as_secs_f64() * j).max(0.0))
    }
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(15),
            2.0,
            Duration::from_secs(30 * 60),
            0.2,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_then_caps() {
        let mut b =
            ExponentialBackoff::new(Duration::from_secs(1), 2.0, Duration::from_secs(10), 0.0);
        let d1 = b.next_delay();
        let d2 = b.next_delay();
        let d3 = b.next_delay();
        assert!(d2 >= d1);
        assert!(d3 >= d2);
        // After enough steps, we cap.
        for _ in 0..20 {
            let _ = b.next_delay();
        }
        let final_ = b.next_delay();
        assert!(final_ <= Duration::from_secs(10));
    }

    #[test]
    fn reset_works() {
        let mut b = ExponentialBackoff::default();
        let _ = b.next_delay();
        let _ = b.next_delay();
        b.reset();
        let after_reset = b.next_delay();
        // After reset, the first delay is ~base seconds.
        assert!(after_reset < Duration::from_secs(30));
    }
}
