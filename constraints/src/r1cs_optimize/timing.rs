use std::time::{Duration, Instant};

pub(super) const O1_PROFILE_BUCKETS: usize = 11;

pub(super) struct O1Timings {
    enabled: bool,
    started: Instant,
    buckets: [Duration; O1_PROFILE_BUCKETS],
}

impl O1Timings {
    pub(super) fn from_env() -> Self {
        let enabled = std::env::var("ACH_O1_PROFILE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            enabled,
            started: Instant::now(),
            buckets: [Duration::ZERO; O1_PROFILE_BUCKETS],
        }
    }

    #[inline]
    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub(super) fn time<T>(&mut self, bucket: usize, f: impl FnOnce() -> T) -> T {
        if !self.enabled {
            return f();
        }
        let t = Instant::now();
        let value = f();
        self.buckets[bucket] += t.elapsed();
        value
    }

    pub(super) fn print(&self, title: &str, labels: &[&str]) {
        if !self.enabled {
            return;
        }
        debug_assert_eq!(labels.len(), O1_PROFILE_BUCKETS);
        let total = self.started.elapsed();
        eprintln!("[{title}] profile total={:.3}s", total.as_secs_f64());
        for (idx, label) in labels.iter().enumerate() {
            let secs = self.buckets[idx].as_secs_f64();
            let pct = if total.is_zero() {
                0.0
            } else {
                secs * 100.0 / total.as_secs_f64()
            };
            eprintln!("[{title}] profile {label:<16} {secs:>9.3}s {pct:>6.2}%");
        }
    }
}
