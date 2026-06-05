use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WitnessProfileSnapshot {
    pub hint_div: u64,
    pub hint_div_zero: u64,
    pub hint_div_invertible: u64,
}

static HINT_DIV: AtomicU64 = AtomicU64::new(0);
static HINT_DIV_ZERO: AtomicU64 = AtomicU64::new(0);
static HINT_DIV_INVERTIBLE: AtomicU64 = AtomicU64::new(0);
static ENABLED: OnceLock<bool> = OnceLock::new();

pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var_os("ACH_WITNESS_PROFILE").is_some())
}

pub fn reset() {
    HINT_DIV.store(0, Ordering::Relaxed);
    HINT_DIV_ZERO.store(0, Ordering::Relaxed);
    HINT_DIV_INVERTIBLE.store(0, Ordering::Relaxed);
}

pub fn snapshot() -> WitnessProfileSnapshot {
    WitnessProfileSnapshot {
        hint_div: HINT_DIV.load(Ordering::Relaxed),
        hint_div_zero: HINT_DIV_ZERO.load(Ordering::Relaxed),
        hint_div_invertible: HINT_DIV_INVERTIBLE.load(Ordering::Relaxed),
    }
}

#[inline]
pub(crate) fn record_hint_div(denominator_is_zero: bool) {
    if !enabled() {
        return;
    }
    HINT_DIV.fetch_add(1, Ordering::Relaxed);
    if denominator_is_zero {
        HINT_DIV_ZERO.fetch_add(1, Ordering::Relaxed);
    } else {
        HINT_DIV_INVERTIBLE.fetch_add(1, Ordering::Relaxed);
    }
}
