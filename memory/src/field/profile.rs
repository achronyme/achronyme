#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FieldOpSnapshot {
    pub mul: u64,
    pub add: u64,
    pub sub: u64,
    pub neg: u64,
    pub inv: u64,
    pub reduce: u64,
    pub ct_select: u64,
}

impl FieldOpSnapshot {
    pub const fn total(self) -> u64 {
        self.mul + self.add + self.sub + self.neg + self.inv + self.reduce + self.ct_select
    }
}

#[cfg(feature = "field-op-profile")]
mod counters {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::FieldOpSnapshot;

    static MUL: AtomicU64 = AtomicU64::new(0);
    static ADD: AtomicU64 = AtomicU64::new(0);
    static SUB: AtomicU64 = AtomicU64::new(0);
    static NEG: AtomicU64 = AtomicU64::new(0);
    static INV: AtomicU64 = AtomicU64::new(0);
    static REDUCE: AtomicU64 = AtomicU64::new(0);
    static CT_SELECT: AtomicU64 = AtomicU64::new(0);

    #[inline(always)]
    pub fn record_mul() {
        MUL.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_add() {
        ADD.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_sub() {
        SUB.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_neg() {
        NEG.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_inv() {
        INV.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_reduce() {
        REDUCE.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_ct_select() {
        CT_SELECT.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reset() {
        MUL.store(0, Ordering::Relaxed);
        ADD.store(0, Ordering::Relaxed);
        SUB.store(0, Ordering::Relaxed);
        NEG.store(0, Ordering::Relaxed);
        INV.store(0, Ordering::Relaxed);
        REDUCE.store(0, Ordering::Relaxed);
        CT_SELECT.store(0, Ordering::Relaxed);
    }

    pub fn snapshot() -> FieldOpSnapshot {
        FieldOpSnapshot {
            mul: MUL.load(Ordering::Relaxed),
            add: ADD.load(Ordering::Relaxed),
            sub: SUB.load(Ordering::Relaxed),
            neg: NEG.load(Ordering::Relaxed),
            inv: INV.load(Ordering::Relaxed),
            reduce: REDUCE.load(Ordering::Relaxed),
            ct_select: CT_SELECT.load(Ordering::Relaxed),
        }
    }
}

#[cfg(feature = "field-op-profile")]
pub use counters::*;

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_mul() {}

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_add() {}

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_sub() {}

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_neg() {}

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_inv() {}

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_reduce() {}

#[cfg(not(feature = "field-op-profile"))]
#[inline(always)]
pub(crate) fn record_ct_select() {}

#[cfg(not(feature = "field-op-profile"))]
pub fn reset() {}

#[cfg(not(feature = "field-op-profile"))]
pub fn snapshot() -> FieldOpSnapshot {
    FieldOpSnapshot::default()
}

pub const fn enabled() -> bool {
    cfg!(feature = "field-op-profile")
}
