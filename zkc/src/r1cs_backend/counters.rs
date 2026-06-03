use std::sync::atomic::{AtomicU64, Ordering};

// Per-call-site bool-check emission counters. Each tracks how many
// `b · (1 − b) = 0` constraints a specific code path has emitted
// since the last `reset_boolcheck_counters()` call. Useful when an
// optimisation diff or compiler-comparison probe wants to localise
// where bool-check shape constraints originate without re-running
// the entire pipeline with a debug build. All atomic; safe to
// snapshot or reset at any point.
pub static BC_RANGE_CHECK: AtomicU64 = AtomicU64::new(0);
pub static BC_NOT: AtomicU64 = AtomicU64::new(0);
pub static BC_AND_LHS: AtomicU64 = AtomicU64::new(0);
pub static BC_AND_RHS: AtomicU64 = AtomicU64::new(0);
pub static BC_OR_LHS: AtomicU64 = AtomicU64::new(0);
pub static BC_OR_RHS: AtomicU64 = AtomicU64::new(0);
pub static BC_ASSERT: AtomicU64 = AtomicU64::new(0);
pub static BC_DECOMPOSE: AtomicU64 = AtomicU64::new(0);
pub static BC_MUX_COND: AtomicU64 = AtomicU64::new(0);
pub static BC_ENFORCE_N_RANGE: AtomicU64 = AtomicU64::new(0);
pub static BC_IS_LT_VIA_BITS: AtomicU64 = AtomicU64::new(0);
pub static BC_DECOMPOSE_1BIT: AtomicU64 = AtomicU64::new(0);

pub fn snapshot_boolcheck_counters() -> [(&'static str, u64); 12] {
    [
        ("RangeCheck", BC_RANGE_CHECK.load(Ordering::Relaxed)),
        ("Not", BC_NOT.load(Ordering::Relaxed)),
        ("And.lhs", BC_AND_LHS.load(Ordering::Relaxed)),
        ("And.rhs", BC_AND_RHS.load(Ordering::Relaxed)),
        ("Or.lhs", BC_OR_LHS.load(Ordering::Relaxed)),
        ("Or.rhs", BC_OR_RHS.load(Ordering::Relaxed)),
        ("Assert", BC_ASSERT.load(Ordering::Relaxed)),
        ("Decompose", BC_DECOMPOSE.load(Ordering::Relaxed)),
        ("Mux.cond", BC_MUX_COND.load(Ordering::Relaxed)),
        (
            "enforce_n_range",
            BC_ENFORCE_N_RANGE.load(Ordering::Relaxed),
        ),
        ("is_lt_via_bits", BC_IS_LT_VIA_BITS.load(Ordering::Relaxed)),
        ("Decompose(1bit)", BC_DECOMPOSE_1BIT.load(Ordering::Relaxed)),
    ]
}

pub fn reset_boolcheck_counters() {
    BC_RANGE_CHECK.store(0, Ordering::Relaxed);
    BC_NOT.store(0, Ordering::Relaxed);
    BC_AND_LHS.store(0, Ordering::Relaxed);
    BC_AND_RHS.store(0, Ordering::Relaxed);
    BC_OR_LHS.store(0, Ordering::Relaxed);
    BC_OR_RHS.store(0, Ordering::Relaxed);
    BC_ASSERT.store(0, Ordering::Relaxed);
    BC_DECOMPOSE.store(0, Ordering::Relaxed);
    BC_MUX_COND.store(0, Ordering::Relaxed);
    BC_ENFORCE_N_RANGE.store(0, Ordering::Relaxed);
    BC_IS_LT_VIA_BITS.store(0, Ordering::Relaxed);
    BC_DECOMPOSE_1BIT.store(0, Ordering::Relaxed);
}
