use ir::types::Instruction as IrInstruction;
use memory::FieldBackend;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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

const R1CS_KIND_PROFILE_LEN: usize = 25;

#[derive(Clone, Copy, Default)]
pub struct R1csKindProfileEntry {
    pub instructions: u64,
    pub constraints: u64,
}

pub struct R1csKindProfileSnapshot {
    pub labels: [&'static str; R1CS_KIND_PROFILE_LEN],
    pub entries: [R1csKindProfileEntry; R1CS_KIND_PROFILE_LEN],
}

static R1CS_KIND_PROFILE: OnceLock<Mutex<[R1csKindProfileEntry; R1CS_KIND_PROFILE_LEN]>> =
    OnceLock::new();
static R1CS_KIND_PROFILE_ENABLED: OnceLock<bool> = OnceLock::new();

pub fn r1cs_kind_profile_enabled() -> bool {
    *R1CS_KIND_PROFILE_ENABLED.get_or_init(|| {
        std::env::var("ACH_R1CS_KIND_PROFILE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

pub fn reset_r1cs_kind_profile() {
    let mut entries = r1cs_kind_profile()
        .lock()
        .expect("R1CS kind profile mutex poisoned");
    *entries = [R1csKindProfileEntry::default(); R1CS_KIND_PROFILE_LEN];
}

pub fn snapshot_r1cs_kind_profile() -> R1csKindProfileSnapshot {
    let entries = *r1cs_kind_profile()
        .lock()
        .expect("R1CS kind profile mutex poisoned");
    R1csKindProfileSnapshot {
        labels: R1CS_KIND_PROFILE_LABELS,
        entries,
    }
}

pub fn record_r1cs_kind_profile<F: FieldBackend>(inst: &IrInstruction<F>, constraints: usize) {
    if !r1cs_kind_profile_enabled() {
        return;
    }
    let mut entries = r1cs_kind_profile()
        .lock()
        .expect("R1CS kind profile mutex poisoned");
    let entry = &mut entries[r1cs_kind_profile_index(inst)];
    entry.instructions += 1;
    entry.constraints += constraints as u64;
}

fn r1cs_kind_profile() -> &'static Mutex<[R1csKindProfileEntry; R1CS_KIND_PROFILE_LEN]> {
    R1CS_KIND_PROFILE
        .get_or_init(|| Mutex::new([R1csKindProfileEntry::default(); R1CS_KIND_PROFILE_LEN]))
}

fn r1cs_kind_profile_index<F: FieldBackend>(inst: &IrInstruction<F>) -> usize {
    match inst {
        IrInstruction::Const { .. } => 0,
        IrInstruction::Input { .. } => 1,
        IrInstruction::Add { .. } => 2,
        IrInstruction::Sub { .. } => 3,
        IrInstruction::Mul { .. } => 4,
        IrInstruction::Div { .. } => 5,
        IrInstruction::Neg { .. } => 6,
        IrInstruction::Mux { .. } => 7,
        IrInstruction::PoseidonHash { .. } => 8,
        IrInstruction::Not { .. } => 9,
        IrInstruction::And { .. } => 10,
        IrInstruction::Or { .. } => 11,
        IrInstruction::Decompose { .. } => 12,
        IrInstruction::IsEq { .. } => 13,
        IrInstruction::IsNeq { .. } => 14,
        IrInstruction::IsLt { .. } => 15,
        IrInstruction::IsLe { .. } => 16,
        IrInstruction::IsLtBounded { .. } => 17,
        IrInstruction::IsLeBounded { .. } => 18,
        IrInstruction::IntDiv { .. } => 19,
        IrInstruction::IntMod { .. } => 20,
        IrInstruction::AssertEq { .. } => 21,
        IrInstruction::Assert { .. } => 22,
        IrInstruction::RangeCheck { .. } => 23,
        IrInstruction::WitnessCall(_) => 24,
    }
}

const R1CS_KIND_PROFILE_LABELS: [&str; R1CS_KIND_PROFILE_LEN] = [
    "Const",
    "Input",
    "Add",
    "Sub",
    "Mul",
    "Div",
    "Neg",
    "Mux",
    "PoseidonHash",
    "Not",
    "And",
    "Or",
    "Decompose",
    "IsEq",
    "IsNeq",
    "IsLt",
    "IsLe",
    "IsLtBounded",
    "IsLeBounded",
    "IntDiv",
    "IntMod",
    "AssertEq",
    "Assert",
    "RangeCheck",
    "WitnessCall",
];
