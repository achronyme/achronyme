use crate::segmented_vec::SegmentedVec;
use constraints::poseidon::PoseidonParams;
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use constraints::r1cs_optimize::{R1CSOptimizeResult, SubstitutionMap};
use constraints::PoseidonParamsProvider;
use memory::field::PrimeId;
use memory::{Bn254Fr, FieldBackend, FieldElement};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar, Visibility as IrVisibility};

use crate::error::R1CSError;
use crate::r1cs_gadgets::power_of_two_generic;
use crate::witness::WitnessOp;

mod api;
mod counters;
mod dispatch;
mod int_divmod;
mod lc_map;

pub use counters::{
    reset_boolcheck_counters, snapshot_boolcheck_counters, BC_AND_LHS, BC_AND_RHS, BC_ASSERT,
    BC_DECOMPOSE, BC_DECOMPOSE_1BIT, BC_ENFORCE_N_RANGE, BC_IS_LT_VIA_BITS, BC_MUX_COND, BC_NOT,
    BC_OR_LHS, BC_OR_RHS, BC_RANGE_CHECK,
};
use lc_map::{LcMap, UsedSsaSet};
pub use lc_map::{LcMapShapeCounts, R1CSRetainedStats};

#[cfg(test)]
mod tests;

pub struct ConstraintOrigin {
    /// Index of the IR instruction in `IrProgram::instructions`.
    pub ir_index: usize,
    /// The SSA variable defined by the instruction.
    pub result_var: SsaVar,
}

/// Maximum LC term count before auto-materialization.
///
/// Without this, chains of Add/Sub (e.g. MDS in Poseidon partial rounds)
/// cause exponential LC growth: f(n) = 2·f(n-1)+1 ≈ 2^n terms.
/// Materializing keeps each LC bounded and prevents OOM on large circuits.
const LC_AUTO_MATERIALIZE_THRESHOLD: usize = 8;

pub struct R1CSCompiler<F: FieldBackend = Bn254Fr> {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem<F>,
    /// Declared variables: maps `public`/`witness` names → allocated R1CS wire.
    /// Only contains explicitly declared circuit inputs (not `let` bindings).
    pub bindings: HashMap<String, Variable>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
    /// Cached Poseidon parameters. Initialized on first `poseidon()` call.
    pub(crate) poseidon_params: Option<PoseidonParams<F>>,
    /// Witness generation trace: records each intermediate variable allocation.
    ///
    /// Stored in a [`SegmentedVec`] rather than a flat `Vec` so the
    /// container never issues a single allocation larger than
    /// `SegmentedVec::DEFAULT_SEGMENT_MAX * size_of::<WitnessOp<F>>()`
    /// (~64 MB at the current op layout). Boss-fight-class circuits
    /// emitting millions of witness ops would otherwise trigger a 1+ GiB
    /// `Vec::push` doubling request mid-stream that constrained sandboxes
    /// reject.
    pub witness_ops: SegmentedVec<WitnessOp<F>>,
    /// Prime field for this compilation.
    /// Determines the default bit width for range checks and comparisons.
    pub prime_id: PrimeId,
    /// SSA variables proven to be boolean by bool_prop analysis.
    /// Boolean enforcement constraints are skipped for these.
    proven_boolean: std::collections::HashSet<ir::types::SsaVar>,
    /// SSA variables for which boolean enforcement (v * (1-v) = 0) has already
    /// been emitted. Avoids duplicate constraints when the same condition
    /// is used in multiple Mux/And/Or instructions.
    bool_enforced: std::collections::HashSet<ir::types::SsaVar>,
    /// Maps each R1CS constraint index to the IR instruction that generated it.
    /// Built during `compile_ir`, parallel to `cs.constraints()`. Skipped when
    /// `track_constraint_origins` is false (see `R1CSCompiler::new_lean`).
    pub constraint_origins: Vec<ConstraintOrigin>,
    /// Toggle for `constraint_origins` population. Defaults to `true` so the
    /// inspector / CLI provenance readers keep working. Setting it to `false`
    /// (via `new_lean`) skips the per-constraint origin push on the hot
    /// emission path, freeing ~16 B per emitted constraint plus Vec capacity
    /// tail — material on circuits emitting tens of millions of constraints.
    track_constraint_origins: bool,
    /// Toggle for retaining input-name metadata while compiling IR inputs.
    ///
    /// Normal compilers keep the `bindings`, `public_inputs`, and `witnesses`
    /// name tables for witness lookup, inspectors, and CLI consumers. The
    /// lean boss-fight path only needs wire allocation and constraints; keeping
    /// one `String` plus one hash entry for every synthetic lysis witness slot
    /// is pure retention overhead there.
    track_input_metadata: bool,
    /// Lean-only forward collapse for `AssertEq` assignments whose lhs is a
    /// fresh private wire. The default compiler keeps the historical one
    /// constraint per assert surface; the boss-fight lean path uses this to
    /// avoid retaining eliminate-before-use linear constraints.
    forward_assert_eq_collapse: bool,
    /// Emit multi-term LC products directly instead of first materializing each
    /// operand into a fresh wire.
    ///
    /// The default path materializes `LC_a` and `LC_b`, emits linear
    /// constraints for those fresh wires, then relies on O1 to substitute them
    /// away. This mode emits the post-substitution quadratic shape directly:
    /// `LC_a * LC_b = out`.
    pub(crate) direct_linear_mul: bool,
    /// Whether to retain witness-generation operations.
    ///
    /// Compile-only benchmarks and exporters that only need the constraint
    /// shape can disable this log to avoid retaining one witness operation per
    /// intermediate wire. Normal proving paths leave it enabled.
    pub(crate) record_witness_ops: bool,
    /// Variable substitution map from R1CS linear constraint elimination.
    /// Set by `optimize_r1cs()`. Used by witness generation to compute
    /// values for substituted-away wires.
    pub substitution_map: Option<SubstitutionMap<F>>,
    /// Lookup cache: SSA variable → its `LinearCombination`. Populated as the
    /// compiler walks the IR instruction stream. Reset at the start of
    /// every `compile_ir` call.
    lc_map: LcMap<F>,
    /// Optional upper bound for term count retained in `lc_map`.
    ///
    /// When set, cached non-constant LCs longer than this limit are
    /// materialized into a fresh wire before insertion, so future lookups see
    /// a one-variable LC instead of keeping the full term list alive. The
    /// default compiler leaves this unset because materialization emits extra
    /// linear constraints; compile-only sizing probes can enable it to trade
    /// constraint count for bounded resident memory.
    lc_cache_term_limit: Option<usize>,
    /// Dense bitset over `SsaVar.0`: set once an SSA value has been consumed
    /// by any later instruction. Used by the forward `AssertEq` collapse to
    /// substitute fresh private assignment targets without keeping a global
    /// substitution map.
    used_ssa: UsedSsaSet,
    /// Proven bit-width bounds from `RangeCheck`, used by `IsLt`/`IsLe`.
    range_bounds: HashMap<SsaVar, u32>,
    /// Cached divmod gadgets: `(lhs, rhs, max_bits) → (q_lc, r_lc)`.
    /// When `IntDiv` and `IntMod` use the same operands, the second reuses
    /// the cached result instead of emitting duplicate constraints.
    #[allow(clippy::type_complexity)]
    divmod_cache: HashMap<(SsaVar, SsaVar, u32), (LinearCombination<F>, LinearCombination<F>)>,
    /// Content-hash intern table for Artik bytecode payloads.
    /// Holds `Arc<[u8]>` so identical payloads emitted at multiple
    /// `WitnessCall` sites share one heap allocation. A flat `Vec`
    /// (not `HashMap`) is the right shape here: a single compilation
    /// typically yields a handful of unique templates, and linear scan
    /// over a cache-resident `Vec<(u64, Arc<[u8]>)>` beats `HashMap`
    /// probing for that cardinality — no empty-slot overhead, fully
    /// deterministic insertion order. The secondary slice equality
    /// check on a `u64` hash hit is mandatory: a 64-bit collision
    /// (astronomically unlikely but not impossible) would otherwise
    /// alias distinct programs to the same `Arc` and corrupt witness
    /// execution.
    artik_program_intern: Vec<(u64, Arc<[u8]>)>,
}
