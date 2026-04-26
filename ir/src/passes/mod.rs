pub mod bit_pattern;
pub mod bool_prop;
pub mod bound_inference;
pub mod canonicalize;
pub mod const_fold;
pub mod cse;
pub mod dce;
pub mod taint;
pub mod validate;

pub use canonicalize::canonicalize_ssa;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram};

/// Statistics returned by the optimization pipeline.
pub struct OptimizeStats {
    /// Total instructions before optimization.
    pub total_before: usize,
    /// Instructions converted to constants by constant folding.
    pub const_fold_converted: usize,
    /// Common sub-expressions eliminated by CSE.
    pub cse_eliminated: usize,
    /// Instructions eliminated by dead code elimination.
    pub dce_eliminated: usize,
    /// Tautological `AssertEq(x, x)` eliminated.
    pub tautological_asserts_eliminated: usize,
    /// Total instructions after optimization.
    pub total_after: usize,
    /// Bound inference results (comparisons optimized + those remaining unbounded).
    pub bound_inference: bound_inference::BoundInferenceResult,
    /// Number of bitwidth bounds inferred from Num2Bits-style patterns.
    pub bit_pattern_bounds: usize,
    /// Number of boolean-enforced variables detected via `v*(v-1)=0`.
    pub bit_pattern_booleans: usize,
}

/// Run all optimization passes on the IR program.
///
/// Applies constant folding and dead code elimination.
/// Returns statistics about what was optimized.
///
/// ```
/// use ir::IrLowering;
/// use ir::passes::optimize;
///
/// let mut prog: ir::types::IrProgram = IrLowering::lower_circuit(
///     "let a = 2 + 3\nassert_eq(x, a)",
///     &["x"],
///     &[],
/// ).unwrap();
/// let before = prog.len();
/// let stats = optimize(&mut prog);
/// assert!(prog.len() <= before);
/// assert_eq!(stats.total_after, prog.len());
/// ```
pub fn optimize<F: FieldBackend>(program: &mut IrProgram<F>) -> OptimizeStats {
    let total_before = program.len();

    // Count Const instructions before folding
    let consts_before = program
        .iter()
        .filter(|i| matches!(i, Instruction::Const { .. }))
        .count();

    // Snapshot pre-pass instructions when validation is enabled, so the
    // validator can locate the original defining instruction of any
    // dangling SsaVar in the panic message. No-op (no clone) otherwise.
    let snapshot = |program: &IrProgram<F>| -> Option<Vec<Instruction<F>>> {
        if validate::validation_enabled() {
            Some(program.instructions.clone())
        } else {
            None
        }
    };

    let before = snapshot(program);
    const_fold::constant_fold(program);
    validate::assert_no_dangling_ssa_vars_with_before(program, before.as_deref(), "const_fold");
    let proven_booleans = bool_prop::compute_proven_boolean(program);
    let bp_result = bit_pattern::detect_bit_patterns(program, &proven_booleans);
    let before = snapshot(program);
    let bi_result = bound_inference::bound_inference(program, &bp_result.bounds);
    validate::assert_no_dangling_ssa_vars_with_before(
        program,
        before.as_deref(),
        "bound_inference",
    );

    // Count Const instructions after folding — difference = folded
    let consts_after = program
        .iter()
        .filter(|i| matches!(i, Instruction::Const { .. }))
        .count();
    let const_fold_converted = consts_after.saturating_sub(consts_before);

    let before = snapshot(program);
    let cse_eliminated = cse::common_subexpression_elimination(program);
    validate::assert_no_dangling_ssa_vars_with_before(program, before.as_deref(), "cse");

    // Count tautological AssertEq(x, x) before DCE removes them
    let tautological_before = program
        .iter()
        .filter(|i| matches!(i, Instruction::AssertEq { lhs, rhs, .. } if lhs == rhs))
        .count();

    let before_dce = program.len();
    let before = snapshot(program);
    dce::dead_code_elimination(program);
    validate::assert_no_dangling_ssa_vars_with_before(program, before.as_deref(), "dce");
    let dce_eliminated = before_dce
        .saturating_sub(program.len())
        .saturating_sub(tautological_before);

    let total_after = program.len();

    OptimizeStats {
        total_before,
        const_fold_converted,
        cse_eliminated,
        dce_eliminated,
        tautological_asserts_eliminated: tautological_before,
        total_after,
        bound_inference: bi_result,
        bit_pattern_bounds: bp_result.bounds.len(),
        bit_pattern_booleans: bp_result.booleans_detected,
    }
}

/// Run analysis passes and return warnings.
pub fn analyze<F: FieldBackend>(program: &IrProgram<F>) -> Vec<taint::TaintWarning> {
    let (_, warnings) = taint::taint_analysis(program);
    warnings
}
