pub mod bool_prop;
pub mod const_fold;
pub mod dce;
pub mod taint;

use crate::types::{Instruction, IrProgram};

/// Statistics returned by the optimization pipeline.
pub struct OptimizeStats {
    /// Total instructions before optimization.
    pub total_before: usize,
    /// Instructions converted to constants by constant folding.
    pub const_fold_converted: usize,
    /// Instructions eliminated by dead code elimination.
    pub dce_eliminated: usize,
    /// Total instructions after optimization.
    pub total_after: usize,
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
/// let mut prog = IrLowering::lower_circuit(
///     "let a = 2 + 3\nassert_eq(x, a)",
///     &["x"],
///     &[],
/// ).unwrap();
/// let before = prog.instructions.len();
/// let stats = optimize(&mut prog);
/// assert!(prog.instructions.len() <= before);
/// assert_eq!(stats.total_after, prog.instructions.len());
/// ```
pub fn optimize(program: &mut IrProgram) -> OptimizeStats {
    let total_before = program.instructions.len();

    // Count Const instructions before folding
    let consts_before = program
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Const { .. }))
        .count();

    const_fold::constant_fold(program);

    // Count Const instructions after folding — difference = folded
    let consts_after = program
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Const { .. }))
        .count();
    let const_fold_converted = consts_after.saturating_sub(consts_before);

    let before_dce = program.instructions.len();
    dce::dead_code_elimination(program);
    let dce_eliminated = before_dce.saturating_sub(program.instructions.len());

    let total_after = program.instructions.len();

    OptimizeStats {
        total_before,
        const_fold_converted,
        dce_eliminated,
        total_after,
    }
}

/// Run analysis passes and return warnings.
pub fn analyze(program: &IrProgram) -> Vec<taint::TaintWarning> {
    let (_, warnings) = taint::taint_analysis(program);
    warnings
}
