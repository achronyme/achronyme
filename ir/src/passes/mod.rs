pub mod bool_prop;
pub mod const_fold;
pub mod dce;
pub mod taint;

use crate::types::IrProgram;

/// Run all optimization passes on the IR program.
///
/// Applies constant folding and dead code elimination.
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
/// optimize(&mut prog);
/// assert!(prog.instructions.len() <= before);
/// ```
pub fn optimize(program: &mut IrProgram) {
    const_fold::constant_fold(program);
    dce::dead_code_elimination(program);
}

/// Run analysis passes and return warnings.
pub fn analyze(program: &IrProgram) -> Vec<taint::TaintWarning> {
    let (_, warnings) = taint::taint_analysis(program);
    warnings
}
