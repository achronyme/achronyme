pub mod const_fold;
pub mod dce;
pub mod taint;

use crate::types::IrProgram;

/// Run all optimization passes on the IR program.
pub fn optimize(program: &mut IrProgram) {
    const_fold::constant_fold(program);
    dce::dead_code_elimination(program);
}

/// Run analysis passes and return warnings.
pub fn analyze(program: &IrProgram) -> Vec<taint::TaintWarning> {
    let (_, warnings) = taint::taint_analysis(program);
    warnings
}
