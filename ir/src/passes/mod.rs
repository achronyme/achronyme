pub mod const_fold;
pub mod dce;

use crate::types::IrProgram;

/// Run all optimization passes on the IR program.
pub fn optimize(program: &mut IrProgram) {
    const_fold::constant_fold(program);
    dce::dead_code_elimination(program);
}
