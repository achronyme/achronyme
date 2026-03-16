//! Fuzz target: IR Lowering
//!
//! Feeds arbitrary source code through the full parser → IR lowering pipeline.
//! Neither the parser nor the IR lowerer should panic on any input.
//!
//! This catches:
//! - Panics in AST → SSA IR translation
//! - Unhandled AST node types
//! - Stack overflows from deeply nested circuit expressions
//! - Edge cases in variable resolution and scope handling

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        // Try lowering as self-contained circuit source
        // Errors are expected and fine — panics are not
        let _ = ir::IrLowering::lower_self_contained(source);
    }
});
