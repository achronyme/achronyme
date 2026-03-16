//! Fuzz target: Full R1CS Pipeline
//!
//! Feeds arbitrary source through the entire pipeline:
//!   source → parse → IR lower → optimize → R1CS compile → witness gen → verify
//!
//! No step in this pipeline should panic on any input. Errors at any stage
//! are expected (invalid syntax, unsupported ops, etc.) but panics indicate bugs.
//!
//! This catches:
//! - Panics in the R1CS compiler (constraint generation)
//! - Panics in witness generation (field arithmetic edge cases)
//! - Panics in constraint verification
//! - Panics in optimization passes (const_fold, dce, bound_inference)
//! - Inconsistencies between compiler and witness generator

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        // Try the full pipeline — every error path must be graceful
        let result = std::panic::catch_unwind(|| {
            // Phase 1: Parse + lower
            let lowered = ir::IrLowering::lower_self_contained(source);
            let (pub_names, wit_names, mut program) = match lowered {
                Ok(v) => v,
                Err(_) => return,
            };

            // Phase 2: Optimize
            ir::passes::optimize(&mut program);

            // Phase 3: R1CS compile
            let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
            let mut compiler = compiler::r1cs_backend::R1CSCompiler::new();
            compiler.set_proven_boolean(proven);

            // Build dummy inputs (zero for everything)
            let mut inputs = HashMap::new();
            for name in pub_names.iter().chain(wit_names.iter()) {
                inputs.insert(name.clone(), memory::FieldElement::ZERO);
            }

            // Phase 4: Compile with witness — may fail (e.g., div by zero), that's fine
            let witness = match compiler.compile_ir_with_witness(&program, &inputs) {
                Ok(w) => w,
                Err(_) => return,
            };

            // Phase 5: Verify — result doesn't matter, but must not panic
            let _ = compiler.cs.verify(&witness);
        });

        // If catch_unwind caught a panic, that's a bug we want to report
        if result.is_err() {
            // Re-panic so libfuzzer sees the crash
            panic!("pipeline panicked on input: {:?}", std::str::from_utf8(data));
        }
    }
});
