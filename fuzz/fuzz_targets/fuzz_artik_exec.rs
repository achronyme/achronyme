//! Fuzz target: Artik executor end-to-end.
//!
//! Feeds arbitrary bytes through `decode` and — when the validator
//! accepts them — runs the resulting [`artik::Program`] under a
//! tight budget. The executor must NEVER panic: traps return
//! `Err(ArtikError)`; non-terminating loops are cut off by the budget
//! limit; invalid cell accesses surface as `WrongCellKind` or
//! `UndefinedRegister`.
//!
//! This is the "did we get everything right" catch-all: every branch
//! the validator accepts must execute cleanly in finite time against
//! an empty signal/witness context.

#![no_main]

use libfuzzer_sys::fuzz_target;
use memory::field::{Bn254Fr, FieldElement};
use artik::bytecode::decode;
use artik::executor::{execute_with_budget, ArtikContext};

const FUZZ_BUDGET: u64 = 10_000;

fuzz_target!(|data: &[u8]| {
    let Ok(prog) = decode(data, None) else {
        return;
    };
    let signals: Vec<FieldElement<Bn254Fr>> = Vec::new();
    let mut slots: Vec<FieldElement<Bn254Fr>> = Vec::new();
    let mut ctx = ArtikContext::<Bn254Fr>::new(&signals, &mut slots);
    let _ = execute_with_budget(&prog, &mut ctx, FUZZ_BUDGET);
});
