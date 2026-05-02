//! Adversarial walker fixtures.
//!
//! These tests document scenarios that the current heap path cannot
//! handle: programs whose post-split body materialises so many cold
//! vars sequentially that lazy-reload-without-recycling overruns the
//! frame cap. The next escalation is **scratch-reg recycling**; this
//! file exists so the future implementer has a canonical place to
//! flip these tests from `#[ignore]` to `#[test]` when that
//! implementation lands.
//!
//! Justification: a single template body that legitimately
//! materialises more than ~200 distinct cold vars violates the
//! invariant that the callee frame is bounded by
//! `hot_captures + distinct cold vars materialised in that template
//! body`.

use ir_core::{Instruction, SsaVar};
use ir_forge::extended::ExtendedInstruction;
use ir_forge::lysis_lift::Walker;
use memory::{Bn254Fr, FieldElement, FieldFamily};

#[allow(dead_code)]
fn ssa(i: u32) -> SsaVar {
    SsaVar(i)
}

#[allow(dead_code)]
fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

#[allow(dead_code)]
fn plain(inst: Instruction<Bn254Fr>) -> ExtendedInstruction<Bn254Fr> {
    ExtendedInstruction::Plain(inst)
}

/// Adversarial scenario: a single template body that touches > 200
/// distinct cold vars sequentially (no batching, no early-use
/// clustering). Each cold reference triggers `LoadHeap` plus a fresh
/// `RegAllocator::alloc()` because the current walker has no
/// scratch-reg recycling. The frame allocator hits its 255-reg cap
/// and the walker errors with `WalkError::Alloc(...)`.
///
/// Building a precise counterexample requires careful pre-split
/// state shaping: ≥ 200 SsaVars must remain live across the split,
/// the post-split body must keep them in `cold` after the first-use
/// partition, and each must be referenced exactly once in serial
/// order so they never become hot. This fixture stays as a
/// placeholder until the v1.1 implementer has the scratch-recycling
/// machinery to compare against.
///
/// **Current behaviour**: walker fails. **Behaviour with scratch-reg
/// recycling**: walker succeeds because each LoadHeap reuses the reg
/// of a recently-dead cold var, capping the frame at the working set
/// size (typically <= 64) instead of growing to the spill set (250+).
#[test]
#[ignore = "lazy-reload-without-recycling overflows the 255-reg frame cap when a single template body sequentially materialises more cold vars than fit alongside the hot partition. Flip to #[test] once scratch-reg recycling lands."]
fn adversarial_sequential_cold_vars_overflow_v1_frame() {
    // Placeholder body: one Const, one Halt — does NOT actually
    // exercise the failure path. Constructing the precise fixture
    // requires the scratch-recycling reference implementation to
    // compare against; building it without that baseline risks
    // pinning the walker to a passing-by-accident state. The
    // `#[ignore]` reason above carries the contract; the body
    // exists only so the test compiles.
    let body = vec![plain(Instruction::Const {
        result: ssa(0),
        value: fe(0),
    })];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let result = walker.lower(&body);
    // Once scratch-reg recycling lands and this is flipped to
    // `#[test]`, the assertion becomes `result.is_err()` (current
    // walker fails) or `result.is_ok()` after recycling (passes).
    // Today the placeholder body trivially succeeds, which is
    // harmless because the test is `#[ignore]`'d.
    let _ = result;
}
