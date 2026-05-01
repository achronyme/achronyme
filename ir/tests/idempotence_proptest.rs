//! Property-based idempotence test for `ir::passes::optimize`.
//!
//! Invariant: `optimize(optimize(p)) == optimize(p)` — running the
//! optimizer pipeline twice produces the same instruction sequence as
//! running it once. This is the *fixed-point property* of the dataflow
//! framework underlying each pass (Cooper & Torczon, "Engineering a
//! Compiler", §10).
//!
//! Reference implementation: Noir's
//! `compiler/noirc_evaluator/src/ssa/opt/brillig_entry_points.rs`
//! ships a single `idempotency()` test in this exact shape — run pass
//! twice on the same SSA, assert byte-equal output.
//!
//! ## Vacuity guard
//!
//! `optimize` returning the empty program is *trivially idempotent*
//! (Pierce, TaPL §8 covers the analogous "stuck state" trap). The
//! input generator always emits at least one `AssertEq` so DCE
//! cannot eliminate every instruction; the post-optimize program is
//! required to be non-empty.
//!
//! ## Discriminator (verified during development)
//!
//! Patching `ir/src/passes/dce.rs::dead_code_elimination` to skip its
//! outer fixpoint loop (single-pass DCE only) breaks the chain
//! `Const → Add → Neg → unused`: a single pass removes the
//! tail-most unused `Neg` but leaves the upstream `Add` and `Const`
//! that fed it. Running optimize twice picks up the newly-orphaned
//! instructions on the second pass — i.e. idempotence fails. This
//! test catches that regression.

use ir::passes::optimize;
use ir::types::{Instruction, IrProgram, SsaVar};
use ir_core::Visibility;
use memory::FieldElement;
use proptest::prelude::*;

/// Operand-producing instruction tags. Each tag generates exactly one
/// fresh result var; the generator threads the var through subsequent
/// instructions to build a valid SSA program.
#[derive(Debug, Clone, Copy)]
enum InstrTag {
    Const(u64),
    Add,
    Sub,
    Mul,
    Neg,
}

/// Asserter tags — these consume two existing vars and produce a
/// result (which DCE may keep, since AssertEq is a side-effect).
#[derive(Debug, Clone, Copy)]
enum AssertTag {
    AssertEq,
}

/// Build a small IR program from a recipe: each `InstrTag` produces a
/// fresh var; `AssertTag` consumes two prior vars. The first two
/// instructions are always `Const` so subsequent operand picks always
/// have something to reference.
fn build_program(
    seed_consts: Vec<u64>,
    body: Vec<(InstrTag, usize, usize)>,
    asserts: Vec<(AssertTag, usize, usize)>,
) -> IrProgram {
    let mut p: IrProgram = IrProgram::new();
    let mut vars: Vec<SsaVar> = Vec::new();

    // Seed: at least 2 Consts so subsequent ops can index into vars.
    for v in seed_consts {
        let r = p.fresh_var();
        p.push(Instruction::Const {
            result: r,
            value: FieldElement::from_u64(v),
        });
        vars.push(r);
    }

    // Body: each tag picks two operands by index modulo current vars.len().
    for (tag, i, j) in body {
        let lhs = vars[i % vars.len()];
        let rhs = vars[j % vars.len()];
        let r = p.fresh_var();
        match tag {
            InstrTag::Const(v) => p.push(Instruction::Const {
                result: r,
                value: FieldElement::from_u64(v),
            }),
            InstrTag::Add => p.push(Instruction::Add {
                result: r,
                lhs,
                rhs,
            }),
            InstrTag::Sub => p.push(Instruction::Sub {
                result: r,
                lhs,
                rhs,
            }),
            InstrTag::Mul => p.push(Instruction::Mul {
                result: r,
                lhs,
                rhs,
            }),
            InstrTag::Neg => p.push(Instruction::Neg {
                result: r,
                operand: lhs,
            }),
        };
        vars.push(r);
    }

    // Asserts: anchor live wires so DCE can't strip everything.
    for (tag, i, j) in asserts {
        let lhs = vars[i % vars.len()];
        let rhs = vars[j % vars.len()];
        let r = p.fresh_var();
        match tag {
            AssertTag::AssertEq => p.push(Instruction::AssertEq {
                result: r,
                lhs,
                rhs,
                message: None,
            }),
        };
    }

    p
}

/// Strategy for generating an `InstrTag`.
fn instr_tag_strategy() -> impl Strategy<Value = InstrTag> {
    prop_oneof![
        any::<u64>().prop_map(InstrTag::Const),
        Just(InstrTag::Add),
        Just(InstrTag::Sub),
        Just(InstrTag::Mul),
        Just(InstrTag::Neg),
    ]
}

/// Manual deep-copy of an IrProgram. `IrProgram` doesn't derive
/// `Clone` (fields evolve over time and the maintainers want
/// per-callsite explicit copies); the test needs one to run
/// optimize twice.
fn clone_program(p: &IrProgram) -> IrProgram {
    IrProgram {
        instructions: p.instructions.clone(),
        next_var: p.next_var,
        var_names: p.var_names.clone(),
        var_types: p.var_types.clone(),
        input_spans: p.input_spans.clone(),
        var_spans: p.var_spans.clone(),
    }
}

/// Compare instruction sequences directly. `Instruction` derives
/// `Debug` and `Clone`; `PartialEq` is intentionally not derived
/// because some fields are field elements with subtle equality
/// semantics. `Debug` formatting is deterministic for the variants
/// the generator emits, so we can compare via `format!`.
fn instructions_eq(p: &IrProgram, q: &IrProgram) -> bool {
    if p.len() != q.len() {
        return false;
    }
    p.iter()
        .zip(q.iter())
        .all(|(a, b)| format!("{a:?}") == format!("{b:?}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// `optimize(optimize(p)) == optimize(p)` — running the optimizer
    /// twice produces the same output as running it once.
    #[test]
    fn optimize_is_idempotent(
        seed_consts in prop::collection::vec(any::<u64>(), 2..6),
        body in prop::collection::vec(
            (instr_tag_strategy(), 0usize..16, 0usize..16),
            0..20,
        ),
        asserts in prop::collection::vec(
            (Just(AssertTag::AssertEq), 0usize..16, 0usize..16),
            1..3,
        ),
    ) {
        let mut p1 = build_program(seed_consts, body, asserts);
        optimize(&mut p1);
        let mut p2 = clone_program(&p1);
        optimize(&mut p2);

        prop_assert!(
            instructions_eq(&p1, &p2),
            "optimize is not idempotent on input:\np1 (after 1 pass):\n{p1}\np2 (after 2 passes):\n{p2}",
        );
    }

}

// ============================================================================
// Vacuity guard (advisor §2c): catch a degenerate optimizer that
// always returns ⊥. Hand-built positive example is enough for this —
// proptest shrinks toward all-tautological inputs which spuriously
// trip the property.
// ============================================================================

/// Non-degenerate program: two distinct Consts plus a non-tautological
/// AssertEq that is *not* satisfied (forces the optimizer to keep the
/// constraint live, since folding it to a constant would be unsound).
/// After `optimize`, the program must retain at least one instruction.
#[test]
fn optimize_does_not_collapse_to_empty() {
    let mut p: IrProgram = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(7),
    });
    let b = p.fresh_var();
    p.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(11),
    });
    let r = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: r,
        lhs: a,
        rhs: b,
        message: None,
    });

    optimize(&mut p);

    assert!(
        !p.is_empty(),
        "optimize should not collapse a program with a live, \
         non-tautological AssertEq to the empty program; got:\n{p}"
    );
}

// ============================================================================
// Determinism unit tests (smaller, hand-built — fixed inputs that
// historically tripped phase-ordering bugs in similar projects).
// ============================================================================

/// Chain `Input → Add → Neg → unused`: rooted at an `Input`
/// (non-foldable side-effect) so `const_fold` cannot eat the chain
/// before DCE runs. Single-pass DCE would leave the upstream `Add`
/// live (the now-orphaned `Neg` referenced it before being removed);
/// the fixpoint loop inside `dce::dead_code_elimination` propagates
/// the orphan-ness backward and removes the whole chain.
///
/// **Discriminator (verified during development)**: patching
/// `dce.rs` to use a single-pass loop (replace `loop { ... if
/// program.len() == before { break; } }` with one iteration) makes
/// `p1 = optimize(input)` retain `Input + Add` while
/// `p2 = optimize(p1)` retains only `Input` — i.e., idempotence
/// fails on this exact shape. This test trips when fixpoint DCE
/// regresses.
#[test]
fn optimize_idempotent_on_dead_chain() {
    let mut p1: IrProgram = IrProgram::new();
    let a = p1.fresh_var();
    p1.push(Instruction::Input {
        result: a,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let b = p1.fresh_var();
    p1.push(Instruction::Add {
        result: b,
        lhs: a,
        rhs: a,
    });
    let c = p1.fresh_var();
    p1.push(Instruction::Neg {
        result: c,
        operand: b,
    });
    // No AssertEq — `Input` is itself a side-effect, so DCE keeps it
    // even when nothing references its result.

    optimize(&mut p1);
    let mut p2 = clone_program(&p1);
    optimize(&mut p2);

    assert!(
        instructions_eq(&p1, &p2),
        "optimize(optimize(p)) != optimize(p) on dead-chain:\n{p1}\n--\n{p2}"
    );
}
