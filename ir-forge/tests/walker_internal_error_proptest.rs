//! Property-based test: `Walker::lower` never returns an *internal-
//! error* `WalkError` variant on lift-shaped input.
//!
//! ## The narrowed property
//!
//! Literal "totality" — `Walker::lower` always returns `Ok` — is
//! unsound by design. `WalkError` (in
//! `ir-forge/src/lysis_lift/walker.rs`) has 18 variants split into
//! three classes:
//!
//! - **User-rejection allowed (8)**: `Alloc`, `OperandOutOfRange`,
//!   `NegativeLoopBound`, `LoopBodyTooLong`, `LiveSetTooLarge`,
//!   `SymbolicIndexedEffectNotEmittable`,
//!   `SymbolicArrayReadNotEmittable`, `SymbolicShiftNotEmittable`.
//!   Doc-comments frame these as resource limits or "rejected here
//!   rather than miscompiled".
//!
//! - **Forbidden / lift bug (7)**: `UndefinedSsaVar`,
//!   `SymbolicIndexedEffectIndexOutOfRange`,
//!   `SymbolicIndexedEffectMissingValue`,
//!   `SymbolicArrayReadIndexOutOfRange`,
//!   `SymbolicShiftNegativeAmount`, `TemplateCapturesMismatch`,
//!   `UndefinedTemplateId`. Doc-comments say "logic bug at lowering
//!   or instantiation" or "should be impossible if … wired correctly".
//!
//! - **Conditional (3)**: `TemplateNotSupported`,
//!   `TemplateOutputsNotSupported`, `UnsupportedInstruction { kind }`.
//!   These depend on lift-phase state — see
//!   `is_forbidden_walk_error` for the detailed rules.
//!
//! Property: for every `ExtendedInstruction` sequence shaped like the
//! production lift's output, `Walker::lower` returns `Ok(_)` or
//! `Err(e)` where `e` is in the user-rejection allowed set (or a
//! conditional one whose "forbidden" half does not apply).
//!
//! ## Generator strategy (Noir `ast_fuzzer` pattern)
//!
//! Rather than uniform random over the 7 `ExtendedInstruction`
//! variants — which would mostly trip forbidden variants because of
//! malformed-shape generation — the generator builds sequences in
//! lift order: seed `Plain(Const)` vars, then `Plain(arith)`
//! instructions, optionally wrapped in `LoopUnroll`. SSA validity is
//! enforced by tracking the defined-var set as we build.
//!
//! ## Discriminator (verified during development)
//!
//! Patching `walker.rs::lower` to return
//! `Err(WalkError::UndefinedSsaVar(SsaVar(99999)))` on a known
//! valid input makes the proptest fail at the very first case, since
//! `UndefinedSsaVar` is in the forbidden set. This is the regression
//! signal this test is designed to catch.

use ir_core::{Instruction, SsaVar};
use ir_forge::extended::ExtendedInstruction;
use ir_forge::lysis_lift::{WalkError, Walker};
use memory::{Bn254Fr, FieldElement, FieldFamily};
use proptest::prelude::*;

type Fe = FieldElement<Bn254Fr>;

/// Predicate: is this `WalkError` variant a *forbidden* internal
/// error (i.e. a lift bug that the production lift should never
/// emit)?
fn is_forbidden_walk_error(err: &WalkError) -> bool {
    match err {
        // ---- User-rejection allowed (8) ----
        WalkError::Alloc(_)
        | WalkError::OperandOutOfRange { .. }
        | WalkError::NegativeLoopBound { .. }
        | WalkError::LoopBodyTooLong { .. }
        | WalkError::LiveSetTooLarge { .. }
        | WalkError::SymbolicIndexedEffectNotEmittable
        | WalkError::SymbolicArrayReadNotEmittable
        | WalkError::SymbolicShiftNotEmittable => false,

        // ---- Forbidden / lift bug (7) ----
        WalkError::UndefinedSsaVar(_)
        | WalkError::SymbolicIndexedEffectIndexOutOfRange { .. }
        | WalkError::SymbolicIndexedEffectMissingValue
        | WalkError::SymbolicArrayReadIndexOutOfRange { .. }
        | WalkError::SymbolicShiftNegativeAmount { .. }
        | WalkError::TemplateCapturesMismatch { .. }
        | WalkError::UndefinedTemplateId(_) => true,

        // ---- Conditional (3) ----
        // The production lift uses inline + LoopUnroll (not
        // `TemplateCall`/`TemplateBody`), so any `TemplateNotSupported`
        // is a regression on the inline-only contract.
        WalkError::TemplateNotSupported => true,
        // The production lift uses Option B (no return values), so
        // any `TemplateOutputsNotSupported` is a regression too.
        WalkError::TemplateOutputsNotSupported => true,
        // `Div` is closed by Walker `Div` (commit `7bf3a828`); other
        // kinds (`Mod`/`BitAnd`/`BitOr`/`BitXor`/`Shl`/`Shr`) are
        // legitimate-not-yet-implemented punts. The generator does
        // not emit those kinds, so any `UnsupportedInstruction` here
        // is a regression on the kinds we *do* generate.
        WalkError::UnsupportedInstruction { kind } => {
            // Kinds we generate, listed in `arith_strategy()`:
            matches!(*kind, "Const" | "Add" | "Sub" | "Mul" | "Neg" | "AssertEq")
        }
    }
}

// ============================================================================
// Generator: lift-shaped ExtendedInstruction sequences
// ============================================================================

#[derive(Debug, Clone, Copy)]
enum ArithTag {
    Add,
    Sub,
    Mul,
    Neg,
}

fn arith_strategy() -> impl Strategy<Value = ArithTag> {
    prop_oneof![
        Just(ArithTag::Add),
        Just(ArithTag::Sub),
        Just(ArithTag::Mul),
        Just(ArithTag::Neg),
    ]
}

/// `(tag, lhs_index, rhs_index)` triple driving one arith instruction.
type ArithRecipe = (ArithTag, usize, usize);

/// `(loop_start, loop_end, inner_arith_recipe)` for a single LoopUnroll.
type LoopRecipe = (i64, i64, Vec<ArithRecipe>);

/// Build an `ExtendedInstruction` sequence with valid SSA.
///
/// Layout:
/// 1. N `Plain(Const)` seed vars (always at least 2)
/// 2. K `Plain(arith)` instructions referencing prior vars
/// 3. Optional 0-1 `LoopUnroll` wrapping a small `Plain(arith)` body
/// 4. M `Plain(AssertEq)` anchors
fn build_lift_sequence(
    seed_count: usize,
    seed_values: Vec<u64>,
    arith_recipe: Vec<ArithRecipe>,
    loop_recipe: Option<LoopRecipe>,
    assert_recipe: Vec<(usize, usize)>,
) -> Vec<ExtendedInstruction<Bn254Fr>> {
    let mut body: Vec<ExtendedInstruction<Bn254Fr>> = Vec::new();
    let mut next_var: u32 = 0;
    let mut defined: Vec<SsaVar> = Vec::new();

    let fresh = |defined: &mut Vec<SsaVar>, next_var: &mut u32| -> SsaVar {
        let v = SsaVar(*next_var);
        *next_var += 1;
        defined.push(v);
        v
    };

    let fe_of = |n: u64| -> Fe { Fe::from_canonical([n, 0, 0, 0]) };

    // 1. Seeds
    let n_seeds = seed_count.max(2);
    for i in 0..n_seeds {
        let v = fresh(&mut defined, &mut next_var);
        let value = seed_values.get(i).copied().unwrap_or(i as u64);
        body.push(ExtendedInstruction::Plain(Instruction::Const {
            result: v,
            value: fe_of(value),
        }));
    }

    // 2. Arith chain
    for (tag, i, j) in &arith_recipe {
        let lhs = defined[i % defined.len()];
        let rhs = defined[j % defined.len()];
        let r = fresh(&mut defined, &mut next_var);
        let inst = match tag {
            ArithTag::Add => Instruction::Add {
                result: r,
                lhs,
                rhs,
            },
            ArithTag::Sub => Instruction::Sub {
                result: r,
                lhs,
                rhs,
            },
            ArithTag::Mul => Instruction::Mul {
                result: r,
                lhs,
                rhs,
            },
            ArithTag::Neg => Instruction::Neg {
                result: r,
                operand: lhs,
            },
        };
        body.push(ExtendedInstruction::Plain(inst));
    }

    // 3. Optional LoopUnroll wrapper. Inner body only references vars
    //    defined BEFORE the loop (no inner-loop fresh vars threaded
    //    through outer `defined` — keeps the generator simple and
    //    avoids nested-scope SSA bookkeeping). `iter_var` is local to
    //    the loop body and must NOT be added to the outer `defined`
    //    set — that's how UndefinedSsaVar gets emitted on outer
    //    references.
    if let Some((start, end, inner_recipe)) = loop_recipe {
        let iter_var = SsaVar(next_var);
        next_var += 1;
        let mut inner_body: Vec<ExtendedInstruction<Bn254Fr>> = Vec::new();
        let mut inner_defined = defined.clone();
        inner_defined.push(iter_var);
        let mut inner_next = next_var;
        for (tag, i, j) in &inner_recipe {
            let lhs = inner_defined[i % inner_defined.len()];
            let rhs = inner_defined[j % inner_defined.len()];
            let r = SsaVar(inner_next);
            inner_next += 1;
            inner_defined.push(r);
            let inst = match tag {
                ArithTag::Add => Instruction::Add {
                    result: r,
                    lhs,
                    rhs,
                },
                ArithTag::Sub => Instruction::Sub {
                    result: r,
                    lhs,
                    rhs,
                },
                ArithTag::Mul => Instruction::Mul {
                    result: r,
                    lhs,
                    rhs,
                },
                ArithTag::Neg => Instruction::Neg {
                    result: r,
                    operand: lhs,
                },
            };
            inner_body.push(ExtendedInstruction::Plain(inst));
        }
        // Update outer next_var to skip past inner-loop vars so
        // post-loop fresh vars don't collide.
        next_var = inner_next;
        body.push(ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body: inner_body,
        });
    }

    // 4. AssertEq anchors (Plain). Use distinct operand indices so
    //    the constraint isn't trivially tautological.
    for (i, j) in &assert_recipe {
        let lhs = defined[i % defined.len()];
        let rhs = defined[j % defined.len()];
        let r = SsaVar(next_var);
        next_var += 1;
        body.push(ExtendedInstruction::Plain(Instruction::AssertEq {
            result: r,
            lhs,
            rhs,
            message: None,
        }));
    }

    body
}

// ============================================================================
// Property tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Walker never returns an internal-error variant on a
    /// lift-shaped input. User-rejection variants and `Ok` are both
    /// fine.
    #[test]
    fn walker_does_not_emit_internal_error(
        seed_count in 2usize..6,
        seed_values in prop::collection::vec(any::<u64>(), 0..6),
        arith_recipe in prop::collection::vec(
            (arith_strategy(), 0usize..16, 0usize..16),
            0..16,
        ),
        // Loop bounds: small, non-negative range that fits in u32.
        loop_recipe in proptest::option::of((
            0i64..4,
            4i64..16,
            prop::collection::vec(
                (arith_strategy(), 0usize..16, 0usize..16),
                0..6,
            ),
        )),
        assert_recipe in prop::collection::vec(
            (0usize..16, 0usize..16),
            0..3,
        ),
    ) {
        let body = build_lift_sequence(
            seed_count,
            seed_values,
            arith_recipe,
            loop_recipe,
            assert_recipe,
        );

        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        match walker.lower(body.clone()) {
            Ok(_) => {}
            Err(e) => {
                prop_assert!(
                    !is_forbidden_walk_error(&e),
                    "Walker emitted forbidden internal-error variant {e:?} on lift-shaped input. \
                     This is a regression on the lift contract — see test docstring §2a."
                );
            }
        }
    }
}

// ============================================================================
// Hand-built positive examples (smoke + regression pins)
// ============================================================================

/// Trivial lift sequence: two Consts, one Add, one AssertEq. Walker
/// must accept this without error.
#[test]
fn walker_accepts_trivial_arith() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        ExtendedInstruction::Plain(Instruction::Const {
            result: SsaVar(0),
            value: Fe::from_canonical([1, 0, 0, 0]),
        }),
        ExtendedInstruction::Plain(Instruction::Const {
            result: SsaVar(1),
            value: Fe::from_canonical([2, 0, 0, 0]),
        }),
        ExtendedInstruction::Plain(Instruction::Add {
            result: SsaVar(2),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
        }),
        ExtendedInstruction::Plain(Instruction::AssertEq {
            result: SsaVar(3),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
            message: None,
        }),
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let result = walker.lower(body.clone());
    assert!(
        result.is_ok(),
        "Walker rejected trivial arith sequence: {result:?}"
    );
}

/// LoopUnroll with a Plain body that references outer vars. Walker
/// should accept this without internal error.
#[test]
fn walker_accepts_simple_loop_unroll() {
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
        ExtendedInstruction::Plain(Instruction::Const {
            result: SsaVar(0),
            value: Fe::from_canonical([1, 0, 0, 0]),
        }),
        ExtendedInstruction::Plain(Instruction::Const {
            result: SsaVar(1),
            value: Fe::from_canonical([2, 0, 0, 0]),
        }),
        ExtendedInstruction::LoopUnroll {
            iter_var: SsaVar(2),
            start: 0,
            end: 4,
            body: vec![ExtendedInstruction::Plain(Instruction::Add {
                result: SsaVar(3),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            })],
        },
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let result = walker.lower(body.clone());
    match &result {
        Ok(_) => {}
        Err(e) => assert!(
            !is_forbidden_walk_error(e),
            "Walker emitted forbidden internal-error on simple LoopUnroll: {e:?}"
        ),
    }
}
