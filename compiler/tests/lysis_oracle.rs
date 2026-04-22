//! Phase 3.C.3 oracle fixtures.
//!
//! Each fixture builds two `IrProgram<F>`s programmatically and asserts
//! that [`compiler::lysis_oracle::semantic_equivalence`] classifies
//! them into the expected [`OracleResult`] variant. The canonical
//! regression (`oracle_shared_vs_duplicated`) runs first; if it misses
//! `Equivalent`, the whole Lysis design premise is broken (rollback per
//! `.claude/plans/lysis-phase3.md` §8).
//!
//! ## Fixture matrix
//!
//! | Fixture                       | Expected            | Exercises               |
//! |-------------------------------|---------------------|-------------------------|
//! | `shared_vs_duplicated`        | `Equivalent`        | canonical regression    |
//! | `ssa_renamed`                 | `Equivalent`        | canonicalize_ssa        |
//! | `constraint_emission_reorder` | `Equivalent`        | multiset canonicalization |
//! | `public_partition`            | `PartitionDiffers`  | Visibility partition    |
//! | `extra_constraint`            | `ConstraintsDiffer` | constraint delta detect |
//! | `coefficient_diff`            | `ConstraintsDiffer` | LC coefficient detect   |
//!
//! `oracle_witness_divergence` (step 4 specific) is deferred to 3.C.8
//! where real Lysis-vs-legacy pipelines expose the WitnessCall
//! divergence surface naturally.

use std::collections::HashMap;

use compiler::lysis_oracle::{semantic_equivalence, OracleResult};
use ir::types::{Instruction, IrProgram, SsaVar, Visibility};
use memory::{Bn254Fr, FieldElement};

type F = Bn254Fr;

fn fe(n: u64) -> FieldElement<F> {
    FieldElement::from_u64(n)
}

// ---------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------

/// A program that computes `y = x * x` over a public witness and
/// asserts `y == z`. SSA numbering starts at `start` so the fixture
/// can be instantiated with different base offsets for renaming tests.
fn square_assert(start: u32) -> IrProgram<F> {
    let mut p: IrProgram<F> = IrProgram::new();
    let z = SsaVar(start);
    let x = SsaVar(start + 1);
    let sq = SsaVar(start + 2);
    let ae = SsaVar(start + 3);
    p.push(Instruction::Input {
        result: z,
        name: "z".into(),
        visibility: Visibility::Public,
    });
    p.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Mul {
        result: sq,
        lhs: x,
        rhs: x,
    });
    p.push(Instruction::AssertEq {
        result: ae,
        lhs: sq,
        rhs: z,
        message: None,
    });
    p.set_next_var(start + 4);
    p
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

#[test]
fn oracle_shared_vs_duplicated_is_equivalent() {
    // Phase 3.C canonical regression. Both sides are structurally
    // identical IR streams built via two independent calls to the
    // same builder. This fixture is the MVP stand-in for the real
    // Lysis-lifter-vs-legacy-instantiate comparison that 3.C.8 will
    // expose once circom/ emits ExtendedInstruction under the flag.
    //
    // The semantic contract checked here: when both sides produce
    // bit-identical IR, the oracle must classify `Equivalent` —
    // otherwise the strict multiset compare is rejecting structurally
    // identical programs, which would invalidate every other fixture.
    let a = square_assert(0);
    let b = square_assert(0);
    assert_eq!(semantic_equivalence(&a, &b, &[]), OracleResult::Equivalent);
}

#[test]
fn oracle_ssa_renamed_is_equivalent() {
    // Same program, SSA numbering offset by 100 on side b. The
    // canonicalize_ssa step must fold both into the same canonical
    // numbering before step 3 runs.
    let a = square_assert(0);
    let b = square_assert(100);
    assert_eq!(semantic_equivalence(&a, &b, &[]), OracleResult::Equivalent);
}

#[test]
fn oracle_constraint_emission_reorder_is_equivalent() {
    // Two programs that emit the same R1CS constraints in a different
    // instruction order. Specifically: side a has `AssertEq(x, y)`
    // before `AssertEq(y, z)`; side b swaps them. Wire allocation is
    // unaffected because x/y/z are already inputs.
    let a = {
        let mut p: IrProgram<F> = IrProgram::new();
        p.push(Instruction::Input {
            result: SsaVar(0),
            name: "x".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Input {
            result: SsaVar(1),
            name: "y".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Input {
            result: SsaVar(2),
            name: "z".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::AssertEq {
            result: SsaVar(3),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
            message: None,
        });
        p.push(Instruction::AssertEq {
            result: SsaVar(4),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
            message: None,
        });
        p.set_next_var(5);
        p
    };
    let b = {
        let mut p: IrProgram<F> = IrProgram::new();
        p.push(Instruction::Input {
            result: SsaVar(0),
            name: "x".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Input {
            result: SsaVar(1),
            name: "y".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Input {
            result: SsaVar(2),
            name: "z".into(),
            visibility: Visibility::Public,
        });
        // Swap emission order.
        p.push(Instruction::AssertEq {
            result: SsaVar(3),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
            message: None,
        });
        p.push(Instruction::AssertEq {
            result: SsaVar(4),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
            message: None,
        });
        p.set_next_var(5);
        p
    };
    assert_eq!(semantic_equivalence(&a, &b, &[]), OracleResult::Equivalent);
}

#[test]
fn oracle_public_partition_differs() {
    let a = square_assert(0);
    let mut b = square_assert(0);
    // Flip x's visibility on b.
    if let Instruction::Input { visibility, .. } = &mut b.instructions_mut()[1] {
        *visibility = Visibility::Public;
    }
    match semantic_equivalence(&a, &b, &[]) {
        OracleResult::PartitionDiffers { a_public, b_public } => {
            assert_eq!(a_public, vec!["z"]);
            assert_eq!(b_public, vec!["z", "x"]);
        }
        other => panic!("expected PartitionDiffers, got {other:?}"),
    }
}

#[test]
fn oracle_extra_constraint_differs() {
    let a = square_assert(0);
    let mut b = square_assert(0);
    // Append a trivially-true AssertEq.
    let ae = b.fresh_var();
    b.push(Instruction::AssertEq {
        result: ae,
        lhs: SsaVar(1), // x
        rhs: SsaVar(1), // x
        message: None,
    });

    match semantic_equivalence(&a, &b, &[]) {
        OracleResult::ConstraintsDiffer {
            a_constraints,
            b_constraints,
            ..
        } => {
            assert!(a_constraints < b_constraints);
        }
        other => panic!("expected ConstraintsDiffer, got {other:?}"),
    }
}

#[test]
fn oracle_coefficient_diff_is_constraint_diff() {
    // Two programs with the same topology but different constants
    // multiplied into a Mul. Side a: x * Const(2). Side b: x * Const(3).
    // The Mul constraint's A-side LC carries the coefficient; the
    // multiset must detect the difference.
    fn build(c: u64) -> IrProgram<F> {
        let mut p: IrProgram<F> = IrProgram::new();
        p.push(Instruction::Input {
            result: SsaVar(0),
            name: "z".into(),
            visibility: Visibility::Public,
        });
        p.push(Instruction::Input {
            result: SsaVar(1),
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Const {
            result: SsaVar(2),
            value: fe(c),
        });
        p.push(Instruction::Mul {
            result: SsaVar(3),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
        });
        p.push(Instruction::AssertEq {
            result: SsaVar(4),
            lhs: SsaVar(3),
            rhs: SsaVar(0),
            message: None,
        });
        p.set_next_var(5);
        p
    }

    let a = build(2);
    let b = build(3);
    match semantic_equivalence(&a, &b, &[]) {
        OracleResult::ConstraintsDiffer { .. } => {}
        other => panic!("expected ConstraintsDiffer, got {other:?}"),
    }
}

#[test]
fn oracle_witness_agreement_on_test_input() {
    // End-to-end check: identical programs, single test input, verify
    // the witness comparison runs and succeeds.
    let a = square_assert(0);
    let b = square_assert(50);

    let mut input: HashMap<String, FieldElement<F>> = HashMap::new();
    input.insert("z".into(), fe(25));
    input.insert("x".into(), fe(5));

    assert_eq!(
        semantic_equivalence(&a, &b, std::slice::from_ref(&input)),
        OracleResult::Equivalent
    );
}
