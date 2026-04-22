//! `semantic_equivalence` — decide whether two `IrProgram<F>` describe
//! the same circuit.
//!
//! The oracle is the Phase 3 correctness safety net: it compares the
//! output of the legacy `ir::prove_ir::instantiate` path against the
//! output of the Lysis lifter for a growing set of fixtures. Any
//! deviation surfaces as a concrete `OracleResult` variant — the CI
//! matrix reads these to decide whether a Lysis change is safe to
//! merge.
//!
//! The full pipeline is four steps (RFC §9.1):
//!
//! 1. **Canonicalize**. Rename SsaVars to their visitation index in
//!    both programs (`ir::passes::canonicalize_ssa`). Defensive —
//!    protects downstream comparison against non-deterministic
//!    fresh-var counters in independent emitters.
//!
//! 2. **Public partition**. Extract the public-input names (in
//!    declaration order) from both canonical programs and require
//!    bit-identical equality. A mismatch points at an I/O surface
//!    divergence and short-circuits before compile.
//!
//! 3. **Constraint multiset**. Compile both to R1CS
//!    (`crate::r1cs_backend::R1CSCompiler`), canonicalize each
//!    `Constraint<F>` by sorting its `LinearCombination` terms
//!    (via `LinearCombination::simplify`) and serializing the
//!    coefficients as `[u64; 4]` canonical limbs, then sort the
//!    resulting `Vec<CanonicalConstraint>` and compare. Variable
//!    counts must also match — two multisets can coincide on
//!    constraints while one system carries unreferenced wires.
//!
//! 4. **Witness agreement**. For each provided test input, solve both
//!    R1CSs (`crate::witness_gen::WitnessGenerator`) and compare the
//!    resulting witness vectors element-wise. This catches the case
//!    where the constraint set is identical but the
//!    witness-computation pipeline (e.g., an Artik blob) diverges.

use std::collections::HashMap;

use constraints::poseidon::PoseidonParamsProvider;
use constraints::r1cs::{Constraint, LinearCombination};
use ir::passes::canonicalize_ssa;
use ir::types::{Instruction, IrProgram, Visibility};
use memory::{FieldBackend, FieldElement};

use crate::r1cs_backend::R1CSCompiler;
use crate::witness_gen::WitnessGenerator;

/// Outcome of [`semantic_equivalence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleResult {
    /// Programs are semantically equivalent on every checked axis.
    Equivalent,
    /// Public-input declarations disagree.
    PartitionDiffers {
        a_public: Vec<String>,
        b_public: Vec<String>,
    },
    /// R1CS compilation failed on one of the two programs.
    CompilationFailed { side: OracleSide, error: String },
    /// Canonical constraint multisets disagree, or the two systems
    /// allocate a different number of wires.
    ConstraintsDiffer {
        a_constraints: usize,
        b_constraints: usize,
        a_variables: usize,
        b_variables: usize,
    },
    /// Witness solving failed on one side. Likely an `R1CSError`
    /// propagated from `WitnessGenerator::generate`.
    WitnessSolveFailed {
        side: OracleSide,
        input_index: usize,
        error: String,
    },
    /// Both solved, but the resulting witness vectors disagree.
    WitnessDiverges { input_index: usize },
}

/// Which of the two programs failed a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleSide {
    A,
    B,
}

/// Decide whether `a` and `b` describe the same circuit.
///
/// `test_inputs` is the set of public-input assignments to solve with;
/// leave empty to skip step 4 (multiset equality alone is often
/// enough for fast regression tests).
pub fn semantic_equivalence<F>(
    a: &IrProgram<F>,
    b: &IrProgram<F>,
    test_inputs: &[HashMap<String, FieldElement<F>>],
) -> OracleResult
where
    F: PoseidonParamsProvider,
{
    // Step 1: canonicalize SSA numbering on both sides.
    let a_canon = canonicalize_ssa(a);
    let b_canon = canonicalize_ssa(b);

    // Step 2: public-input partition.
    let a_pub = extract_public_inputs(&a_canon);
    let b_pub = extract_public_inputs(&b_canon);
    if a_pub != b_pub {
        return OracleResult::PartitionDiffers {
            a_public: a_pub,
            b_public: b_pub,
        };
    }

    // Step 3: compile both to R1CS.
    let mut rc_a = R1CSCompiler::<F>::new();
    if let Err(e) = rc_a.compile_ir(&a_canon) {
        return OracleResult::CompilationFailed {
            side: OracleSide::A,
            error: format!("{e}"),
        };
    }
    let mut rc_b = R1CSCompiler::<F>::new();
    if let Err(e) = rc_b.compile_ir(&b_canon) {
        return OracleResult::CompilationFailed {
            side: OracleSide::B,
            error: format!("{e}"),
        };
    }

    // Constraint multiset comparison.
    let a_set = constraint_multiset(rc_a.cs.constraints());
    let b_set = constraint_multiset(rc_b.cs.constraints());
    if a_set != b_set || rc_a.cs.num_variables() != rc_b.cs.num_variables() {
        return OracleResult::ConstraintsDiffer {
            a_constraints: rc_a.cs.num_constraints(),
            b_constraints: rc_b.cs.num_constraints(),
            a_variables: rc_a.cs.num_variables(),
            b_variables: rc_b.cs.num_variables(),
        };
    }

    // Step 4: witness agreement on each test input.
    for (idx, input) in test_inputs.iter().enumerate() {
        let w_a = match WitnessGenerator::from_compiler(&rc_a).generate(input) {
            Ok(w) => w,
            Err(e) => {
                return OracleResult::WitnessSolveFailed {
                    side: OracleSide::A,
                    input_index: idx,
                    error: format!("{e}"),
                };
            }
        };
        let w_b = match WitnessGenerator::from_compiler(&rc_b).generate(input) {
            Ok(w) => w,
            Err(e) => {
                return OracleResult::WitnessSolveFailed {
                    side: OracleSide::B,
                    input_index: idx,
                    error: format!("{e}"),
                };
            }
        };
        if w_a != w_b {
            return OracleResult::WitnessDiverges { input_index: idx };
        }
    }

    OracleResult::Equivalent
}

/// Public inputs declared in `program.instructions`, in declaration
/// order. Name collisions are preserved — duplicate public declarations
/// would disagree just like any other I/O difference.
fn extract_public_inputs<F: FieldBackend>(program: &IrProgram<F>) -> Vec<String> {
    program
        .iter()
        .filter_map(|inst| match inst {
            Instruction::Input {
                name,
                visibility: Visibility::Public,
                ..
            } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Canonical positional key for a single `A * B = C` constraint.
/// Coefficients are stored as canonical `[u64; 4]` limbs so the key
/// carries `Ord` without leaking `F` into the sorted type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalConstraint {
    a: Vec<(usize, [u64; 4])>,
    b: Vec<(usize, [u64; 4])>,
    c: Vec<(usize, [u64; 4])>,
}

fn constraint_multiset<F: FieldBackend>(constraints: &[Constraint<F>]) -> Vec<CanonicalConstraint> {
    let mut out: Vec<CanonicalConstraint> =
        constraints.iter().map(canonicalize_constraint).collect();
    out.sort();
    out
}

fn canonicalize_constraint<F: FieldBackend>(c: &Constraint<F>) -> CanonicalConstraint {
    CanonicalConstraint {
        a: lc_to_terms(&c.a),
        b: lc_to_terms(&c.b),
        c: lc_to_terms(&c.c),
    }
}

/// Simplify an LC (collapses duplicates, drops zero coefficients,
/// sorts by wire index via BTreeMap) and project onto the portable
/// `(wire_index, canonical_limbs)` representation.
fn lc_to_terms<F: FieldBackend>(lc: &LinearCombination<F>) -> Vec<(usize, [u64; 4])> {
    lc.simplify()
        .terms()
        .iter()
        .map(|(v, coeff)| (v.index(), coeff.to_canonical()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::types::SsaVar;
    use memory::Bn254Fr;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_u64(n)
    }

    /// Build a small program: input `z` (public), input `x` and `y`
    /// (witness), and assert `x * y == z`. The SSA numbering starts
    /// at `start` so we can test renaming.
    fn mul_eq_program(start: u32) -> IrProgram<Bn254Fr> {
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.set_next_var(start + 4);

        let z = SsaVar(start);
        let x = SsaVar(start + 1);
        let y = SsaVar(start + 2);
        let prod = SsaVar(start + 3);

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
        p.push(Instruction::Input {
            result: y,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Mul {
            result: prod,
            lhs: x,
            rhs: y,
        });
        p.push(Instruction::AssertEq {
            result: SsaVar(start + 4),
            lhs: prod,
            rhs: z,
            message: None,
        });
        p.set_next_var(start + 5);
        p
    }

    #[test]
    fn equivalent_identical_programs() {
        let a = mul_eq_program(0);
        let b = mul_eq_program(0);
        assert_eq!(semantic_equivalence(&a, &b, &[]), OracleResult::Equivalent);
    }

    #[test]
    fn equivalent_under_canonical_renaming() {
        // Same program, but SSA numbering starts at a different offset.
        // canonicalize_ssa must fold this into the same canonical form.
        let a = mul_eq_program(0);
        let b = mul_eq_program(100);
        assert_eq!(semantic_equivalence(&a, &b, &[]), OracleResult::Equivalent);
    }

    #[test]
    fn equivalent_on_test_input() {
        let a = mul_eq_program(0);
        let b = mul_eq_program(50);
        let mut input = HashMap::new();
        input.insert("z".into(), fe(12));
        input.insert("x".into(), fe(3));
        input.insert("y".into(), fe(4));
        assert_eq!(
            semantic_equivalence(&a, &b, std::slice::from_ref(&input)),
            OracleResult::Equivalent
        );
    }

    #[test]
    fn detects_public_partition_difference() {
        let mut a = mul_eq_program(0);
        // Flip z's visibility on side b.
        let mut b = mul_eq_program(0);
        if let Instruction::Input { visibility, .. } = &mut b.instructions_mut()[0] {
            *visibility = Visibility::Witness;
        }
        // Add a new public input to keep the visibility ratio sensible.
        let new_var = b.fresh_var();
        b.push(Instruction::Input {
            result: new_var,
            name: "q".into(),
            visibility: Visibility::Public,
        });

        match semantic_equivalence(&a, &b, &[]) {
            OracleResult::PartitionDiffers { a_public, b_public } => {
                assert_eq!(a_public, vec!["z"]);
                assert_eq!(b_public, vec!["q"]);
            }
            other => panic!("expected PartitionDiffers, got {other:?}"),
        }

        // Silence unused-mut warning on a when the match arm above runs.
        let _ = &mut a;
    }

    #[test]
    fn detects_constraint_difference() {
        let a = mul_eq_program(0);
        // Build b with one extra constraint: AssertEq(x, x) — trivially
        // true but adds a wire + constraint.
        let mut b = mul_eq_program(0);
        let extra_result = b.fresh_var();
        b.push(Instruction::AssertEq {
            result: extra_result,
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
    fn witness_compare_skipped_with_empty_inputs() {
        // When test_inputs is empty, step 4 doesn't run. We only
        // rely on the multiset compare from step 3.
        let a = mul_eq_program(0);
        let b = mul_eq_program(0);
        assert_eq!(semantic_equivalence(&a, &b, &[]), OracleResult::Equivalent);
    }

    #[test]
    fn canonicalize_constraint_sorts_lc_terms() {
        // Regression: the same underlying constraint expressed with
        // different term orderings must collapse to the same key.
        use constraints::r1cs::{LinearCombination, Variable};

        let mut lc_a: LinearCombination<Bn254Fr> = LinearCombination::zero();
        lc_a.add_term(Variable(5), fe(3));
        lc_a.add_term(Variable(2), fe(7));

        let mut lc_b: LinearCombination<Bn254Fr> = LinearCombination::zero();
        lc_b.add_term(Variable(2), fe(7));
        lc_b.add_term(Variable(5), fe(3));

        assert_eq!(lc_to_terms(&lc_a), lc_to_terms(&lc_b));
    }
}
