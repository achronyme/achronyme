//! Test helpers shared between integration tests, the cargo-fuzz harness
//! at `fuzz/fuzz_targets/fuzz_r1cs_preservation.rs`, and the
//! frozen-baseline regression pins.
//!
//! Gated behind `cfg(any(test, feature = "test-support"))` so this
//! module is compiled into integration tests automatically and into
//! external consumers (currently the fuzz crate + cross-path baselines)
//! only when they opt in via `features = ["test-support"]`. Mirrors the
//! [`ir_forge::test_utils`] pattern.
//!
//! ## Two responsibilities, one module
//!
//! 1. **R1CS preservation oracle helpers**: `compile_and_solve` +
//!    `apply_substitutions`. See
//!    `zkc/tests/r1cs_preservation_proptest.rs` for the property
//!    framing (CompCert two-sided simulation, advisor §2b).
//!
//! 2. **Frozen-baseline regression machinery**: the canonical-multiset
//!    hash + `FrozenBaseline` snapshot used by the cross-path
//!    baseline tests. The `canonicalize_constraint` / `lc_to_terms` /
//!    `constraint_multiset` / `extract_public_inputs` primitives are
//!    shared with `lysis_oracle::compare` so both consumers see the
//!    same canonicalization logic.

use std::collections::HashMap;

use constraints::poseidon::PoseidonParamsProvider;
use constraints::r1cs::{Constraint, LinearCombination};
use ir::IrLowering;
use ir_core::{Instruction, IrProgram, Visibility};
use memory::{FieldBackend, FieldElement};
#[cfg(feature = "test-support")]
use sha2::{Digest, Sha256};

use crate::r1cs_backend::R1CSCompiler;
use crate::witness::WitnessGenerator;

// ============================================================================
// R1CS preservation oracle helpers
// ============================================================================

/// Compile a circuit source to R1CS, generate a satisfying witness,
/// and verify it satisfies the pre-O1 system. Returns the compiler
/// (with `cs` still in its pre-O1 state) and the witness vector.
///
/// Panics if the lowering, R1CS compile, or witness generation fails,
/// or if the resulting witness does not verify against the pre-O1
/// system. Used as the input-side fixture for both the proptest and
/// the cargo-fuzz harness — both treat any of those failures as a
/// fixture-construction error rather than an oracle violation.
pub fn compile_and_solve(
    source: &str,
    public: &[(&str, FieldElement)],
    witness_inputs: &[(&str, FieldElement)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness_inputs.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness_inputs.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    let w = wg.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("pre-O1 R1CS must verify on solved witness");

    (compiler, w)
}

/// Apply the compiler's `substitution_map` to a witness vector,
/// re-deriving each substituted wire's value from its LC. Returns
/// the post-substitution witness — call after `optimize_r1cs()` to
/// fill in eliminated wires before `cs.verify()`.
pub fn apply_substitutions(compiler: &R1CSCompiler, witness: &[FieldElement]) -> Vec<FieldElement> {
    let mut w = witness.to_vec();
    if let Some(subs) = &compiler.substitution_map {
        for (var, lc) in subs {
            w[*var] = lc.evaluate(&w).expect("substitution LC must evaluate");
        }
    }
    w
}

// ============================================================================
// Canonicalization primitives (shared with lysis_oracle::compare)
// ============================================================================

/// Canonical positional key for a single `A * B = C` constraint.
/// Coefficients are stored as canonical `[u64; 4]` limbs so the key
/// carries `Ord` without leaking `F` into the sorted type — that's
/// what makes the resulting multiset stable across runs even when
/// HashMap iteration order leaks into wire allocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalConstraint {
    pub a: Vec<(usize, [u64; 4])>,
    pub b: Vec<(usize, [u64; 4])>,
    pub c: Vec<(usize, [u64; 4])>,
}

/// Canonicalize a single constraint by sorting + deduplicating each
/// of the three linear combinations.
pub fn canonicalize_constraint<F: FieldBackend>(c: &Constraint<F>) -> CanonicalConstraint {
    CanonicalConstraint {
        a: lc_to_terms(&c.a),
        b: lc_to_terms(&c.b),
        c: lc_to_terms(&c.c),
    }
}

/// Simplify an LC (collapses duplicates, drops zero coefficients,
/// sorts by wire index via BTreeMap) and project onto the portable
/// `(wire_index, canonical_limbs)` representation.
pub fn lc_to_terms<F: FieldBackend>(lc: &LinearCombination<F>) -> Vec<(usize, [u64; 4])> {
    lc.simplify()
        .terms()
        .iter()
        .map(|(v, coeff)| (v.index(), coeff.to_canonical()))
        .collect()
}

/// Compute a canonical, sorted multiset of constraints. Result is
/// stable across runs regardless of HashMap iteration leaks in wire
/// allocation — this is the load-bearing invariant for frozen-baseline
/// pins.
pub fn constraint_multiset<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> Vec<CanonicalConstraint> {
    let mut out: Vec<CanonicalConstraint> =
        constraints.iter().map(canonicalize_constraint).collect();
    out.sort();
    out
}

/// Public inputs declared in `program.instructions`, in declaration
/// order. Stable across runs (instruction order is preserved by
/// lowering).
pub fn extract_public_inputs<F: FieldBackend>(program: &IrProgram<F>) -> Vec<String> {
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

// ============================================================================
// Frozen-baseline machinery
// ============================================================================

/// SHA-256 hash of the bincode-serialized canonical multiset. Compact
/// pin value (32 bytes) — full constraint detail surfaces only when
/// an assertion fails (see `assert_frozen_baseline_matches`).
///
/// Hash domain: wire indices and field-element coefficients only.
/// Public-input *names* are intentionally **not** included — naming is
/// checked separately via `FrozenBaseline::public_inputs` (a Vec
/// captured by `extract_public_inputs`), so a public-input rename
/// surfaces as a Vec diff rather than an opaque hash mismatch. This
/// keeps drift messages actionable: count/var/name diffs print before
/// the hash compare in `assert_frozen_baseline_matches`.
///
/// Only available with `feature = "test-support"` — the helper pulls
/// in `sha2`, which we don't want in a production build of zkc.
#[cfg(feature = "test-support")]
pub fn canonical_multiset_hash<F: FieldBackend>(constraints: &[Constraint<F>]) -> [u8; 32] {
    let multiset = constraint_multiset(constraints);
    let mut hasher = Sha256::new();
    for c in &multiset {
        for (idx, limbs) in &c.a {
            hasher.update((*idx as u64).to_le_bytes());
            for limb in limbs {
                hasher.update(limb.to_le_bytes());
            }
        }
        hasher.update([0xFF]); // separator a→b
        for (idx, limbs) in &c.b {
            hasher.update((*idx as u64).to_le_bytes());
            for limb in limbs {
                hasher.update(limb.to_le_bytes());
            }
        }
        hasher.update([0xFF]); // separator b→c
        for (idx, limbs) in &c.c {
            hasher.update((*idx as u64).to_le_bytes());
            for limb in limbs {
                hasher.update(limb.to_le_bytes());
            }
        }
        hasher.update([0xFE]); // constraint terminator
    }
    hasher.finalize().into()
}

/// Snapshot of a circuit's structural identity. Pin-able value used
/// by frozen-baseline regression tests.
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenBaseline {
    /// Canonical multiset hash before O1 (linear elimination).
    pub pre_o1_hash: [u8; 32],
    /// Constraint count before O1.
    pub pre_o1_count: usize,
    /// Canonical multiset hash after O1.
    pub post_o1_hash: [u8; 32],
    /// Constraint count after O1.
    pub post_o1_count: usize,
    /// Wire count after O1 (zero is unallocated wire 0).
    pub num_variables: usize,
    /// Public inputs in declaration order.
    pub public_inputs: Vec<String>,
}

/// Compile a program through R1CSCompiler and capture a `FrozenBaseline`
/// snapshot. Drives both pre-O1 and post-O1 multiset hashing.
///
/// Panics on R1CS compilation error — input is expected to be a
/// well-formed `IrProgram` from a known-good lowering pipeline.
#[cfg(feature = "test-support")]
pub fn compute_frozen_baseline<F: PoseidonParamsProvider>(
    program: &IrProgram<F>,
) -> FrozenBaseline {
    let public_inputs = extract_public_inputs(program);

    let mut compiler = R1CSCompiler::<F>::new();
    compiler
        .compile_ir(program)
        .expect("R1CS compilation must succeed for frozen baseline fixture");

    let pre_o1_constraints: Vec<Constraint<F>> = compiler.cs.constraints().to_vec();
    let pre_o1_hash = canonical_multiset_hash(&pre_o1_constraints);
    let pre_o1_count = pre_o1_constraints.len();

    compiler.optimize_r1cs();

    let post_o1_constraints = compiler.cs.constraints();
    let post_o1_hash = canonical_multiset_hash(post_o1_constraints);
    let post_o1_count = post_o1_constraints.len();
    let num_variables = compiler.cs.num_variables();

    FrozenBaseline {
        pre_o1_hash,
        pre_o1_count,
        post_o1_hash,
        post_o1_count,
        num_variables,
        public_inputs,
    }
}

/// Assert two frozen baselines match on shape only (constraint counts,
/// var count, public partition) — skips the canonical-multiset hash
/// comparison. Use this for circuits with known wire-id permutation
/// non-determinism that the sort-based canonicalization doesn't
/// neutralize (sort handles term-order within an LC, not wire-index
/// permutation across LCs). Documented escape hatch — every caller
/// should cite the upstream determinism leak in a comment.
#[cfg(feature = "test-support")]
pub fn assert_frozen_baseline_shape_matches(actual: &FrozenBaseline, expected: &FrozenBaseline) {
    if actual.public_inputs != expected.public_inputs {
        panic!(
            "frozen baseline (shape) public-input partition mismatch:\n  expected: {:?}\n  actual:   {:?}",
            expected.public_inputs, actual.public_inputs,
        );
    }
    if actual.num_variables != expected.num_variables {
        panic!(
            "frozen baseline (shape) variable-count mismatch: expected {}, actual {}",
            expected.num_variables, actual.num_variables,
        );
    }
    if actual.pre_o1_count != expected.pre_o1_count {
        panic!(
            "frozen baseline (shape) pre-O1 constraint-count mismatch: expected {}, actual {}",
            expected.pre_o1_count, actual.pre_o1_count,
        );
    }
    if actual.post_o1_count != expected.post_o1_count {
        panic!(
            "frozen baseline (shape) post-O1 constraint-count mismatch: expected {}, actual {}",
            expected.post_o1_count, actual.post_o1_count,
        );
    }
}

/// Assert two frozen baselines match, with a useful diff message on
/// mismatch (constraint counts, var count, public partition, then the
/// hash). Failing prints actionable context, not just a hash mismatch.
#[cfg(feature = "test-support")]
pub fn assert_frozen_baseline_matches(actual: &FrozenBaseline, expected: &FrozenBaseline) {
    if actual.public_inputs != expected.public_inputs {
        panic!(
            "frozen baseline public-input partition mismatch:\n  expected: {:?}\n  actual:   {:?}",
            expected.public_inputs, actual.public_inputs,
        );
    }
    if actual.num_variables != expected.num_variables {
        panic!(
            "frozen baseline variable-count mismatch: expected {}, actual {}",
            expected.num_variables, actual.num_variables,
        );
    }
    if actual.pre_o1_count != expected.pre_o1_count {
        panic!(
            "frozen baseline pre-O1 constraint-count mismatch: expected {}, actual {}",
            expected.pre_o1_count, actual.pre_o1_count,
        );
    }
    if actual.post_o1_count != expected.post_o1_count {
        panic!(
            "frozen baseline post-O1 constraint-count mismatch: expected {}, actual {}",
            expected.post_o1_count, actual.post_o1_count,
        );
    }
    if actual.pre_o1_hash != expected.pre_o1_hash {
        panic!(
            "frozen baseline pre-O1 multiset hash drift\n  \
             expected: {}\n  actual:   {}\n  \
             counts agree ({} pre / {} post / {} vars), but constraint structure changed.\n  \
             A regenerate-baselines flow is needed if intentional; otherwise this is a regression.",
            hex_encode(&expected.pre_o1_hash),
            hex_encode(&actual.pre_o1_hash),
            actual.pre_o1_count,
            actual.post_o1_count,
            actual.num_variables,
        );
    }
    if actual.post_o1_hash != expected.post_o1_hash {
        panic!(
            "frozen baseline post-O1 multiset hash drift\n  \
             expected: {}\n  actual:   {}\n  \
             pre-O1 matches; the optimizer's output diverged.",
            hex_encode(&expected.post_o1_hash),
            hex_encode(&actual.post_o1_hash),
        );
    }
}

#[cfg(feature = "test-support")]
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
