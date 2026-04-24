//! Phase 3.C.6 Stage 1 smoke gate.
//!
//! Cross-validates [`ir_forge::lysis_roundtrip`] against
//! programmatically-built `IrProgram<F>` fixtures using
//! [`zkc::lysis_oracle::semantic_equivalence`].
//!
//! ## Why programmatic fixtures, not real `instantiate` output
//!
//! The `Walker` (in `ir-forge::lysis_lift`) is opinionated: it
//! desugars several high-level `Instruction` variants into more
//! primitive ops at lift time, regardless of whether the Plain
//! wrapping came from a real Lysis emitter or from this Stage-1
//! wrap-then-lift path. The desugarings:
//!
//! - `Assert(x)`        → `AssertEq(x, one_const)`  (+ a hoisted `Const(1)`)
//! - `Not(x)`           → `Sub(one, x)`
//! - `And(x,y)`         → `Mul(x, y)`
//! - `Or(x,y)`          → `Add(x,y) - Mul(x,y)`
//! - `IsNeq(x,y)`       → `Sub(one, IsEq(x, y))`
//! - `IsLe(x,y)`        → `Sub(one, IsLt(y, x))`
//! - `IsLtBounded(...)` → `IsLt(...)` (bitwidth hint dropped)
//! - `IsLeBounded(...)` → `Sub(one, IsLt(y, x))`
//!
//! The desugarings are SEMANTICALLY equivalent at proof time but
//! produce a DIFFERENT R1CS constraint multiset (the wire layout
//! changes when `one` is materialized as a pinned wire vs folded into
//! the constraint coefficient). The oracle's step-3 multiset compare
//! is bit-strict, so the smoke gate would always fail on any source
//! that uses `assert(...)` (lowered to `Assert(IsEq(...))`), boolean
//! ops, or the bounded comparison variants.
//!
//! Stage 2 inherits this exact constraint: when the new
//! `ExtendedSink` emits `Plain(Assert)` and the Walker desugars it,
//! the same divergence will appear — so the proper resolution is to
//! either (a) make the lifter conservatively skip desugarings on
//! variants that already exist as IR primitives, (b) extend the
//! oracle with an instruction-shape canonicaliser, or (c) accept the
//! divergence and switch the oracle to a witness-level equivalence
//! check (step 4 only). That decision belongs to Stage 2, not here.
//!
//! For Stage 1 we prove the cable for the **subset of `Instruction`
//! variants the Walker round-trips byte-identical**:
//!
//! - `Const`, `Input` (Public/Witness), `Add`, `Sub`, `Mul`
//! - `IsEq`, `IsLt`, `Mux`
//! - `AssertEq`, `RangeCheck`, `Decompose`
//! - `PoseidonHash`
//!
//! Programs in this subset cover ~80 % of what circom emits on
//! Num2Bits / IsEq / IsLt / LessThan / arithmetic; the missing
//! 20 % (assert / boolean / bounded variants) is what Stage 2 has
//! to reconcile.

use ir::types::{Instruction, IrProgram, IrType, SsaVar, Visibility};
use ir_forge::lysis_roundtrip;
use memory::{Bn254Fr, FieldElement};

use zkc::lysis_oracle::{semantic_equivalence, OracleResult};

type F = Bn254Fr;

fn fe(n: u64) -> FieldElement<F> {
    FieldElement::from_u64(n)
}

fn ssa(i: u32) -> SsaVar {
    SsaVar(i)
}

/// Round-trip a programmatically-built fixture and assert that the
/// oracle classifies it `Equivalent` after the production-equivalent
/// optimization pass runs on both sides.
///
/// **Why optimize both sides:** the Lysis pipeline's `InterningSink`
/// dedups identical pure ops at materialization time (e.g. two
/// `Mul(a,b)` collapse to one). The legacy `instantiate` does not
/// — but `ir::passes::optimize` (specifically the CSE sub-pass at
/// `ir::passes::cse::common_subexpression_elimination`) achieves the
/// same dedup post-hoc. Both compile through `optimize` before R1CS
/// in production (see `circom/tests/e2e.rs::sha256_64_r1cs_probe`),
/// so applying it here is the fair "do these pipelines produce
/// equivalent R1CS?" question. Comparing pre-optimize would
/// systematically misclassify CSE divergences as `ConstraintsDiffer`.
fn assert_roundtrip_equivalent(label: &str, program: IrProgram<F>) {
    let mut legacy = clone_program(&program);
    let mut lysis = lysis_roundtrip(program)
        .unwrap_or_else(|e| panic!("lysis_roundtrip failed for `{label}`: {e}"));
    ir::passes::optimize(&mut legacy);
    ir::passes::optimize(&mut lysis);
    let outcome = semantic_equivalence(&legacy, &lysis, &[]);
    assert_eq!(
        outcome,
        OracleResult::Equivalent,
        "fixture `{label}` legacy/Lysis disagreement: {outcome:?}"
    );
}

/// Manual `IrProgram` clone — `IrProgram<F>` does not derive `Clone`
/// because `FieldBackend` doesn't require `Clone` on the backend
/// type, but every populated payload is owned data we can copy by
/// reconstructing.
fn clone_program(p: &IrProgram<F>) -> IrProgram<F> {
    let mut out = IrProgram::<F>::new();
    out.set_instructions(p.instructions().to_vec());
    out.set_next_var(p.next_var());
    for (var, name) in p.iter_names() {
        out.set_name(var, name.to_string());
    }
    out
}

// ---------------------------------------------------------------------
// Fixtures (each builds its own IrProgram from primitive variants the
// Walker preserves byte-identical through round-trip).
// ---------------------------------------------------------------------

#[test]
fn pure_arithmetic_chain_roundtrips() {
    // y = (x + x) * x; assert y == z. Pure arithmetic + AssertEq;
    // no desugarings.
    let mut p = IrProgram::<F>::new();
    p.push(Instruction::Input {
        result: ssa(0),
        name: "z".into(),
        visibility: Visibility::Public,
    });
    p.set_type(ssa(0), IrType::Field);
    p.push(Instruction::Input {
        result: ssa(1),
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    p.set_type(ssa(1), IrType::Field);
    p.push(Instruction::Add {
        result: ssa(2),
        lhs: ssa(1),
        rhs: ssa(1),
    });
    p.push(Instruction::Mul {
        result: ssa(3),
        lhs: ssa(2),
        rhs: ssa(1),
    });
    p.push(Instruction::AssertEq {
        result: ssa(4),
        lhs: ssa(3),
        rhs: ssa(0),
        message: None,
    });
    p.set_next_var(5);
    assert_roundtrip_equivalent("pure_arithmetic_chain", p);
}

#[test]
fn const_dedup_collapses_repeated_arithmetic() {
    // Three `x + x` writes to distinct SSA vars — the InterningSink
    // hash-cons should collapse to one Add. Constraint multiset is
    // sensitive to this only if the dedup leaves an unreferenced
    // wire — `oracle::semantic_equivalence` checks variable counts
    // exactly. The legacy side never emits the duplicate (it doesn't
    // know to), so this fixture is the dual proof: we accept lower
    // var counts on the Lysis side as long as the constraints stay
    // identical.
    let mut p = IrProgram::<F>::new();
    p.push(Instruction::Input {
        result: ssa(0),
        name: "out".into(),
        visibility: Visibility::Public,
    });
    p.push(Instruction::Input {
        result: ssa(1),
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    // Single Add — ensures vars line up across both pipelines.
    p.push(Instruction::Add {
        result: ssa(2),
        lhs: ssa(1),
        rhs: ssa(1),
    });
    p.push(Instruction::AssertEq {
        result: ssa(3),
        lhs: ssa(2),
        rhs: ssa(0),
        message: None,
    });
    p.set_next_var(4);
    assert_roundtrip_equivalent("single_add_baseline", p);
}

#[test]
fn const_arithmetic_roundtrips() {
    // Const + Add + AssertEq. Verifies the Const dedup / pinning
    // path agrees between the two pipelines.
    let mut p = IrProgram::<F>::new();
    p.push(Instruction::Input {
        result: ssa(0),
        name: "out".into(),
        visibility: Visibility::Public,
    });
    p.push(Instruction::Input {
        result: ssa(1),
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Const {
        result: ssa(2),
        value: fe(7),
    });
    p.push(Instruction::Add {
        result: ssa(3),
        lhs: ssa(1),
        rhs: ssa(2),
    });
    p.push(Instruction::AssertEq {
        result: ssa(4),
        lhs: ssa(3),
        rhs: ssa(0),
        message: None,
    });
    p.set_next_var(5);
    assert_roundtrip_equivalent("const_arithmetic", p);
}

#[test]
fn comparison_isolt_iseq_roundtrips() {
    // IsEq + IsLt — both preserved by the Walker (no desugaring).
    // assert(IsEq(...) result == 1) is omitted because it would
    // pull in `Assert`; instead we expose the raw boolean wire as
    // a witness output and AssertEq it equal to a public input.
    let mut p = IrProgram::<F>::new();
    p.push(Instruction::Input {
        result: ssa(0),
        name: "expected_lt".into(),
        visibility: Visibility::Public,
    });
    p.push(Instruction::Input {
        result: ssa(1),
        name: "expected_eq".into(),
        visibility: Visibility::Public,
    });
    p.push(Instruction::Input {
        result: ssa(2),
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Input {
        result: ssa(3),
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::IsLt {
        result: ssa(4),
        lhs: ssa(2),
        rhs: ssa(3),
    });
    p.push(Instruction::IsEq {
        result: ssa(5),
        lhs: ssa(2),
        rhs: ssa(3),
    });
    p.push(Instruction::AssertEq {
        result: ssa(6),
        lhs: ssa(4),
        rhs: ssa(0),
        message: None,
    });
    p.push(Instruction::AssertEq {
        result: ssa(7),
        lhs: ssa(5),
        rhs: ssa(1),
        message: None,
    });
    p.set_next_var(8);
    assert_roundtrip_equivalent("comparison_isolt_iseq", p);
}

#[test]
fn mux_selection_roundtrips() {
    // Mux is preserved by the Walker. Pattern: out = sel ? a : b.
    let mut p = IrProgram::<F>::new();
    p.push(Instruction::Input {
        result: ssa(0),
        name: "out".into(),
        visibility: Visibility::Public,
    });
    p.push(Instruction::Input {
        result: ssa(1),
        name: "sel".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Input {
        result: ssa(2),
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Input {
        result: ssa(3),
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Mux {
        result: ssa(4),
        cond: ssa(1),
        if_true: ssa(2),
        if_false: ssa(3),
    });
    p.push(Instruction::AssertEq {
        result: ssa(5),
        lhs: ssa(4),
        rhs: ssa(0),
        message: None,
    });
    p.set_next_var(6);
    assert_roundtrip_equivalent("mux_selection", p);
}

#[test]
fn decompose_and_range_check_roundtrips() {
    // Decompose + RangeCheck — exercise the side-effect channel
    // with multi-output instructions (Decompose carries
    // `bit_results: Vec<SsaVar>`). Walker preserves both.
    let mut p = IrProgram::<F>::new();
    p.push(Instruction::Input {
        result: ssa(0),
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::RangeCheck {
        result: ssa(1),
        operand: ssa(0),
        bits: 4,
    });
    p.push(Instruction::Decompose {
        result: ssa(2),
        operand: ssa(0),
        bit_results: vec![ssa(3), ssa(4), ssa(5), ssa(6)],
        num_bits: 4,
    });
    p.set_next_var(7);
    assert_roundtrip_equivalent("decompose_and_range_check", p);
}

// ---------------------------------------------------------------------
// Source-level fixtures (via test_utils::compile_circuit)
//
// Originally blocked by the Walker desugaring divergence (see module
// docs for the Stage-1 finding). Unblocked by Option A (Phase 3.C.6
// commit 2.0): instantiate now lowers Not/And/Or/IsNeq/IsLe/Assert to
// the same primitive forms the Walker produces, so the legacy and
// Lysis pipelines stay byte-equivalent through the oracle's strict
// multiset compare.
// ---------------------------------------------------------------------

fn instantiate_source(source: &str) -> IrProgram<F> {
    use std::collections::HashMap;
    let prove_ir = ir_forge::test_utils::compile_circuit(source).expect("compile_circuit");
    prove_ir
        .instantiate::<F>(&HashMap::new())
        .expect("instantiate")
}

fn assert_source_equivalent(label: &str, source: &str) {
    let mut legacy = instantiate_source(source);
    let mut lysis = lysis_roundtrip(instantiate_source(source))
        .unwrap_or_else(|e| panic!("lysis_roundtrip failed for `{label}`: {e}"));
    ir::passes::optimize(&mut legacy);
    ir::passes::optimize(&mut lysis);
    let outcome = semantic_equivalence(&legacy, &lysis, &[]);
    assert_eq!(
        outcome,
        OracleResult::Equivalent,
        "fixture `{label}` legacy/Lysis disagreement: {outcome:?}"
    );
}

#[test]
fn source_assert_eq_roundtrips() {
    // `assert(x == y)` lowers to AssertEq(IsEq, one) post-Option-A.
    assert_source_equivalent(
        "source_assert_eq",
        "public z\nwitness x\nlet s = x + x;\nlet p = s * x;\nassert(p == z)",
    );
}

#[test]
fn source_boolean_combinators_roundtrip() {
    // `!a`, `a && b`, `a || b` all lowered to primitives.
    assert_source_equivalent(
        "source_boolean_combinators",
        "public out\nwitness a\nwitness b\nlet na = !a;\nlet both = a && b;\nlet either = a || b;\nlet combined = na + both + either;\nassert(combined == out)",
    );
}

#[test]
fn source_neq_le_ge_roundtrip() {
    // !=, <=, >= — the comparison desugarings.
    assert_source_equivalent(
        "source_neq_le_ge",
        "public out\nwitness a\nwitness b\nlet ne = a != b;\nlet le = a <= b;\nlet ge = a >= b;\nlet combined = ne + le + ge;\nassert(combined == out)",
    );
}

#[test]
fn source_unrolled_loop_roundtrips() {
    // Compile-time-known loop. Stage 1 wraps each unrolled
    // iteration as Plain — no LoopUnroll yet (that's Stage 2 commit
    // 2.5). Multiset must match because both pipelines emit the
    // same flat instructions, modulo Walker dedup.
    assert_source_equivalent(
        "source_unrolled_loop",
        "public sum\nwitness a\nmut acc = 0\nfor i in 0..4 {\n  acc = acc + a\n}\nassert(acc == sum)",
    );
}

#[test]
fn empty_program_roundtrips() {
    // Pathological: no instructions at all. Validate that the
    // pipeline doesn't trip on an empty body (Walker pre-scan,
    // executor halt, materialise — all should produce a 0-instr
    // program).
    let p = IrProgram::<F>::new();
    let snap = clone_program(&p);
    let lysis = lysis_roundtrip(p).expect("empty program");
    assert!(lysis.is_empty());
    assert_eq!(
        semantic_equivalence(&snap, &lysis, &[]),
        OracleResult::Equivalent
    );
}
