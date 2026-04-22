//! Week-1 Phase 3.A exit criterion — round-trip smoke test.
//!
//! Builds a Num2Bits(4)-shaped Lysis program via `ProgramBuilder`,
//! runs it through the full pipeline `encode → decode → validate →
//! execute with InterningSink → materialize_interning_sink`, and
//! asserts the resulting `Vec<Instruction<F>>` has the shape a
//! real Num2Bits(4) lowering would produce.
//!
//! This is NOT a semantics test — no R1CS compilation, no witness
//! solving, no oracle. It proves the pipeline "Lysis bytecode →
//! `Vec<ir::Instruction>`" is live, which is the prerequisite for
//! Phase 3.B (the actual ProveIR-extended → Lysis lifter).
//!
//! ## Num2Bits(4) reference shape
//!
//! Canonical circom-style Num2Bits(4) emits, roughly:
//!
//! ```text
//!   in       : Input (witness)
//!   bit[0..4]: Decompose(in, 4) — 4 fresh wires + the operand alias
//!   one      : Const(1)
//!
//!   // boolean constraints: bit[i] * (1 - bit[i]) == 0  →  bit[i] == bit[i] * bit[i]
//!   for i in 0..4:
//!     AssertEq(bit[i], bit[i] * bit[i])
//!
//!   // sum == in
//!   (omitted from the smoke test; Decompose implies the sum constraint
//!    downstream in R1CS. We check the shape up to the asserts.)
//! ```

use artik::FieldFamily;
use ir::prove_ir::lysis_materialize::materialize_interning_sink;
use ir::{Instruction, SsaVar};
use lysis::{
    bytecode::validate, decode, encode, execute, InterningSink, LysisConfig, ProgramBuilder,
    Visibility,
};
use memory::{Bn254Fr, FieldElement};

fn fe(x: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([x, 0, 0, 0])
}

fn build_num2bits_4_skeleton() -> lysis::Program<Bn254Fr> {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    // Const pool: "in" (string, index 0), field 1 (index 1).
    b.intern_string("in");
    b.intern_field(fe(1));

    // r0 = Input("in", Witness)
    // Decompose r0 into 4 bits laid out in r1..r4.
    // r5 = Const(1)
    // for each bit i in 1..=4:
    //   r(10+i) = bit_i * bit_i
    //   AssertEq(bit_i, r(10+i))
    b.load_input(0, 0, Visibility::Witness)
        .emit_decompose(1, 0, 4)
        .load_const(5, 1)
        // boolean checks per bit
        .emit_mul(11, 1, 1) // bit0 * bit0
        .emit_assert_eq(1, 11) // bit0 == bit0^2
        .emit_mul(12, 2, 2)
        .emit_assert_eq(2, 12)
        .emit_mul(13, 3, 3)
        .emit_assert_eq(3, 13)
        .emit_mul(14, 4, 4)
        .emit_assert_eq(4, 14)
        .halt();
    b.finish()
}

fn run_through_lysis(program: &lysis::Program<Bn254Fr>) -> Vec<Instruction<Bn254Fr>> {
    let bytes = encode(program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    validate(&decoded, &LysisConfig::default()).expect("validate");
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink).expect("execute");
    materialize_interning_sink(sink)
}

#[test]
fn num2bits_4_round_trip_yields_ir_instructions() {
    let program = build_num2bits_4_skeleton();
    let instrs = run_through_lysis(&program);

    // The materialize path must produce a non-empty Vec of
    // `ir::Instruction<F>` — proves the bridge is wired end-to-end.
    assert!(!instrs.is_empty(), "materialize produced no instructions");
}

#[test]
fn num2bits_4_contains_expected_variants() {
    let program = build_num2bits_4_skeleton();
    let instrs = run_through_lysis(&program);

    let counts = count_variants(&instrs);

    // One Input wire (the operand).
    assert_eq!(counts.input, 1, "expected 1 Input, got {counts:?}");
    // One Decompose (into 4 bits).
    assert_eq!(counts.decompose, 1, "expected 1 Decompose, got {counts:?}");
    // One Const (the literal 1).
    assert_eq!(counts.const_, 1, "expected 1 Const, got {counts:?}");
    // Four Muls — one per boolean check, each deduped by structural
    // key (bit_i * bit_i differs per i, so no dedup here).
    assert_eq!(counts.mul, 4, "expected 4 Muls, got {counts:?}");
    // Four AssertEqs — side-effect channel never dedups.
    assert_eq!(counts.assert_eq, 4, "expected 4 AssertEqs, got {counts:?}");
}

#[test]
fn num2bits_4_decompose_binds_four_bit_results() {
    let program = build_num2bits_4_skeleton();
    let instrs = run_through_lysis(&program);

    let dec = instrs
        .iter()
        .find_map(|i| match i {
            Instruction::Decompose {
                bit_results,
                num_bits,
                ..
            } => Some((bit_results.len(), *num_bits)),
            _ => None,
        })
        .expect("Decompose present");
    assert_eq!(dec.0, 4, "expected 4 bit_results");
    assert_eq!(dec.1, 4, "num_bits should match");
}

#[test]
fn num2bits_4_topological_order_preserved() {
    // Every instruction's operands must have appeared as a prior
    // `result` — standard topological invariant.
    let program = build_num2bits_4_skeleton();
    let instrs = run_through_lysis(&program);

    let mut defined: std::collections::HashSet<SsaVar> = std::collections::HashSet::new();
    for inst in &instrs {
        for op in operands(inst) {
            assert!(
                defined.contains(&op),
                "operand {op:?} used before definition in\n{inst:?}"
            );
        }
        defined.insert(inst.result_var());
        for extra in inst.extra_result_vars() {
            defined.insert(*extra);
        }
    }
}

#[test]
fn num2bits_4_materialize_is_deterministic() {
    // Two independent runs must produce identical materialized Vecs.
    let program = build_num2bits_4_skeleton();
    let a = run_through_lysis(&program);
    let b = run_through_lysis(&program);

    assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(format!("{x:?}"), format!("{y:?}"));
    }
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

#[derive(Debug, Default)]
struct VariantCounts {
    input: usize,
    const_: usize,
    add: usize,
    mul: usize,
    decompose: usize,
    assert_eq: usize,
    other: usize,
}

fn count_variants(instrs: &[Instruction<Bn254Fr>]) -> VariantCounts {
    let mut c = VariantCounts::default();
    for i in instrs {
        match i {
            Instruction::Input { .. } => c.input += 1,
            Instruction::Const { .. } => c.const_ += 1,
            Instruction::Add { .. } => c.add += 1,
            Instruction::Mul { .. } => c.mul += 1,
            Instruction::Decompose { .. } => c.decompose += 1,
            Instruction::AssertEq { .. } => c.assert_eq += 1,
            _ => c.other += 1,
        }
    }
    c
}

fn operands(inst: &Instruction<Bn254Fr>) -> Vec<SsaVar> {
    use Instruction as I;
    match inst {
        I::Const { .. } | I::Input { .. } => vec![],
        I::Add { lhs, rhs, .. }
        | I::Sub { lhs, rhs, .. }
        | I::Mul { lhs, rhs, .. }
        | I::Div { lhs, rhs, .. }
        | I::IsEq { lhs, rhs, .. }
        | I::IsNeq { lhs, rhs, .. }
        | I::IsLt { lhs, rhs, .. }
        | I::IsLe { lhs, rhs, .. }
        | I::And { lhs, rhs, .. }
        | I::Or { lhs, rhs, .. }
        | I::AssertEq { lhs, rhs, .. } => vec![*lhs, *rhs],
        I::Neg { operand, .. }
        | I::Not { operand, .. }
        | I::Assert { operand, .. }
        | I::RangeCheck { operand, .. }
        | I::Decompose { operand, .. } => vec![*operand],
        I::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => vec![*cond, *if_true, *if_false],
        I::PoseidonHash { left, right, .. } => vec![*left, *right],
        I::IsLtBounded { lhs, rhs, .. } | I::IsLeBounded { lhs, rhs, .. } => vec![*lhs, *rhs],
        I::IntDiv { lhs, rhs, .. } | I::IntMod { lhs, rhs, .. } => vec![*lhs, *rhs],
        I::WitnessCall { inputs, .. } => inputs.clone(),
    }
}
