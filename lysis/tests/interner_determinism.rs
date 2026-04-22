//! Integration tests for Phase 2's two structural invariants.
//!
//! 1. **Structural dedup**: running a program through an
//!    [`InterningSink`] collapses equivalent pure nodes; the
//!    materialized Vec is strictly smaller than the no-intern
//!    [`StubSink`] baseline whenever the program contains structural
//!    duplication. Side-effects survive count-intact.
//!
//! 2. **Determinism**: two independent runs of the same program —
//!    each with its own fresh `InterningSink` — produce identical
//!    output (same NodeIds, same order, same cached hashes). This
//!    is what the fixed-key SipHash-2-4 buys us; it is the
//!    invariant the Phase 2 oracle harness depends on.

use artik::FieldFamily;
use lysis::{
    decode, encode, execute, InstructionKind, InterningSink, IrSink, LysisConfig, NodeId,
    ProgramBuilder, StubSink,
};
use memory::field::{Bn254Fr, FieldElement};

fn fe(x: u64) -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([x, 0, 0, 0])
}

fn b() -> ProgramBuilder<Bn254Fr> {
    ProgramBuilder::new(FieldFamily::BnLike256)
}

/// Run a program through the full pipeline with a user-supplied sink.
/// Returns the sink for inspection.
fn run_with_intern(program: &lysis::Program<Bn254Fr>) -> InterningSink<Bn254Fr> {
    let bytes = encode(program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    lysis::bytecode::validate(&decoded, &LysisConfig::default()).expect("validate");
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink).expect("execute");
    sink
}

fn run_with_stub(program: &lysis::Program<Bn254Fr>) -> StubSink<Bn254Fr> {
    let bytes = encode(program);
    let decoded = decode::<Bn254Fr>(&bytes).expect("decode");
    lysis::bytecode::validate(&decoded, &LysisConfig::default()).expect("validate");
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink).expect("execute");
    sink
}

// ---------------------------------------------------------------------
// Structural dedup.
// ---------------------------------------------------------------------

#[test]
fn identical_emit_add_collapses_to_one_node() {
    // Emit the same (Add r0 r1) six times. StubSink records 6 Adds;
    // InterningSink collapses to 1.
    let mut builder = b();
    builder.intern_field(fe(1));
    builder.intern_field(fe(2));
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_add(2, 0, 1)
        .emit_add(3, 0, 1)
        .emit_add(4, 0, 1)
        .emit_add(5, 0, 1)
        .emit_add(6, 0, 1)
        .emit_add(7, 0, 1)
        .halt();
    let program = builder.finish();

    let stub_count = run_with_stub(&program).count();
    let intern = run_with_intern(&program);

    // Stub: 2 Consts + 6 Adds = 8 emissions.
    assert_eq!(stub_count, 8);
    // Intern: 2 Consts + 1 Add (deduped).
    assert_eq!(intern.pure_len(), 3);
    assert_eq!(intern.effect_len(), 0);
}

#[test]
fn load_const_of_same_value_is_deduped() {
    // Two LoadConst pointing at the same const-pool entry both emit
    // Const(7). Stub → 2. Intern → 1.
    let mut builder = b();
    builder.intern_field(fe(7));
    builder.load_const(0, 0).load_const(1, 0).halt();
    let program = builder.finish();

    let stub = run_with_stub(&program);
    let intern = run_with_intern(&program);

    assert_eq!(stub.count(), 2);
    assert_eq!(intern.pure_len(), 1);
}

#[test]
fn side_effects_are_not_deduped_under_intern() {
    // Two identical AssertEqs: stub keeps 2, intern also keeps 2
    // (different EffectIds, not interned).
    let mut builder = b();
    builder.intern_field(fe(1));
    builder.intern_field(fe(2));
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_assert_eq(0, 1)
        .emit_assert_eq(0, 1)
        .halt();
    let program = builder.finish();

    let stub = run_with_stub(&program);
    let intern = run_with_intern(&program);

    assert_eq!(stub.count(), 4); // 2 Consts + 2 AssertEqs
    assert_eq!(intern.pure_len(), 2);
    assert_eq!(intern.effect_len(), 2);
}

#[test]
fn range_checks_stay_distinct_under_intern() {
    let mut builder = b();
    builder.intern_string("x");
    builder
        .load_input(0, 0, lysis::Visibility::Witness)
        .emit_range_check(0, 8)
        .emit_range_check(0, 8)
        .halt();
    let program = builder.finish();

    let stub = run_with_stub(&program);
    let intern = run_with_intern(&program);

    // Stub: 1 Input + 2 RangeChecks.
    assert_eq!(stub.count(), 3);
    // Intern: 1 Input (side-effect) + 2 RangeChecks (side-effect) = 3 in effect channel, 0 in pure.
    assert_eq!(intern.pure_len(), 0);
    assert_eq!(intern.effect_len(), 3);
}

// ---------------------------------------------------------------------
// Materialization round-trip.
// ---------------------------------------------------------------------

#[test]
fn materialize_preserves_operand_ordering() {
    let mut builder = b();
    builder.intern_field(fe(1));
    builder.intern_field(fe(2));
    builder
        .load_const(0, 0)
        .load_const(1, 1)
        .emit_add(2, 0, 1)
        .emit_mul(3, 2, 2)
        .halt();
    let program = builder.finish();

    let intern = run_with_intern(&program);
    let flat = intern.materialize();

    // Topological: for each instruction, every operand NodeId must
    // have appeared as a `result` in a prior instruction.
    let mut defined: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    for instr in &flat {
        for op in operands(instr) {
            assert!(
                defined.contains(&op),
                "operand {op:?} referenced before definition in materialized output"
            );
        }
        defined.insert(instr.result());
    }
}

fn operands(instr: &InstructionKind<Bn254Fr>) -> Vec<NodeId> {
    use InstructionKind as K;
    match instr {
        K::Const { .. } | K::Input { .. } => vec![],
        K::Add { lhs, rhs, .. }
        | K::Sub { lhs, rhs, .. }
        | K::Mul { lhs, rhs, .. }
        | K::Div { lhs, rhs, .. }
        | K::IsEq { lhs, rhs, .. }
        | K::IsNeq { lhs, rhs, .. }
        | K::IsLt { lhs, rhs, .. }
        | K::IsLe { lhs, rhs, .. }
        | K::And { lhs, rhs, .. }
        | K::Or { lhs, rhs, .. }
        | K::AssertEq { lhs, rhs, .. } => vec![*lhs, *rhs],
        K::Neg { operand, .. }
        | K::Not { operand, .. }
        | K::Assert { operand, .. }
        | K::RangeCheck { operand, .. }
        | K::Decompose { operand, .. } => vec![*operand],
        K::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => vec![*cond, *if_true, *if_false],
        K::PoseidonHash { left, right, .. } => vec![*left, *right],
        K::IsLtBounded { lhs, rhs, .. } | K::IsLeBounded { lhs, rhs, .. } => vec![*lhs, *rhs],
        K::IntDiv { lhs, rhs, .. } | K::IntMod { lhs, rhs, .. } => vec![*lhs, *rhs],
        K::WitnessCall { inputs, .. } => inputs.clone(),
    }
}

// ---------------------------------------------------------------------
// Determinism: two runs produce identical output.
// ---------------------------------------------------------------------

#[test]
fn two_runs_produce_identical_materialized_vec() {
    let program = {
        let mut builder = b();
        builder.intern_field(fe(1));
        builder.intern_field(fe(2));
        builder.intern_field(fe(3));
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .load_const(2, 2)
            .emit_add(3, 0, 1)
            .emit_mul(4, 3, 2)
            .emit_add(5, 0, 1) // dup of r3
            .halt();
        builder.finish()
    };

    let flat1 = run_with_intern(&program).materialize();
    let flat2 = run_with_intern(&program).materialize();

    assert_eq!(flat1.len(), flat2.len());
    for (a, b) in flat1.iter().zip(flat2.iter()) {
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }
}

#[test]
fn two_runs_assign_identical_node_ids() {
    // Structural dedup means node identity is a function of
    // structural shape, not insertion happenstance. Two separate
    // runs should assign the same NodeIds to equivalent ops.
    let program = {
        let mut builder = b();
        builder.intern_field(fe(1));
        builder
            .load_const(0, 0)
            .emit_add(1, 0, 0)
            .emit_mul(2, 1, 1)
            .halt();
        builder.finish()
    };

    let intern1 = run_with_intern(&program);
    let intern2 = run_with_intern(&program);

    assert_eq!(intern1.pure_len(), intern2.pure_len());
    assert_eq!(intern1.effect_len(), intern2.effect_len());

    // The interner's insertion-order iteration yields identical (id, key)
    // pairs — ids are monotonic in insertion order, and structural dedup
    // makes insertion order deterministic.
    let list1: Vec<(u32, String)> = intern1
        .interner()
        .iter_pure()
        .map(|(id, key, _)| (id.raw(), format!("{key:?}")))
        .collect();
    let list2: Vec<(u32, String)> = intern2
        .interner()
        .iter_pure()
        .map(|(id, key, _)| (id.raw(), format!("{key:?}")))
        .collect();
    assert_eq!(list1, list2);
}

#[test]
fn cached_hashes_are_stable_across_runs() {
    // The NodeMeta.hash cached at insertion must agree between
    // independent runs — that's what lets the oracle compare two
    // interner states by hash alone.
    let program = {
        let mut builder = b();
        builder.intern_field(fe(42));
        builder.load_const(0, 0).emit_neg(1, 0).halt();
        builder.finish()
    };

    let intern1 = run_with_intern(&program);
    let intern2 = run_with_intern(&program);

    let hashes1: Vec<u64> = intern1
        .interner()
        .iter_pure()
        .map(|(_, _, meta)| meta.hash)
        .collect();
    let hashes2: Vec<u64> = intern2
        .interner()
        .iter_pure()
        .map(|(_, _, meta)| meta.hash)
        .collect();

    assert_eq!(hashes1, hashes2);
}
