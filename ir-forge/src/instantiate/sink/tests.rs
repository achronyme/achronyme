use super::*;
use memory::{Bn254Fr, FieldElement};

type F = Bn254Fr;

fn fe(n: u64) -> FieldElement<F> {
    FieldElement::from_u64(n)
}

#[test]
fn extended_sink_wraps_each_inst_as_plain() {
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    let v0 = sink.fresh_var();
    sink.push_inst(
        Instruction::Const {
            result: v0,
            value: fe(3),
        },
        None,
    );
    sink.set_type(v0, IrType::Field);

    assert_eq!(body.len(), 1);
    assert!(matches!(body[0], ExtendedInstruction::Plain(_)));
    assert_eq!(metadata.len(), 0, "metadata.instructions stays empty");
    assert_eq!(metadata.next_var(), 1);
    assert_eq!(metadata.get_type(SsaVar(0)), Some(IrType::Field));
}

#[test]
fn extended_sink_var_counter_advances_per_fresh_var() {
    // Equivalent emission program: two fresh vars + Const + Add.
    // The metadata IrProgram skeleton is the var-counter source of
    // truth; `body` carries the actual instructions wrapped as Plain.
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    let v0 = sink.fresh_var();
    let v1 = sink.fresh_var();
    sink.push_inst(
        Instruction::Const {
            result: v0,
            value: fe(0),
        },
        None,
    );
    sink.push_inst(
        Instruction::Add {
            result: v1,
            lhs: v0,
            rhs: v0,
        },
        None,
    );

    assert_eq!(metadata.next_var(), 2);
    assert_eq!(body.len(), 2);
}

#[test]
fn extended_sink_emits_loop_unroll_with_symbolic_iter_var() {
    // Direct sink-level test: simulate what emit_range_loop will
    // do once wired in. The body emits one Mul that references
    // iter_var symbolically; finalising should produce a single
    // LoopUnroll containing exactly that one Plain instruction.
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    // Allocate a symbolic iter_var.
    let iter_var = sink.fresh_var();
    // Begin a symbolic loop scope.
    sink.begin_symbolic_loop();
    // Emit one body instruction that refs iter_var.
    let mul = sink.fresh_var();
    sink.push_inst(
        Instruction::Mul {
            result: mul,
            lhs: iter_var,
            rhs: iter_var,
        },
        None,
    );
    // Finalise.
    sink.finish_symbolic_loop(iter_var, 0, 4);

    // Outer body should have exactly one LoopUnroll node.
    assert_eq!(body.len(), 1, "one LoopUnroll in outer body");
    match &body[0] {
        ExtendedInstruction::LoopUnroll {
            iter_var: iv,
            start,
            end,
            body: loop_body,
        } => {
            assert_eq!(*iv, iter_var);
            assert_eq!(*start, 0);
            assert_eq!(*end, 4);
            assert_eq!(loop_body.len(), 1, "one Plain Mul inside the loop");
            match &loop_body[0] {
                ExtendedInstruction::Plain(Instruction::Mul { lhs, rhs, .. }) => {
                    assert_eq!(*lhs, iter_var);
                    assert_eq!(*rhs, iter_var);
                }
                other => panic!("expected Plain(Mul), got {other:?}"),
            }
        }
        other => panic!("expected LoopUnroll, got {other:?}"),
    }
}

#[test]
fn extended_sink_handles_nested_loops() {
    // for i in 0..3 { for j in 0..2 { Mul(j, j) } }
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    let i = sink.fresh_var();
    sink.begin_symbolic_loop();

    let j = sink.fresh_var();
    sink.begin_symbolic_loop();

    let mul = sink.fresh_var();
    sink.push_inst(
        Instruction::Mul {
            result: mul,
            lhs: j,
            rhs: j,
        },
        None,
    );

    sink.finish_symbolic_loop(j, 0, 2);
    sink.finish_symbolic_loop(i, 0, 3);

    assert_eq!(body.len(), 1, "one outer LoopUnroll");
    match &body[0] {
        ExtendedInstruction::LoopUnroll {
            body: outer_body, ..
        } => {
            assert_eq!(outer_body.len(), 1, "outer body has one inner LoopUnroll");
            assert!(matches!(
                outer_body[0],
                ExtendedInstruction::LoopUnroll { .. }
            ));
        }
        _ => panic!("expected outer LoopUnroll"),
    }
}

#[test]
fn extended_sink_pushes_symbolic_indexed_effect() {
    // Simulate what `emit_let_indexed_symbolic` does inside a
    // symbolic loop body: begin loop, push effect, finish loop.
    // The resulting ExtendedInstruction tree must wrap the effect
    // inside the LoopUnroll body, not the outer scope.
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    let iter_var = sink.fresh_var();
    let slot0 = sink.fresh_var();
    let slot1 = sink.fresh_var();
    let value_var = sink.fresh_var();

    sink.begin_symbolic_loop();
    sink.push_symbolic_indexed_effect(
        IndexedEffectKind::Let,
        vec![slot0, slot1],
        iter_var,
        Some(value_var),
        None,
    );
    sink.finish_symbolic_loop(iter_var, 0, 2);

    assert_eq!(body.len(), 1, "one outer LoopUnroll");
    match &body[0] {
        ExtendedInstruction::LoopUnroll { body: inner, .. } => {
            assert_eq!(inner.len(), 1);
            match &inner[0] {
                ExtendedInstruction::SymbolicIndexedEffect {
                    kind,
                    array_slots,
                    index_var,
                    value_var: vv,
                    ..
                } => {
                    assert_eq!(*kind, IndexedEffectKind::Let);
                    assert_eq!(array_slots, &vec![slot0, slot1]);
                    assert_eq!(*index_var, iter_var);
                    assert_eq!(*vv, Some(value_var));
                }
                other => panic!("expected SymbolicIndexedEffect, got {other:?}"),
            }
        }
        other => panic!("expected LoopUnroll, got {other:?}"),
    }
}

#[test]
fn extended_sink_pushes_symbolic_array_read() {
    // Mirror of the write-side test: simulate `emit_array_index_
    // symbolic` inside a symbolic loop body.
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    let iter_var = sink.fresh_var();
    let slot0 = sink.fresh_var();
    let slot1 = sink.fresh_var();
    let result_var = sink.fresh_var();

    sink.begin_symbolic_loop();
    sink.push_symbolic_array_read(result_var, vec![slot0, slot1], iter_var, None);
    sink.finish_symbolic_loop(iter_var, 0, 2);

    assert_eq!(body.len(), 1, "one outer LoopUnroll");
    match &body[0] {
        ExtendedInstruction::LoopUnroll { body: inner, .. } => {
            assert_eq!(inner.len(), 1);
            match &inner[0] {
                ExtendedInstruction::SymbolicArrayRead {
                    result_var: rv,
                    array_slots,
                    index_var,
                    ..
                } => {
                    assert_eq!(*rv, result_var);
                    assert_eq!(array_slots, &vec![slot0, slot1]);
                    assert_eq!(*index_var, iter_var);
                }
                other => panic!("expected SymbolicArrayRead, got {other:?}"),
            }
        }
        other => panic!("expected LoopUnroll, got {other:?}"),
    }
}

#[test]
fn extended_sink_pushes_symbolic_shift() {
    // Mirror of the read- and write-side tests: simulate the
    // emit-site arm in `instantiate/exprs.rs` for `ShiftR`/`ShiftL`
    // when the shift amount is loop-iter-dependent.
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);

    let iter_var = sink.fresh_var();
    let operand_var = sink.fresh_var();
    let result_var = sink.fresh_var();

    sink.begin_symbolic_loop();
    sink.push_symbolic_shift(
        result_var,
        operand_var,
        iter_var,
        32,
        ShiftDirection::Right,
        None,
    );
    sink.finish_symbolic_loop(iter_var, 0, 32);

    assert_eq!(body.len(), 1, "one outer LoopUnroll");
    match &body[0] {
        ExtendedInstruction::LoopUnroll { body: inner, .. } => {
            assert_eq!(inner.len(), 1);
            match &inner[0] {
                ExtendedInstruction::SymbolicShift {
                    result_var: rv,
                    operand_var: ov,
                    shift_var,
                    num_bits,
                    direction,
                    ..
                } => {
                    assert_eq!(*rv, result_var);
                    assert_eq!(*ov, operand_var);
                    assert_eq!(*shift_var, iter_var);
                    assert_eq!(*num_bits, 32);
                    assert_eq!(*direction, ShiftDirection::Right);
                }
                other => panic!("expected SymbolicShift, got {other:?}"),
            }
        }
        other => panic!("expected LoopUnroll, got {other:?}"),
    }
}

#[test]
fn extended_sink_records_input_span_in_metadata() {
    let span = SpanRange::point(5, 5, 0);
    let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
    let mut metadata = IrProgram::<F>::new();
    let mut sink = ExtendedSink::new(&mut body, &mut metadata);
    sink.set_input_span("y".into(), span.clone());
    assert_eq!(metadata.get_input_span("y"), Some(&span));
}
