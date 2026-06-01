use super::loops::MUL_BODY_BYTES;
use super::*;

// -----------------------------------------------------------------
// InstantiateTemplate + TemplateOutput
// -----------------------------------------------------------------

/// Build a program that declares one 1-capture template, calls it
/// once, and halts. Returns (program, out_reg_index_in_root) so
/// the test can inspect the caller's register afterward.
fn program_with_one_template_call() -> Program<Bn254Fr> {
    use crate::bytecode::encoding::encode_opcode;
    use crate::header::LysisHeader;
    use crate::program::{Instr, Template};
    use crate::ConstPool;

    // Template body: EmitMul r1, r0, r0; TemplateOutput 0 from r1; Return.
    // Captures: r0 = value to square.
    // Frame size: 2.
    let mut buf = Vec::new();
    let mut body = Vec::new();

    // Append an opcode to both `buf` (for byte offsets) and
    // `body` (for the decoded-Instr representation the executor
    // walks).
    let emit = |op: Opcode, buf: &mut Vec<u8>, body: &mut Vec<Instr>| {
        let before = buf.len() as u32;
        encode_opcode(&op, buf);
        body.push(Instr {
            opcode: op,
            offset: before,
        });
    };

    // Root body:
    //   LoadConst r0, 0; r0 = 7 (the value to square)
    //   DefineTemplate 1, frame_size=2, n_params=1, body_offset=?, body_len=?
    //   InstantiateTemplate 1, captures=[r0], outputs=[r1]
    //   Halt
    //
    // Template body (placed after Halt):
    //   EmitMul r1, r0, r0
    //   TemplateOutput 0, r1
    //   Return

    emit(Opcode::LoadConst { dst: 0, idx: 0 }, &mut buf, &mut body);
    let define_template_offset = buf.len() as u32;
    emit(
        Opcode::DefineTemplate {
            template_id: 1,
            frame_size: 2,
            n_params: 1,
            body_offset: 0,
            body_len: 0,
        },
        &mut buf,
        &mut body,
    );
    emit(
        Opcode::InstantiateTemplate {
            template_id: 1,
            capture_regs: Box::new(vec![0]),
            output_regs: Box::new(vec![1]),
        },
        &mut buf,
        &mut body,
    );
    emit(Opcode::Halt, &mut buf, &mut body);
    let template_body_offset = buf.len() as u32;
    emit(
        Opcode::EmitMul {
            dst: 1,
            lhs: 0,
            rhs: 0,
        },
        &mut buf,
        &mut body,
    );
    emit(
        Opcode::TemplateOutput {
            output_idx: 0,
            src_reg: 1,
        },
        &mut buf,
        &mut body,
    );
    emit(Opcode::Return, &mut buf, &mut body);
    let template_body_end = buf.len() as u32;
    let template_body_len = template_body_end - template_body_offset;

    // Patch the DefineTemplate opcode in the body Vec with real
    // offsets so the executor's Program carries them.
    for instr in body.iter_mut() {
        if instr.offset == define_template_offset {
            if let Opcode::DefineTemplate {
                template_id,
                frame_size,
                n_params,
                ..
            } = instr.opcode
            {
                instr.opcode = Opcode::DefineTemplate {
                    template_id,
                    frame_size,
                    n_params,
                    body_offset: template_body_offset,
                    body_len: template_body_len,
                };
            }
        }
    }

    // Const pool: one field entry (7).
    let mut const_pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
    const_pool.push(crate::bytecode::ConstPoolEntry::Field(seven()));

    Program {
        header: LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0),
        const_pool,
        templates: vec![Template {
            id: 1,
            frame_size: 2,
            n_params: 1,
            body_offset: template_body_offset,
            body_len: template_body_len,
        }],
        body,
    }
}

#[test]
fn template_call_returns_to_caller_at_next_opcode() {
    let program = program_with_one_template_call();
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).unwrap();
    // Expect: 1 Const(7) in root + 1 Mul(r0, r0) in template body.
    assert_eq!(sink.count(), 2);
    assert!(matches!(
        sink.instructions()[0],
        InstructionKind::Const { .. }
    ));
    assert!(matches!(
        sink.instructions()[1],
        InstructionKind::Mul { .. }
    ));
}

/// Build a linear template chain: root `InstantiateTemplate(0)`
/// then `Halt`; template `i` (`i < n-1`) body is
/// `InstantiateTemplate(i+1)` then (optionally a `LoadConst`
/// *between*, making the call NON-tail) then `Return`; the leaf
/// template `n-1` is `LoadConst(0,0); Return` (its `Const(7)` in
/// the sink proves the chain reached the leaf). This is exactly
/// the shape the walker emits per split, scaled down.
fn tail_chain_program(n: u16, non_tail: bool) -> Program<Bn254Fr> {
    use crate::bytecode::encoding::encode_opcode;
    use crate::header::LysisHeader;
    use crate::program::{Instr, Template};
    use crate::ConstPool;

    assert!(n >= 1);
    let mut buf = Vec::new();
    let mut body: Vec<Instr> = Vec::new();
    let emit = |op: Opcode, buf: &mut Vec<u8>, body: &mut Vec<Instr>| {
        let before = buf.len() as u32;
        encode_opcode(&op, buf);
        body.push(Instr {
            opcode: op,
            offset: before,
        });
    };

    // Root prefix: DefineTemplate(0..n), InstantiateTemplate(0),
    // Halt. DefineTemplate offsets patched after bodies are laid.
    let mut define_offsets: Vec<u32> = Vec::with_capacity(n as usize);
    for id in 0..n {
        define_offsets.push(buf.len() as u32);
        emit(
            Opcode::DefineTemplate {
                template_id: id,
                frame_size: 2,
                n_params: 0,
                body_offset: 0,
                body_len: 0,
            },
            &mut buf,
            &mut body,
        );
    }
    emit(
        Opcode::InstantiateTemplate {
            template_id: 0,
            capture_regs: Box::new(vec![]),
            output_regs: Box::new(vec![]),
        },
        &mut buf,
        &mut body,
    );
    emit(Opcode::Halt, &mut buf, &mut body);

    // Template bodies, recording (offset, len) per id.
    let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(n as usize);
    for id in 0..n {
        let start = buf.len() as u32;
        if id < n - 1 {
            emit(
                Opcode::InstantiateTemplate {
                    template_id: id + 1,
                    capture_regs: Box::new(vec![]),
                    output_regs: Box::new(vec![]),
                },
                &mut buf,
                &mut body,
            );
            if non_tail {
                // An op between the call and Return ⇒ the call is
                // NOT in tail position; TCO must not fire.
                emit(Opcode::LoadConst { dst: 0, idx: 0 }, &mut buf, &mut body);
            }
        } else {
            // Leaf: observable side effect proving it ran.
            emit(Opcode::LoadConst { dst: 0, idx: 0 }, &mut buf, &mut body);
        }
        emit(Opcode::Return, &mut buf, &mut body);
        ranges.push((start, buf.len() as u32 - start));
    }

    // Patch DefineTemplate body_offset/len.
    for (id, &doff) in define_offsets.iter().enumerate() {
        let (bo, bl) = ranges[id];
        for instr in body.iter_mut() {
            if instr.offset == doff {
                if let Opcode::DefineTemplate {
                    template_id,
                    frame_size,
                    n_params,
                    ..
                } = instr.opcode
                {
                    instr.opcode = Opcode::DefineTemplate {
                        template_id,
                        frame_size,
                        n_params,
                        body_offset: bo,
                        body_len: bl,
                    };
                }
            }
        }
    }

    let mut const_pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
    const_pool.push(crate::bytecode::ConstPoolEntry::Field(seven()));
    let templates = (0..n)
        .map(|id| {
            let (bo, bl) = ranges[id as usize];
            Template {
                id,
                frame_size: 2,
                n_params: 0,
                body_offset: bo,
                body_len: bl,
            }
        })
        .collect();
    Program {
        header: LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0),
        const_pool,
        templates,
        body,
    }
}

#[test]
fn tail_chain_runs_in_constant_stack_past_max_call_depth() {
    // A 20-deep linear tail-chain with max_call_depth=4 is
    // impossible without tail-call elimination (frames would grow
    // to 20 and trip the runtime backstop ~frame 4). With TCO each
    // `InstantiateTemplate(next); Return` replaces the caller, so
    // the chain runs in O(1) frames and the leaf's Const(7)
    // materializes.
    let program = tail_chain_program(20, false);
    let cfg = LysisConfig {
        max_call_depth: 4,
        ..Default::default()
    };
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&program, &[], &cfg, &mut sink)
        .expect("tail chain must run in constant stack, not CallStackOverflow");
    let flat = sink.materialize();
    assert!(
        flat.iter().any(|n| matches!(
            n,
            InstructionKind::Const { value, .. } if *value == seven()
        )),
        "the leaf template's Const(7) must materialize (chain reached the leaf)"
    );
}

#[test]
fn non_tail_call_chain_still_overflows_under_low_max_call_depth() {
    // Guard: TCO must fire ONLY in tail position. With a
    // `LoadConst` between the `InstantiateTemplate` and `Return`
    // the call is not tail, so the stack still grows and a
    // 3-deep chain must trip max_call_depth=2 exactly as before.
    let program = tail_chain_program(3, true);
    let cfg = LysisConfig {
        max_call_depth: 2,
        ..Default::default()
    };
    let mut sink = StubSink::<Bn254Fr>::new();
    let err = execute(&program, &[], &cfg, &mut sink).unwrap_err();
    assert!(
        matches!(err, LysisError::CallStackOverflow { .. }),
        "non-tail chain must still overflow (TCO must not swallow it), got {err:?}"
    );
}

#[test]
fn template_call_does_not_infinite_loop() {
    // Regression test for the pop_frame PC fix: a stale caller.pc
    // sitting on the template-call opcode would re-invoke it
    // forever until BudgetExhausted fired. A correct implementation
    // halts before the default budget.
    let program = program_with_one_template_call();
    let cfg = LysisConfig {
        instruction_budget: 1024,
        ..Default::default()
    };
    let mut sink = StubSink::<Bn254Fr>::new();
    execute(&program, &[], &cfg, &mut sink).expect("no infinite loop");
}

#[test]
fn loop_unroll_dedup_across_iterations_via_hash_consing() {
    // Body references a non-iteration register (r5 holds a
    // pre-loop constant). The Mul result is structurally
    // identical across iterations because both operands are the
    // same across iterations — but wait, r0 = iter is different
    // each iteration, so Mul(r5, r0) differs. To actually dedup,
    // the body must NOT reference iter.
    //
    // Here we emit r5 = Const(42), then loop { r1 = r5 * r5 }.
    // The Mul is structurally identical every iteration, so the
    // interner collapses all 3 emits into one node.
    let mut builder = b();
    builder.intern_field(FieldElement::<Bn254Fr>::from_canonical([42, 0, 0, 0]));
    builder.load_const(5, 0); // r5 = 42
    builder
        .loop_unroll(0, 0, 3, MUL_BODY_BYTES)
        .emit_mul(1, 5, 5)
        .halt();
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap();
    // Interning: 1 Const(42) + 3 Const(iter 0/1/2) + 1 Mul (r5*r5 is the same every iter).
    let flat = sink.materialize();
    let muls = flat
        .iter()
        .filter(|n| matches!(n, InstructionKind::Mul { .. }))
        .count();
    assert_eq!(muls, 1, "hash-consing collapses identical Muls");
}
