use super::*;

#[test]
fn assert_eq_keeps_constraint_for_used_or_public_lhs() {
    let mut used_prog: IrProgram = IrProgram::new();
    let x = used_prog.fresh_var();
    used_prog.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let y = used_prog.fresh_var();
    used_prog.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let first_product = used_prog.fresh_var();
    used_prog.push(Instruction::Mul {
        result: first_product,
        lhs: x,
        rhs: y,
    });
    let eq = used_prog.fresh_var();
    used_prog.push(Instruction::AssertEq {
        result: eq,
        lhs: x,
        rhs: y,
        message: None,
    });

    let mut used_compiler = R1CSCompiler::<Bn254Fr>::new_lean();
    used_compiler.compile_ir(&used_prog).unwrap();
    assert_eq!(
        used_compiler.cs.num_constraints(),
        2,
        "lhs already used by a prior expression must keep its equality constraint"
    );

    let mut public_prog: IrProgram = IrProgram::new();
    let out = public_prog.fresh_var();
    public_prog.push(Instruction::Input {
        result: out,
        name: "out".into(),
        visibility: IrVisibility::Public,
    });
    let y = public_prog.fresh_var();
    public_prog.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let eq = public_prog.fresh_var();
    public_prog.push(Instruction::AssertEq {
        result: eq,
        lhs: out,
        rhs: y,
        message: None,
    });

    let mut public_compiler = R1CSCompiler::<Bn254Fr>::new_lean();
    public_compiler.compile_ir(&public_prog).unwrap();
    assert_eq!(
        public_compiler.cs.num_constraints(),
        1,
        "public lhs must stay constrained to preserve the public interface"
    );
}
#[test]
fn compile_instructions_streaming_resolves_operands_across_batches() {
    // Pin: `compile_instructions_streaming` does NOT clear the
    // per-program operand-lookup caches between calls, so an
    // operand defined in an earlier batch remains resolvable in a
    // later batch. The chunk-draining lysis-to-R1CS bridge relies
    // on this: a `Mul` (or any operand-taking instruction) sealed
    // into chunk N may reference an SsaVar first emitted in chunk
    // M<N when the interner's dedup tiers return a cross-chunk
    // `NodeId`. Wipe the cache per chunk and the cross-chunk
    // operand lookup fails.
    //
    // The companion `compile_instructions_does_clear_caches_*` test
    // below shows the dual: feeding the same batched stream through
    // the single-batch `compile_instructions` entry point fails on
    // the second batch because its operands look up wires the
    // entry point cleared.
    let build_prog = || {
        let mut prog: IrProgram = IrProgram::new();
        let x = prog.fresh_var();
        prog.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let c = prog.fresh_var();
        prog.push(Instruction::Const {
            result: c,
            value: FieldElement::<Bn254Fr>::from_u64(5),
        });
        let y = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: y,
            lhs: x,
            rhs: c,
        });
        let out = prog.fresh_var();
        prog.push(Instruction::Input {
            result: out,
            name: "out".into(),
            visibility: IrVisibility::Public,
        });
        let assertion = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: assertion,
            lhs: y,
            rhs: out,
            message: None,
        });
        prog
    };

    // Reference path: single eager `compile_ir` call.
    let mut eager = R1CSCompiler::<Bn254Fr>::new();
    eager.compile_ir(&build_prog()).unwrap();

    // Subject path: split the same program across three batches.
    // Batch 1 defines `x` (Input) and `c` (Const).
    // Batch 2 has `Mul y = x * c` — operands cross the batch
    //   boundary; both `x` and `c` were defined in batch 1.
    // Batch 3 defines `out` (Input) and asserts `y == out` —
    //   the AssertEq references `y` from batch 2 and `out` from
    //   batch 3, exercising both cross-batch and within-batch
    //   operand lookup on the same call.
    let instrs: Vec<_> = build_prog().into_instructions();
    let batch1: Vec<_> = instrs[0..2].to_vec();
    let batch2: Vec<_> = instrs[2..3].to_vec();
    let batch3: Vec<_> = instrs[3..].to_vec();

    let mut streaming = R1CSCompiler::<Bn254Fr>::new();
    streaming.compile_instructions_streaming(batch1).unwrap();
    streaming.compile_instructions_streaming(batch2).unwrap();
    streaming.compile_instructions_streaming(batch3).unwrap();

    assert_eq!(eager.cs.num_constraints(), streaming.cs.num_constraints());
    assert_eq!(eager.cs.num_variables(), streaming.cs.num_variables());
    assert_eq!(eager.cs.num_pub_inputs(), streaming.cs.num_pub_inputs());
    assert_eq!(eager.public_inputs, streaming.public_inputs);
    assert_eq!(eager.witnesses, streaming.witnesses);
}

#[test]
fn compile_instructions_clears_caches_so_batched_operand_lookup_fails() {
    // Dual of the streaming pin: feeding the SAME batched stream
    // through the single-batch `compile_instructions` entry point
    // fails on the second batch because the entry point clears
    // `lc_map` on every call. Pinning this guards against an
    // accidental removal of the clearing semantics from
    // `compile_instructions` proper — that entry point IS the
    // "fresh compiler per program" boundary; the streaming entry
    // point is the explicit opt-in to no-clear behavior.
    let mut prog: IrProgram = IrProgram::new();
    let x = prog.fresh_var();
    prog.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let c = prog.fresh_var();
    prog.push(Instruction::Const {
        result: c,
        value: FieldElement::<Bn254Fr>::from_u64(5),
    });
    let y = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: y,
        lhs: x,
        rhs: c,
    });
    let instrs: Vec<_> = prog.into_instructions();
    let batch1: Vec<_> = instrs[0..2].to_vec();
    let batch2: Vec<_> = instrs[2..].to_vec();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_instructions(batch1).unwrap();
    // Batch 2 references `x` and `c` from batch 1; the entry
    // point cleared `lc_map` on entry, so lookup fails.
    let err = compiler.compile_instructions(batch2).unwrap_err();
    assert!(
        matches!(err, R1CSError::UnsupportedOperation(_, _)),
        "expected undefined-SSA-variable error, got {err:?}"
    );
}

/// Build an `IrProgram` that emits two `WitnessCall`s. Each call
/// declares one fresh input and one fresh output; `program_bytes`
/// per call is supplied by the caller. The bytecode is opaque to
/// `compile_ir` — it is only stored, never decoded.
fn build_two_witness_call_prog(bytes_a: Vec<u8>, bytes_b: Vec<u8>) -> IrProgram {
    use ir::types::WitnessCallBody;

    let mut prog: IrProgram = IrProgram::new();
    let in_a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: in_a,
        name: "in_a".into(),
        visibility: IrVisibility::Witness,
    });
    let in_b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: in_b,
        name: "in_b".into(),
        visibility: IrVisibility::Witness,
    });
    let out_a = prog.fresh_var();
    prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs: vec![out_a],
        inputs: vec![in_a],
        program_bytes: bytes_a,
    })));
    let out_b = prog.fresh_var();
    prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs: vec![out_b],
        inputs: vec![in_b],
        program_bytes: bytes_b,
    })));
    prog
}

#[test]
fn artik_intern_shares_arc_for_identical_payloads() {
    // Pin: two `WitnessCall`s carrying byte-identical `program_bytes`
    // collapse to a single `Arc<[u8]>` in the intern table, and the
    // resulting `WitnessOp::ArtikCall` entries share the same pointer.
    let payload = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let prog = build_two_witness_call_prog(payload.clone(), payload.clone());

    let mut c = R1CSCompiler::<Bn254Fr>::new();
    c.compile_ir(&prog).unwrap();

    assert_eq!(
        c.artik_program_intern_len(),
        1,
        "byte-identical payloads must collapse to a single intern entry"
    );

    let artik_ops: Vec<&WitnessOp<_>> = c
        .witness_ops
        .iter()
        .filter(|op| matches!(op, WitnessOp::ArtikCall { .. }))
        .collect();
    assert_eq!(artik_ops.len(), 2, "expected two ArtikCall entries");
    let (a, b) = match (&artik_ops[0], &artik_ops[1]) {
        (
            WitnessOp::ArtikCall {
                program_bytes: pa, ..
            },
            WitnessOp::ArtikCall {
                program_bytes: pb, ..
            },
        ) => (pa, pb),
        _ => unreachable!(),
    };
    assert!(
        Arc::ptr_eq(a, b),
        "intern table must hand out the same Arc to identical payloads"
    );
}

#[test]
fn artik_intern_survives_across_streaming_batches() {
    // Pin: the intern table is owned by the compiler, not by a
    // single `compile_ir` call, so two `compile_instructions_streaming`
    // batches that each carry a byte-identical `WitnessCall` payload
    // still collapse to a single `Arc<[u8]>`. The chunk-drain entry
    // point relies on this — it routes each sealed chunk through
    // `compile_instructions_streaming` against the same compiler,
    // so intern hits must accumulate across chunks.
    use ir::types::WitnessCallBody;

    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let mut prog: IrProgram = IrProgram::new();
    let in_a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: in_a,
        name: "in_a".into(),
        visibility: IrVisibility::Witness,
    });
    let out_a = prog.fresh_var();
    prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs: vec![out_a],
        inputs: vec![in_a],
        program_bytes: payload.clone(),
    })));
    let in_b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: in_b,
        name: "in_b".into(),
        visibility: IrVisibility::Witness,
    });
    let out_b = prog.fresh_var();
    prog.push(Instruction::WitnessCall(Box::new(WitnessCallBody {
        outputs: vec![out_b],
        inputs: vec![in_b],
        program_bytes: payload.clone(),
    })));

    let instrs: Vec<_> = prog.into_instructions();
    let batch1: Vec<_> = instrs[0..2].to_vec();
    let batch2: Vec<_> = instrs[2..].to_vec();

    let mut c = R1CSCompiler::<Bn254Fr>::new();
    c.compile_instructions_streaming(batch1).unwrap();
    c.compile_instructions_streaming(batch2).unwrap();

    assert_eq!(
        c.artik_program_intern_len(),
        1,
        "intern table must persist across streaming batches"
    );
    let artik_ops: Vec<&WitnessOp<_>> = c
        .witness_ops
        .iter()
        .filter(|op| matches!(op, WitnessOp::ArtikCall { .. }))
        .collect();
    assert_eq!(artik_ops.len(), 2);
    let (a, b) = match (&artik_ops[0], &artik_ops[1]) {
        (
            WitnessOp::ArtikCall {
                program_bytes: pa, ..
            },
            WitnessOp::ArtikCall {
                program_bytes: pb, ..
            },
        ) => (pa, pb),
        _ => unreachable!(),
    };
    assert!(
        Arc::ptr_eq(a, b),
        "Arc identity must hold across streaming batch boundaries"
    );
}

#[test]
fn artik_intern_keeps_distinct_arcs_for_different_payloads() {
    // Pin: payloads that differ in even a single byte get distinct
    // intern entries and distinct `Arc`s — the secondary slice
    // equality check guards against any `u64` hash collision aliasing
    // the two programs.
    let prog = build_two_witness_call_prog(vec![0xAA, 0xBB], vec![0xAA, 0xCC]);

    let mut c = R1CSCompiler::<Bn254Fr>::new();
    c.compile_ir(&prog).unwrap();

    assert_eq!(
        c.artik_program_intern_len(),
        2,
        "byte-distinct payloads must occupy distinct intern entries"
    );

    let artik_ops: Vec<&WitnessOp<_>> = c
        .witness_ops
        .iter()
        .filter(|op| matches!(op, WitnessOp::ArtikCall { .. }))
        .collect();
    let (a, b) = match (&artik_ops[0], &artik_ops[1]) {
        (
            WitnessOp::ArtikCall {
                program_bytes: pa, ..
            },
            WitnessOp::ArtikCall {
                program_bytes: pb, ..
            },
        ) => (pa, pb),
        _ => unreachable!(),
    };
    assert!(
        !Arc::ptr_eq(a, b),
        "distinct payloads must NOT share an Arc"
    );
    assert_eq!(a.as_ref(), &[0xAA, 0xBB][..]);
    assert_eq!(b.as_ref(), &[0xAA, 0xCC][..]);
}
