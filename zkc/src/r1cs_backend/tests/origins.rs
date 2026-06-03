use super::*;

#[test]
fn constraint_origins_tracks_mul() {
    let mut prog: IrProgram = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    // Mul generates exactly 1 constraint
    assert_eq!(compiler.cs.num_constraints(), 1);
    assert_eq!(compiler.constraint_origins.len(), 1);
    assert_eq!(compiler.constraint_origins[0].ir_index, 2); // third instruction
    assert_eq!(compiler.constraint_origins[0].result_var, SsaVar(2));
}
#[test]
fn constraint_origins_tracks_assert_eq() {
    let mut prog: IrProgram = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Public,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: v2,
        lhs: v0,
        rhs: v1,
        message: Some("values must match".into()),
    });

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    assert_eq!(compiler.cs.num_constraints(), 1);
    assert_eq!(compiler.constraint_origins.len(), 1);
    assert_eq!(compiler.constraint_origins[0].ir_index, 2);
    assert_eq!(compiler.constraint_origins[0].result_var, SsaVar(2));
}

#[test]
fn constraint_origins_empty_for_linear_ops() {
    let mut prog: IrProgram = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    // Add is free (no constraints)
    let v2 = prog.fresh_var();
    prog.push(Instruction::Add {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    assert_eq!(compiler.cs.num_constraints(), 0);
    assert!(compiler.constraint_origins.is_empty());
}

#[test]
fn constraint_origins_count_matches_constraints() {
    // Mixed circuit: Mul + PoseidonHash + AssertEq
    let mut prog: IrProgram = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::PoseidonHash {
        result: v3,
        left: v0,
        right: v1,
    });
    let v4 = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: v4,
        lhs: v2,
        rhs: v3,
        message: None,
    });

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();

    // Origins length must match constraint count exactly
    assert_eq!(
        compiler.constraint_origins.len(),
        compiler.cs.num_constraints()
    );

    // Verify Poseidon constraints map back to the PoseidonHash instruction (index 3)
    let poseidon_origins: Vec<_> = compiler
        .constraint_origins
        .iter()
        .filter(|o| o.ir_index == 3)
        .collect();
    assert_eq!(poseidon_origins.len(), 361); // PoseidonHash = 361 constraints
}

#[test]
fn compile_instructions_matches_compile_ir_on_mixed_circuit() {
    // Pin: the streaming `compile_instructions` entry point and
    // the eager `compile_ir(&IrProgram)` entry point produce
    // byte-identical R1CS output (same constraint count, same
    // constraint_origins) on a representative mixed circuit.
    // Reuses the constraint_origins_count_matches_constraints
    // shape.
    let build_prog = || {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: v3,
            left: v0,
            right: v1,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v4,
            lhs: v0,
            rhs: v1,
            message: None,
        });
        prog
    };

    let mut eager = R1CSCompiler::new();
    eager.compile_ir(&build_prog()).unwrap();

    let mut streaming = R1CSCompiler::new();
    streaming
        .compile_instructions(build_prog().into_instructions())
        .unwrap();

    assert_eq!(eager.cs.num_constraints(), streaming.cs.num_constraints());
    assert_eq!(
        eager.constraint_origins.len(),
        streaming.constraint_origins.len()
    );
    for (a, b) in eager
        .constraint_origins
        .iter()
        .zip(streaming.constraint_origins.iter())
    {
        assert_eq!(a.ir_index, b.ir_index);
        assert_eq!(a.result_var, b.result_var);
    }
}

#[test]
fn lean_compiler_skips_constraint_origins() {
    // Pin: a compiler built via `new_lean` leaves `constraint_origins`
    // empty after emission, while the eager `new` constructor populates
    // it as usual on the same program.
    let mut prog: IrProgram = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let mut lean = R1CSCompiler::new_lean();
    lean.compile_ir(&prog).unwrap();
    assert!(
        lean.constraint_origins.is_empty(),
        "lean compiler must not populate constraint_origins"
    );
    assert!(
        lean.cs.num_constraints() > 0,
        "lean compiler must still emit constraints"
    );
}

#[test]
fn lean_compiler_skips_input_metadata_but_preserves_wire_layout() {
    // Pin: `new_lean` is allowed to drop name metadata, but it must still
    // allocate public and witness wires exactly like the eager compiler.
    let mut prog: IrProgram = IrProgram::new();
    let pub_var = prog.fresh_var();
    prog.push(Instruction::Input {
        result: pub_var,
        name: "public_out".into(),
        visibility: IrVisibility::Public,
    });
    let witness_var = prog.fresh_var();
    prog.push(Instruction::Input {
        result: witness_var,
        name: "__lysis_sym_slot_42".into(),
        visibility: IrVisibility::Witness,
    });
    let assertion = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: assertion,
        lhs: pub_var,
        rhs: witness_var,
        message: None,
    });

    let mut eager = R1CSCompiler::new();
    eager.compile_ir(&prog).unwrap();

    let mut lean = R1CSCompiler::new_lean();
    lean.compile_ir(&prog).unwrap();

    assert_eq!(eager.cs.num_variables(), lean.cs.num_variables());
    assert_eq!(eager.cs.num_pub_inputs(), lean.cs.num_pub_inputs());
    assert_eq!(eager.cs.num_constraints(), lean.cs.num_constraints());
    assert_eq!(eager.bindings.len(), 2);
    assert_eq!(eager.public_inputs, vec!["public_out"]);
    assert_eq!(eager.witnesses, vec!["__lysis_sym_slot_42"]);
    assert!(lean.bindings.is_empty());
    assert!(lean.public_inputs.is_empty());
    assert!(lean.witnesses.is_empty());
}

#[test]
fn lean_compiler_matches_eager_on_constraint_surface() {
    // Pin: lean and eager R1CS compilers produce byte-identical
    // constraint systems on a representative mixed circuit — same
    // count, same per-constraint LC terms, same witness ops, same
    // variable allocations. Lean deliberately drops hot-path metadata:
    // constraint origins and input name tables.
    let build_prog = || {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: v3,
            left: v0,
            right: v1,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v4,
            lhs: v0,
            rhs: v1,
            message: None,
        });
        prog
    };

    let mut eager = R1CSCompiler::new();
    eager.compile_ir(&build_prog()).unwrap();

    let mut lean = R1CSCompiler::new_lean();
    lean.compile_ir(&build_prog()).unwrap();

    assert_eq!(eager.cs.num_constraints(), lean.cs.num_constraints());
    assert_eq!(eager.cs.num_variables(), lean.cs.num_variables());
    assert_eq!(eager.cs.num_pub_inputs(), lean.cs.num_pub_inputs());
    assert_eq!(eager.witness_ops.len(), lean.witness_ops.len());

    for (e, l) in eager
        .cs
        .constraints()
        .iter()
        .zip(lean.cs.constraints().iter())
    {
        assert_eq!(e.a.terms(), l.a.terms(), "constraint.a terms diverged");
        assert_eq!(e.b.terms(), l.b.terms(), "constraint.b terms diverged");
        assert_eq!(e.c.terms(), l.c.terms(), "constraint.c terms diverged");
    }

    assert!(
        !eager.constraint_origins.is_empty(),
        "eager compiler must populate origins"
    );
    assert!(
        lean.constraint_origins.is_empty(),
        "lean compiler must leave origins empty"
    );
    assert!(
        lean.bindings.is_empty() && lean.public_inputs.is_empty() && lean.witnesses.is_empty(),
        "lean compiler must leave input metadata empty"
    );
}

#[test]
fn assert_eq_rebinds_fresh_private_lhs_without_linear_constraint() {
    let mut prog: IrProgram = IrProgram::new();
    let x = prog.fresh_var();
    prog.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let y = prog.fresh_var();
    prog.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let eq = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: eq,
        lhs: x,
        rhs: y,
        message: None,
    });
    let product = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: product,
        lhs: x,
        rhs: y,
    });

    let mut compiler = R1CSCompiler::<Bn254Fr>::new_lean();
    compiler.compile_ir(&prog).unwrap();

    assert_eq!(
        compiler.cs.num_constraints(),
        1,
        "fresh private AssertEq lhs should become a forward alias, not a stored linear constraint"
    );
    let constraint = &compiler.cs.constraints()[0];
    assert_eq!(constraint.a.terms(), &[(Variable(2), FieldElement::ONE)]);
    assert_eq!(constraint.b.terms(), &[(Variable(2), FieldElement::ONE)]);
}
