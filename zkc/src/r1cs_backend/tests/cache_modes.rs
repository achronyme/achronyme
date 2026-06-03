use super::*;

#[test]
fn direct_linear_mul_emits_post_o1_shape_for_multi_term_operands() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: IrVisibility::Witness,
    });
    let b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: IrVisibility::Witness,
    });
    let c = prog.fresh_var();
    prog.push(Instruction::Input {
        result: c,
        name: "c".into(),
        visibility: IrVisibility::Witness,
    });
    let ab = prog.fresh_var();
    prog.push(Instruction::Add {
        result: ab,
        lhs: a,
        rhs: b,
    });
    let bc = prog.fresh_var();
    prog.push(Instruction::Add {
        result: bc,
        lhs: b,
        rhs: c,
    });
    let product = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: product,
        lhs: ab,
        rhs: bc,
    });

    let mut baseline = R1CSCompiler::<Bn254Fr>::new_lean();
    baseline.compile_ir(&prog).unwrap();
    assert_eq!(
        baseline.cs.num_constraints(),
        3,
        "baseline emits two materialization constraints plus the product"
    );

    let mut direct = R1CSCompiler::<Bn254Fr>::new_direct_linear_mul();
    direct.compile_ir(&prog).unwrap();
    assert_eq!(
        direct.cs.num_constraints(),
        1,
        "direct mode emits the product constraint without O1-only materializations"
    );
    assert_eq!(
        direct.witness_ops.len(),
        1,
        "direct mode records only the product witness op"
    );
    assert!(matches!(
        direct.witness_ops.iter().next(),
        Some(WitnessOp::Multiply { a, b, .. }) if a.terms().len() == 2 && b.terms().len() == 2
    ));
}
#[test]
fn compile_only_direct_linear_mul_counts_constraints_without_retaining_rows() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: IrVisibility::Witness,
    });
    let b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: IrVisibility::Witness,
    });
    let sum = prog.fresh_var();
    prog.push(Instruction::Add {
        result: sum,
        lhs: a,
        rhs: b,
    });
    let product = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: product,
        lhs: sum,
        rhs: a,
    });

    let mut direct = R1CSCompiler::<Bn254Fr>::new_direct_linear_mul();
    direct.compile_ir(&prog).unwrap();

    let mut compile_only = R1CSCompiler::<Bn254Fr>::new_compile_only_direct_linear_mul();
    compile_only.compile_ir(&prog).unwrap();

    assert_eq!(
        compile_only.cs.num_constraints(),
        direct.cs.num_constraints()
    );
    assert_eq!(compile_only.cs.num_variables(), direct.cs.num_variables());
    assert!(compile_only.cs.constraints().is_empty());
    assert!(!compile_only.cs.constraint_retention_enabled());
    assert!(
        compile_only.witness_ops.is_empty(),
        "compile-only mode must not retain witness replay ops"
    );
}
#[test]
fn lc_cache_term_limit_materializes_long_cached_lcs() {
    let build_prog = || {
        let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
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
        let z = prog.fresh_var();
        prog.push(Instruction::Input {
            result: z,
            name: "z".into(),
            visibility: IrVisibility::Witness,
        });
        let xy = prog.fresh_var();
        prog.push(Instruction::Add {
            result: xy,
            lhs: x,
            rhs: y,
        });
        let xyz = prog.fresh_var();
        prog.push(Instruction::Add {
            result: xyz,
            lhs: xy,
            rhs: z,
        });
        (prog, xyz)
    };

    let (prog, xyz) = build_prog();
    let mut unbounded = R1CSCompiler::new_lean();
    unbounded.compile_ir(&prog).unwrap();
    assert_eq!(unbounded.cs.num_constraints(), 0);
    assert_eq!(
        unbounded.lookup_lc_untracked(&xyz).unwrap().terms().len(),
        3
    );

    let (prog, xyz) = build_prog();
    let mut bounded = R1CSCompiler::new_lean();
    bounded.lc_cache_term_limit = Some(1);
    bounded.compile_ir(&prog).unwrap();
    assert_eq!(
        bounded.lookup_lc_untracked(&xyz).unwrap().terms().len(),
        1,
        "bounded cache should retain only the materialized wire"
    );
    assert_eq!(
        bounded.cs.num_constraints(),
        2,
        "x+y and (x+y)+z each cross the one-term cache limit"
    );
}
#[test]
fn lc_cache_term_limit_with_collapse_absorbs_materialization_rows() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: IrVisibility::Witness,
    });
    let b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: IrVisibility::Witness,
    });
    let c = prog.fresh_var();
    prog.push(Instruction::Input {
        result: c,
        name: "c".into(),
        visibility: IrVisibility::Witness,
    });
    let ab = prog.fresh_var();
    prog.push(Instruction::Add {
        result: ab,
        lhs: a,
        rhs: b,
    });
    let bc = prog.fresh_var();
    prog.push(Instruction::Add {
        result: bc,
        lhs: b,
        rhs: c,
    });
    let product = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: product,
        lhs: ab,
        rhs: bc,
    });

    let mut bounded = R1CSCompiler::new_direct_linear_mul();
    bounded.lc_cache_term_limit = Some(1);
    bounded.compile_ir(&prog).unwrap();
    assert_eq!(
        bounded.cs.num_constraints(),
        3,
        "without collapse, two cache materializations inflate the direct product"
    );

    let mut collapsed = R1CSCompiler::new_direct_linear_mul();
    collapsed.lc_cache_term_limit = Some(1);
    collapsed.cs.enable_incremental_collapse();
    collapsed.compile_ir(&prog).unwrap();
    assert_eq!(
        collapsed.cs.num_constraints(),
        1,
        "collapse should absorb cache materialization rows before the product survivor"
    );
    assert_eq!(
        collapsed.lookup_lc_untracked(&ab).unwrap().terms().len(),
        1,
        "bounded cache still retains only the materialized wire"
    );
}
#[test]
fn count_only_collapse_absorbs_cache_rows_without_substitution_retention() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: IrVisibility::Witness,
    });
    let b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: IrVisibility::Witness,
    });
    let c = prog.fresh_var();
    prog.push(Instruction::Input {
        result: c,
        name: "c".into(),
        visibility: IrVisibility::Witness,
    });
    let ab = prog.fresh_var();
    prog.push(Instruction::Add {
        result: ab,
        lhs: a,
        rhs: b,
    });
    let bc = prog.fresh_var();
    prog.push(Instruction::Add {
        result: bc,
        lhs: b,
        rhs: c,
    });
    let product = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: product,
        lhs: ab,
        rhs: bc,
    });

    let mut compiler = R1CSCompiler::new_direct_linear_mul();
    compiler.record_witness_ops = false;
    compiler.lc_cache_term_limit = Some(1);
    compiler.cs.disable_constraint_retention();
    compiler.cs.enable_incremental_collapse_count_only();
    compiler.compile_ir(&prog).unwrap();

    assert_eq!(
        compiler.cs.num_constraints(),
        1,
        "count-only collapse should absorb cache materialization rows"
    );
    assert!(compiler.cs.constraints().is_empty());
    assert!(
        compiler
            .cs
            .take_collapse_substitution_map()
            .unwrap()
            .is_empty(),
        "compile-only count mode must not retain eliminated-wire replacements"
    );
}
