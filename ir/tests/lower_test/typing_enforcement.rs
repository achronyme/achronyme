use super::*;

#[test]
fn let_bool_on_untyped_emits_range_check() {
    // `let b: Bool = x` where x is an untyped witness — must emit RangeCheck
    let source = "witness x\nlet b: Bool = x\nassert(b)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "let b: Bool on untyped witness must emit RangeCheck(1), found {rc_count}"
    );
}

#[test]
fn let_bool_on_typed_bool_no_extra_range_check() {
    // `let b: Bool = (a == c)` — a == c already produces Bool, no extra RangeCheck needed
    let source = "witness a\nwitness c\nlet b: Bool = a == c\nassert(b)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert_eq!(
        rc_count, 0,
        "let b: Bool on already-Bool value should NOT emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn let_field_on_untyped_no_enforcement() {
    // `let f: Field = x` — Field annotation on untyped is safe, no RangeCheck
    let source = "witness x\nlet f: Field = x\nassert_eq(f, f)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { .. })
    });
    assert_eq!(
        rc_count, 0,
        "let f: Field should not emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn array_annotation_validates_length() {
    // `let a: Field[2] = [x, y, z]` — length mismatch should error
    let source = "witness x\nwitness y\nwitness z\nlet a: Field[2] = [x, y, z]";
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    assert!(result.is_err(), "array length mismatch should fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("length mismatch"),
        "should mention length mismatch: {msg}"
    );
}

#[test]
fn array_bool_on_untyped_elements_enforces() {
    // `let a: Bool[2] = [x, y]` where x, y are untyped — RangeCheck per element
    let source = "witness x\nwitness y\nlet a: Bool[2] = [x, y]\nassert(a[0])";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 2,
        "Bool[2] on untyped elements should emit at least 2 RangeChecks, found {rc_count}"
    );
}

#[test]
fn fn_return_bool_on_untyped_body_enforces() {
    // fn f(x) -> Bool { x } — x is untyped, return type is Bool → enforce
    let source = r#"
witness w
fn f(x: Field) -> Bool { x }
let r = f(w)
assert(r)
"#;
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "fn -> Bool with untyped body should emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn fn_param_bool_on_untyped_arg_enforces() {
    // fn f(b: Bool) { assert(b) } called with untyped witness → enforce
    let source = r#"
witness w
fn f(b: Bool) { assert(b) }
f(w)
"#;
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "fn(b: Bool) with untyped arg should emit RangeCheck, found {rc_count}"
    );
}

#[test]
fn neg_result_has_field_type() {
    // `-x` should have type Field
    let source = "witness x\nlet n = -x\nassert_eq(n, n)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    for inst in prog.iter() {
        if let Instruction::Neg { result, .. } = inst {
            assert_eq!(
                prog.get_type(*result),
                Some(ir::IrType::Field),
                "Neg result should have Field type"
            );
        }
    }
}

// ============================================================================
// T-01: witness x: Bool must emit RangeCheck
// ============================================================================

#[test]
fn witness_bool_decl_emits_range_check() {
    let source = "witness flag: Bool\nassert(flag)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "witness flag: Bool should emit RangeCheck(flag, 1), found {rc_count}"
    );
}

#[test]
fn witness_bool_array_decl_emits_range_checks() {
    let source = "witness flags[3]: Bool\nassert(flags[0])";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 3,
        "witness flags[3]: Bool should emit 3 RangeChecks, found {rc_count}"
    );
}

#[test]
fn public_bool_decl_emits_range_check() {
    let source = "public flag: Bool\nassert(flag)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    let rc_count = count(prog.instructions(), |i| {
        matches!(i, Instruction::RangeCheck { bits: 1, .. })
    });
    assert!(
        rc_count >= 1,
        "public flag: Bool should emit RangeCheck(flag, 1), found {rc_count}"
    );
}

// ============================================================================
// T-03: array Bool[N] annotation must check type compatibility
// ============================================================================

#[test]
fn array_bool_annotation_rejects_field_typed_element() {
    // `a + b` produces Field type, which is incompatible with Bool[1] annotation.
    let source = r#"
witness a: Field
witness b: Field
let arr: Bool[1] = [a + b]
"#;
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    assert!(
        result.is_err(),
        "Bool[1] annotation on Field-typed element should fail"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("AnnotationMismatch") || err.contains("mismatch"),
        "should report type mismatch: {err}"
    );
}

// ============================================================================
// T-04: Annotation shape must match value shape
// ============================================================================

#[test]
fn scalar_annotation_on_array_rejected() {
    // `let arr: Bool = [x, y]` — scalar annotation on array value
    let source = "witness x\nwitness y\nlet arr: Bool = [x, y]";
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    assert!(
        result.is_err(),
        "scalar Bool annotation on array literal should fail"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("mismatch"),
        "should report type mismatch: {err}"
    );
}

#[test]
fn scalar_field_annotation_on_array_rejected() {
    let source = "witness x\nlet arr: Field = [x]";
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    assert!(
        result.is_err(),
        "scalar Field annotation on array literal should fail"
    );
}

#[test]
fn array_annotation_on_scalar_rejected() {
    // `let x: Field[3] = expr` — array annotation on scalar value
    let source = "witness x\nlet y: Field[3] = x";
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    assert!(
        result.is_err(),
        "array Field[3] annotation on scalar value should fail"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("mismatch"),
        "should report type mismatch: {err}"
    );
}

#[test]
fn array_bool_annotation_on_scalar_rejected() {
    let source = "witness x\nlet y: Bool[2] = x";
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    assert!(
        result.is_err(),
        "array Bool[2] annotation on scalar value should fail"
    );
}

// ============================================================================
// T-05: pow_by_squaring results must be typed Field
// ============================================================================

#[test]
fn pow_result_has_field_type() {
    let source = "witness x\nlet p = x ^ 3\nassert_eq(p, p)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    // The last Mul in the pow chain should have Field type
    let mul_results: Vec<_> = prog
        .iter()
        .filter_map(|i| {
            if let Instruction::Mul { result, .. } = i {
                Some(*result)
            } else {
                None
            }
        })
        .collect();
    assert!(!mul_results.is_empty(), "x^3 should emit at least one Mul");
    for r in &mul_results {
        assert_eq!(
            prog.get_type(*r),
            Some(ir::IrType::Field),
            "pow Mul result should have Field type"
        );
    }
}

#[test]
fn pow_zero_result_has_field_type() {
    let source = "witness x\nlet p = x ^ 0\nassert_eq(p, p)";
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    // x^0 = Const(1), should be typed Field
    let const_ones: Vec<_> = prog
        .iter()
        .filter_map(|i| {
            if let Instruction::Const { result, value } = i {
                if *value == memory::FieldElement::ONE {
                    Some(*result)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    // At least one Const(1) should exist and be typed Field
    let any_field = const_ones
        .iter()
        .any(|r| prog.get_type(*r) == Some(ir::IrType::Field));
    assert!(any_field, "x^0 Const(1) should have Field type");
}

// ============================================================================
// T-06: Field[N] annotation preserves Bool type on elements
// ============================================================================

#[test]
fn field_array_preserves_bool_element_type() {
    // (a == b) is Bool-typed; putting it in Field[1] should NOT widen to Field
    let source = r#"
witness a: Field
witness b: Field
let eq = a == b
let arr: Field[1] = [eq]
"#;
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained(source).expect("should lower");
    // Find the IsEq result variable
    for inst in prog.iter() {
        if let Instruction::IsEq { result, .. } = inst {
            assert_eq!(
                prog.get_type(*result),
                Some(ir::IrType::Bool),
                "IsEq result in Field[1] array should preserve Bool type"
            );
        }
    }
}
