use super::*;

#[test]
fn typed_public_sets_ir_type() {
    let (_, _, prog) =
        IrLowering::<memory::Bn254Fr>::lower_self_contained("public x: Field\nassert_eq(x, x)")
            .expect("should lower");
    // The Input instruction for x should have type Field
    for inst in prog.iter() {
        if let Instruction::Input { result, name, .. } = inst {
            if name == "x" {
                assert_eq!(
                    prog.get_type(*result),
                    Some(ir::IrType::Field),
                    "public x: Field should have IrType::Field"
                );
            }
        }
    }
}

#[test]
fn typed_witness_bool_sets_ir_type() {
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "public x: Field\nwitness b: Bool\nassert_eq(x, b)",
    )
    .expect("should lower");
    for inst in prog.iter() {
        if let Instruction::Input { result, name, .. } = inst {
            if name == "b" {
                assert_eq!(
                    prog.get_type(*result),
                    Some(ir::IrType::Bool),
                    "witness b: Bool should have IrType::Bool"
                );
            }
        }
    }
}

#[test]
fn typed_let_field_compiles() {
    // let h: Field = poseidon(a, b) — should compile without error
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "witness a: Field\nwitness b: Field\nlet h: Field = poseidon(a, b)\nassert_eq(h, h)",
    )
    .expect("typed let should compile");
    assert!(!prog.is_empty());
}

#[test]
fn typed_let_bool_compiles() {
    // let ok: Bool = x == y — should compile without error
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "public x: Field\nwitness y: Field\nlet ok: Bool = x == y\nassert(ok)",
    )
    .expect("typed let Bool should compile");
    assert!(!prog.is_empty());
}

#[test]
fn typed_let_bool_from_field_arithmetic_fails() {
    // let bad: Bool = x + y — x + y produces Field, cannot be annotated as Bool
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "public x: Field\nwitness y: Field\nlet bad: Bool = x + y",
    );
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("annotation mismatch") || msg.contains("Bool"),
                "should mention type mismatch: {msg}"
            );
        }
        Ok(_) => panic!("Field expression annotated as Bool should fail"),
    }
}

#[test]
fn typed_fn_with_return_type() {
    let source = r#"
witness a: Field
witness b: Field
fn hash(x: Field, y: Field) -> Field {
    poseidon(x, y)
}
let h: Field = hash(a, b)
assert_eq(h, h)
"#;
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(source)
        .expect("typed fn should compile");
    assert!(!prog.is_empty());
}

#[test]
fn typed_fn_param_mismatch_fails() {
    // Pass a Field value where Bool is expected
    let source = r#"
witness x: Field
fn check(b: Bool) { assert(b) }
check(x)
"#;
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(source);
    match result {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("annotation mismatch") || msg.contains("Bool"),
                "should mention type mismatch: {msg}"
            );
        }
        Ok(_) => panic!("passing Field to Bool param should fail"),
    }
}

#[test]
fn bool_subtype_of_field_allowed() {
    // Bool values can be used where Field is expected
    let source = r#"
witness a: Field
witness b: Field
let ok: Bool = a == b
let x: Field = ok
assert_eq(x, x)
"#;
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(source)
        .expect("Bool used as Field should compile");
    assert!(!prog.is_empty());
}

#[test]
fn untyped_code_unchanged() {
    // All existing untyped code should still work identically
    let source = "public x\nwitness y\nassert_eq(x + y, x * y)";
    let (pub_names, wit_names, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(source)
        .expect("untyped should compile");
    assert_eq!(pub_names, vec!["x"]);
    assert_eq!(wit_names, vec!["y"]);
    assert!(!prog.is_empty());
}

#[test]
fn comparison_result_is_bool() {
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "witness a: Field\nwitness b: Field\nlet eq: Bool = a == b\nassert(eq)",
    )
    .expect("should lower");
    // Find IsEq instruction, check its result has Bool type
    for inst in prog.iter() {
        if let Instruction::IsEq { result, .. } = inst {
            assert_eq!(prog.get_type(*result), Some(ir::IrType::Bool));
        }
    }
}

#[test]
fn not_rejects_field_operand() {
    // !x where x: Field should fail
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "witness x: Field\nlet bad: Bool = !x\nassert(bad)",
    );
    assert!(result.is_err(), "!Field should fail");
}

#[test]
fn not_accepts_bool_operand() {
    let result = IrLowering::<memory::Bn254Fr>::lower_self_contained(
        "witness a: Field\nwitness b: Field\nlet ok = !(a == b)\nassert(ok)",
    );
    assert!(result.is_ok(), "!Bool should compile");
}

#[test]
fn mixed_typed_and_untyped_inputs() {
    // Some inputs typed, some not — gradual typing
    let source = "public x: Field\nwitness y\nassert_eq(x, y)";
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(source)
        .expect("mixed typing should compile");
    // x should have type, y should not
    let mut x_typed = false;
    let mut y_untyped = true;
    for inst in prog.iter() {
        if let Instruction::Input { result, name, .. } = inst {
            if name == "x" {
                x_typed = prog.get_type(*result).is_some();
            }
            if name == "y" {
                y_untyped = prog.get_type(*result).is_none();
            }
        }
    }
    assert!(x_typed, "x: Field should have type");
    assert!(y_untyped, "y (no annotation) should have no type");
}

#[test]
fn if_branches_propagate_type() {
    let source = r#"
witness a: Field
witness b: Field
witness c: Field
let r = if true { a == b } else { a == c }
assert(r)
"#;
    let (_, _, prog) = IrLowering::<memory::Bn254Fr>::lower_self_contained(source)
        .expect("if with matching branch types");
    // The Mux result should have Bool type since both branches are Bool
    for inst in prog.iter() {
        if let Instruction::Mux { result, .. } = inst {
            assert_eq!(prog.get_type(*result), Some(ir::IrType::Bool));
        }
    }
}

// ============================================================================
// Type annotation enforcement (soundness fixes)
