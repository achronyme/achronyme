use compiler::r1cs_backend::R1CSCompiler;
use ir::IrLowering;
use memory::FieldElement;

#[test]
fn test_r1cs_integration_simple_multiply() {
    // Circuit: prove a * b == c
    let program = IrLowering::lower_circuit(
        "let product = a * b; assert_eq(product, c)",
        &["c"],
        &["a", "b"],
    )
    .unwrap();

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();

    // a * b generates 1 constraint (product wire), assert_eq generates 1
    assert_eq!(rc.cs.num_constraints(), 2);

    // Build witness: ONE=1, c=42, a=6, b=7, product=42
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(42), // c (public)
        FieldElement::from_u64(6),  // a
        FieldElement::from_u64(7),  // b
        FieldElement::from_u64(42), // product (intermediate)
    ];
    assert!(rc.cs.verify(&witness).is_ok());

    // Wrong witness should fail
    let bad_witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(43), // c (wrong)
        FieldElement::from_u64(6),
        FieldElement::from_u64(7),
        FieldElement::from_u64(42),
    ];
    assert!(rc.cs.verify(&bad_witness).is_err());
}

#[test]
fn test_r1cs_integration_quadratic() {
    // Circuit: prove x^2 + x + 5 == out
    let program = IrLowering::lower_circuit(
        "let result = x ^ 2 + x + 5; assert_eq(result, out)",
        &["out"],
        &["x"],
    )
    .unwrap();

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();

    // x^2 = 1 constraint, assert_eq = 1 constraint
    assert_eq!(rc.cs.num_constraints(), 2);

    // x = 5: x^2 + x + 5 = 25 + 5 + 5 = 35
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(35), // out
        FieldElement::from_u64(5),  // x
        FieldElement::from_u64(25), // x^2 (intermediate)
    ];
    assert!(rc.cs.verify(&witness).is_ok());

    // x = 3: x^2 + x + 5 = 9 + 3 + 5 = 17, but out = 35 -> fail
    let bad_witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(35), // out (expects 35 but circuit computes 17)
        FieldElement::from_u64(3),  // x
        FieldElement::from_u64(9),  // x^2
    ];
    assert!(rc.cs.verify(&bad_witness).is_err());
}

#[test]
fn test_r1cs_integration_scalar_operations() {
    // Circuit: prove 3*a + 2*b == out (0 mul constraints, 1 assert_eq)
    let program =
        IrLowering::lower_circuit("assert_eq(3 * a + 2 * b, out)", &["out"], &["a", "b"]).unwrap();

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();

    // Only the assert_eq generates a constraint
    assert_eq!(rc.cs.num_constraints(), 1);

    // a=4, b=5: 3*4 + 2*5 = 12 + 10 = 22
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(22), // out
        FieldElement::from_u64(4),  // a
        FieldElement::from_u64(5),  // b
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_r1cs_integration_let_chain() {
    // Circuit: let x2 = x * x; let x3 = x2 * x; assert_eq(x3, out)
    let program = IrLowering::lower_circuit(
        "let x2 = x * x; let x3 = x2 * x; assert_eq(x3, out)",
        &["out"],
        &["x"],
    )
    .unwrap();

    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();

    // x*x = 1 constraint, x2*x = 1 constraint, assert_eq = 1 constraint
    assert_eq!(rc.cs.num_constraints(), 3);

    // x = 3: x^3 = 27
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(27), // out
        FieldElement::from_u64(3),  // x
        FieldElement::from_u64(9),  // x2
        FieldElement::from_u64(27), // x3
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}
