use compiler::r1cs_backend::R1CSCompiler;
use compiler::r1cs_error::R1CSError;
use memory::FieldElement;

// ====================================================================
// For unrolling tests
// ====================================================================

#[test]
fn test_for_static_range_constraint_count() {
    // for i in 0..3 { let step = a * a } -> 3 mul constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit("for i in 0..3 { let step = a * a }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_for_empty_range() {
    // for i in 0..0 { ... } -> 0 iterations, 0 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit("for i in 0..0 { let step = a * a }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_for_iterator_as_constant() {
    // for i in 0..3 { let x = a * i }
    // i=0: a*0 = constant mul -> 0 constraints
    // i=1: a*1 = scalar mul -> 0 constraints
    // i=2: a*2 = scalar mul -> 0 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit("for i in 0..3 { let x = a * i }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "multiplying by constant iterator should be free");
}

#[test]
fn test_for_nested() {
    // Nested for: outer 0..2, inner 0..3, body = a * a (1 constraint)
    // Total: 2 * 3 * 1 = 6 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    rc.compile_circuit(
        "for i in 0..2 { for j in 0..3 { let step = a * a } }"
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 6);
}

#[test]
fn test_for_integration_with_witness() {
    // Circuit: accumulate a * a three times, assert result
    // for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit(
        "for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)"
    ).unwrap();

    // 3 mul inside loop + 1 mul for final a*b + 1 assert_eq = 5
    assert_eq!(rc.cs.num_constraints(), 5);

    // a=3, b=7: a*b = 21
    // Wire layout: ONE, out, a, b, prod_0, prod_1, prod_2, final_prod
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(21), // out (public)
        FieldElement::from_u64(3),  // a
        FieldElement::from_u64(7),  // b
        FieldElement::from_u64(21), // prod (iter 0)
        FieldElement::from_u64(21), // prod (iter 1)
        FieldElement::from_u64(21), // prod (iter 2)
        FieldElement::from_u64(21), // final a*b
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_for_non_literal_rejected() {
    // for i in expr (not a range) -> error
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("a");
    let err = rc.compile_circuit("for i in a { let x = 1 }").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

// ====================================================================
// If/MUX tests
// ====================================================================

#[test]
fn test_if_else_two_constraints() {
    // if flag { a } else { b } -> 1 boolean check + 1 MUX mul = 2 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.compile_circuit("if flag { a } else { b }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_if_without_else() {
    // if flag { a } -> else defaults to 0, still 2 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.compile_circuit("if flag { a }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_if_else_integration_flag_one() {
    // if flag { a } else { b } with flag=1 -> result should be a
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit("let result = if flag { a } else { b }; assert_eq(result, out)")
        .unwrap();

    // 2 (if/mux) + 1 (assert_eq) = 3
    assert_eq!(rc.cs.num_constraints(), 3);

    // flag=1, a=42, b=99 -> result = a = 42
    // Wire layout: ONE, out, flag, a, b, mux_product (flag*(a-b))
    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let diff = a_val.sub(&b_val); // a - b
    let witness = vec![
        FieldElement::ONE,
        a_val,                     // out = 42 (selected a)
        FieldElement::ONE,         // flag = 1
        a_val,                     // a = 42
        b_val,                     // b = 99
        diff,                      // flag * (a - b) = 1 * (42 - 99)
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_if_else_integration_flag_zero() {
    // if flag { a } else { b } with flag=0 -> result should be b
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit("let result = if flag { a } else { b }; assert_eq(result, out)")
        .unwrap();

    // flag=0, a=42, b=99 -> result = b = 99
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(99), // out = 99 (selected b)
        FieldElement::ZERO,         // flag = 0
        FieldElement::from_u64(42), // a
        FieldElement::from_u64(99), // b
        FieldElement::ZERO,         // flag * (a - b) = 0
    ];
    assert!(rc.cs.verify(&witness).is_ok());
}

#[test]
fn test_if_else_boolean_enforcement() {
    // if flag { a } else { b } with flag=2 -> boolean check fails
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");

    rc.compile_circuit("let result = if flag { a } else { b }; assert_eq(result, out)")
        .unwrap();

    // flag=2 violates cond*(1-cond)=0: 2*(1-2) = 2*(-1) = -2 != 0
    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let flag_val = FieldElement::from_u64(2);
    let diff = a_val.sub(&b_val);
    let mux_prod = flag_val.mul(&diff); // 2 * (42-99)
    // result = mux_prod + b
    let result = mux_prod.add(&b_val);
    let witness = vec![
        FieldElement::ONE,
        result,    // out
        flag_val,  // flag = 2 (invalid!)
        a_val,     // a
        b_val,     // b
        mux_prod,  // flag * (a - b)
    ];
    assert!(rc.cs.verify(&witness).is_err(), "flag=2 should fail boolean enforcement");
}

#[test]
fn test_if_nested_mux() {
    // if c1 { a } else { if c2 { b } else { c } }
    // Outer: 2 constraints, inner: 2 constraints -> 4 total
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("c1");
    rc.declare_witness("c2");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.compile_circuit("if c1 { a } else { if c2 { b } else { c } }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 4);
}

#[test]
fn test_if_with_arithmetic_branches() {
    // if flag { a * b } else { c + d }
    // a*b = 1 mul constraint (in then branch)
    // c+d = 0 constraints (in else branch)
    // MUX = 2 constraints (boolean + mul)
    // Total = 3
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.declare_witness("d");
    rc.compile_circuit("if flag { a * b } else { c + d }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_if_else_if_chain() {
    // if c1 { a } else if c2 { b } else { c }
    // This parses as: if c1 { a } else { if c2 { b } else { c } }
    // Each if level = 2 constraints -> 4 total
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("c1");
    rc.declare_witness("c2");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    // pest grammar: "else" ~ (block | if_expr) -- "else if" matches as else + if_expr
    rc.compile_circuit("if c1 { a } else if c2 { b } else { c }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 4);
}

// ====================================================================
// Rejection tests
// ====================================================================

#[test]
fn test_while_rejected() {
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("x");
    let err = rc.compile_circuit("while x { let a = 1 }").unwrap_err();
    assert!(matches!(err, R1CSError::UnboundedLoop(..)));
}

#[test]
fn test_forever_rejected() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("forever { let a = 1 }").unwrap_err();
    assert!(matches!(err, R1CSError::UnboundedLoop(..)));
}

#[test]
fn test_fn_rejected() {
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_circuit("fn foo() { 1 }").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

#[test]
fn test_break_rejected() {
    let mut rc = R1CSCompiler::new();
    // break inside a for loop -- still rejected in circuits
    let err = rc.compile_circuit("for i in 0..3 { break }").unwrap_err();
    assert!(matches!(err, R1CSError::UnsupportedOperation(..)));
}

// ====================================================================
// Integration tests: control flow + witness verification
// ====================================================================

#[test]
fn test_for_with_if_inside() {
    // for i in 0..2 { if flag { a * b } else { c } }
    // Each iteration: 1 mul (a*b) + 2 MUX constraints = 3
    // 2 iterations -> 6 constraints
    let mut rc = R1CSCompiler::new();
    rc.declare_witness("flag");
    rc.declare_witness("a");
    rc.declare_witness("b");
    rc.declare_witness("c");
    rc.compile_circuit("for i in 0..2 { if flag { a * b } else { c } }").unwrap();
    assert_eq!(rc.cs.num_constraints(), 6);
}

#[test]
fn test_full_circuit_with_control_flow() {
    // Realistic circuit: compute x^2 conditionally, accumulate in a loop
    // for i in 0..2 { let step = x * x }
    // let result = if flag { x * x } else { x + 1 }
    // assert_eq(result, out)
    let mut rc = R1CSCompiler::new();
    rc.declare_public("out");
    rc.declare_witness("x");
    rc.declare_witness("flag");

    rc.compile_circuit(
        "for i in 0..2 { let step = x * x }; \
         let result = if flag { x * x } else { x + 1 }; \
         assert_eq(result, out)"
    ).unwrap();

    // Loop: 2 * 1 = 2 constraints (x*x each iteration)
    // If: 1 (x*x in then) + 2 (boolean + MUX) = 3 constraints
    // assert_eq: 1 constraint
    // Total: 2 + 3 + 1 = 6
    assert_eq!(rc.cs.num_constraints(), 6);

    // flag=1, x=5: result = x*x = 25
    // Wire layout: ONE, out, x, flag, step_0(25), step_1(25), then_mul(25), mux_prod
    let x_val = FieldElement::from_u64(5);
    let x_sq = FieldElement::from_u64(25);
    // then branch = x*x = 25, else branch = x+1 = 6
    // diff = then - else = 25 - 6 = 19
    let else_val = x_val.add(&FieldElement::ONE); // 6
    let diff = x_sq.sub(&else_val); // 19
    let mux_prod = FieldElement::ONE.mul(&diff); // flag * diff = 1 * 19 = 19

    let witness = vec![
        FieldElement::ONE,    // ONE wire
        x_sq,                 // out = 25
        x_val,                // x = 5
        FieldElement::ONE,    // flag = 1
        x_sq,                 // step_0 = x*x = 25
        x_sq,                 // step_1 = x*x = 25
        x_sq,                 // then branch x*x = 25
        mux_prod,             // flag * (then - else) = 19
    ];
    assert!(rc.cs.verify(&witness).is_ok());

    // flag=0, x=5: result = x+1 = 6
    let result_b = else_val; // 6
    let mux_prod_0 = FieldElement::ZERO; // 0 * diff = 0

    let witness_b = vec![
        FieldElement::ONE,
        result_b,              // out = 6
        x_val,                 // x = 5
        FieldElement::ZERO,    // flag = 0
        x_sq,                  // step_0 = 25
        x_sq,                  // step_1 = 25
        x_sq,                  // then branch x*x = 25 (still computed)
        mux_prod_0,            // flag * (then - else) = 0
    ];
    assert!(rc.cs.verify(&witness_b).is_ok());
}
