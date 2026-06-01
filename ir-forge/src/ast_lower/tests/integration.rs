use super::*;

// =====================================================================
// Integration tests: real circuit patterns from test/circuit/
// =====================================================================

#[test]
fn integration_basic_arithmetic() {
    let source = "\
        public out\n\
        witness a\n\
        witness b\n\
        let product = a * b\n\
        assert_eq(product, out)\n\
        let sum = a + b\n\
        assert_eq(sum, a + b)\n\
        let diff = b - a\n\
        assert_eq(diff, b - a)\n\
        let doubled = a + a\n\
        assert_eq(doubled, a * 2)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 2);
    assert!(ir.captures.is_empty());
    // 4 Let + 4 AssertEq = 8 nodes
    let asserts = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 4, "expected 4 assert_eq constraints");
}

#[test]
fn integration_nested_functions() {
    let source = "\
        public result\n\
        witness x\n\
        fn square(a) { a * a }\n\
        fn sum_of_squares(a, b) { square(a) + square(b) }\n\
        assert_eq(sum_of_squares(x, x + 1), result)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
}

#[test]
fn integration_poseidon() {
    let source = "\
        public expected\n\
        witness a\n\
        witness b\n\
        witness c\n\
        let h = poseidon(a, b)\n\
        assert_eq(h, expected)\n\
        let folded = poseidon(h, c)\n\
        let many = poseidon_many(a, b, c)\n\
        assert_eq(many, folded)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 3);
    // Should have PoseidonHash and PoseidonMany in Let values
    let has_poseidon = ir.body.iter().any(|n| {
        matches!(
            n,
            CircuitNode::Let {
                value: CircuitExpr::PoseidonHash { .. },
                ..
            }
        )
    });
    assert!(has_poseidon, "expected PoseidonHash in body");
    let has_many = ir.body.iter().any(|n| {
        matches!(
            n,
            CircuitNode::Let {
                value: CircuitExpr::PoseidonMany(_),
                ..
            }
        )
    });
    assert!(has_many, "expected PoseidonMany in body");
}

#[test]
fn integration_power() {
    let source = "\
        public x2\n\
        public x3\n\
        public x4\n\
        witness x\n\
        assert_eq(x ^ 2, x2)\n\
        assert_eq(x ^ 3, x3)\n\
        assert_eq(x ^ 4, x4)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 3);
    assert_eq!(ir.witness_inputs.len(), 1);
    let asserts = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::AssertEq { .. }))
        .count();
    assert_eq!(asserts, 3);
}

#[test]
fn integration_boolean_ops() {
    let source = "\
        witness x\n\
        witness y\n\
        let eq = x == y\n\
        let neq = x != y\n\
        let lt = x < y\n\
        assert(lt)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.witness_inputs.len(), 2);
    assert!(ir
        .body
        .iter()
        .any(|n| matches!(n, CircuitNode::Assert { .. })));
}

#[test]
fn integration_mux() {
    let source = "\
        public out\n\
        witness cond\n\
        witness a\n\
        witness b\n\
        assert_eq(mux(cond, a, b), out)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 3);
}

#[test]
fn integration_range_check() {
    let source = "\
        witness x\n\
        witness y\n\
        range_check(x, 8)\n\
        range_check(y, 16)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.witness_inputs.len(), 2);
    // range_check calls become Expr nodes with RangeCheck
    let has_range = ir.body.iter().any(|n| {
        matches!(
            n,
            CircuitNode::Expr {
                expr: CircuitExpr::RangeCheck { .. },
                ..
            }
        )
    });
    assert!(has_range, "expected RangeCheck in body");
}

#[test]
fn integration_if_else_circuit() {
    let source = "\
        public out\n\
        witness x\n\
        witness cond\n\
        let result = if cond { x * 2 } else { x + 1 }\n\
        assert_eq(result, out)";
    let ir = compile_circuit(source).unwrap();
    // body[0]: $condN temp, body[1]: result = Mux(...)
    assert!(
        matches!(&ir.body[0], CircuitNode::Let { name, .. } if name.starts_with("$cond")),
        "expected $cond temp, got {:?}",
        ir.body[0]
    );
    if let CircuitNode::Let { value, .. } = &ir.body[1] {
        assert!(
            matches!(value, CircuitExpr::Mux { .. }),
            "expected Mux, got {value:?}"
        );
    } else {
        panic!("expected Let, got {:?}", ir.body[1]);
    }
}

#[test]
fn integration_mut_accumulator() {
    // The pattern that was IMPOSSIBLE before ProveIR
    let source = "\
        public total\n\
        witness vals[4]\n\
        mut sum = Field::ZERO\n\
        sum = sum + vals_0\n\
        sum = sum + vals_1\n\
        sum = sum + vals_2\n\
        sum = sum + vals_3\n\
        assert_eq(sum, total)";
    let ir = compile_circuit(source).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.witness_inputs.len(), 1);
    // sum, sum$v1, sum$v2, sum$v3, sum$v4, assert_eq = 6 nodes
    let lets = ir
        .body
        .iter()
        .filter(|n| matches!(n, CircuitNode::Let { .. }))
        .count();
    assert!(lets >= 5, "expected 5 Let nodes (SSA), got {lets}");
}

#[test]
fn integration_static_namespaces_in_circuit() {
    // Another pattern IMPOSSIBLE before ProveIR
    let source = "\
        public out\n\
        witness x\n\
        let zero = Field::ZERO\n\
        let one = Field::ONE\n\
        assert_eq(x + zero, x)\n\
        assert_eq(x * one, out)";
    let ir = compile_circuit(source).unwrap();
    // Field::ZERO and Field::ONE should compile to constants
    if let CircuitNode::Let { value, name, .. } = &ir.body[0] {
        assert_eq!(name, "zero");
        assert_eq!(*value, CircuitExpr::Const(FieldConst::zero()));
    }
    if let CircuitNode::Let { value, name, .. } = &ir.body[1] {
        assert_eq!(name, "one");
        assert_eq!(*value, CircuitExpr::Const(FieldConst::one()));
    }
}

#[test]
fn integration_method_desugaring_in_circuit() {
    // Yet another pattern IMPOSSIBLE before ProveIR
    let source = "\
        public out\n\
        witness x\n\
        witness y\n\
        let m = x.min(y)\n\
        assert_eq(m, out)";
    let ir = compile_circuit(source).unwrap();
    // .min() desugars to Mux(Lt(x, y), x, y)
    if let CircuitNode::Let { value, .. } = &ir.body[0] {
        assert!(
            matches!(value, CircuitExpr::Mux { .. }),
            "expected .min() to desugar to Mux, got {value:?}"
        );
    }
}

#[test]
fn integration_prove_block_with_captures() {
    // Simulate a prove block: outer scope has secret and hash
    let source = "\
        public hash\n\
        assert_eq(poseidon(secret, Field::ZERO), hash)";
    let ir = compile_prove_block(source, &["secret", "hash"]).unwrap();
    assert_eq!(ir.public_inputs.len(), 1);
    assert_eq!(ir.public_inputs[0].name, "hash");
    assert_eq!(ir.captures.len(), 1);
    assert_eq!(ir.captures[0].name, "secret");
    assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
}
