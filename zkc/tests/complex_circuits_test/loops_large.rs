use constraints::poseidon::{poseidon_hash, PoseidonParams};

use super::helpers::{both_verify, fe, inputs, plonkish_verify, r1cs_verify};

#[test]
fn nested_for_accumulation() {
    // 3×3: sum of (i+1)*(j+1) for i in 0..3, j in 0..3
    // = (1*1 + 1*2 + 1*3) + (2*1 + 2*2 + 2*3) + (3*1 + 3*2 + 3*3)
    // = 6 + 12 + 18 = 36
    let source = r#"
let acc = 0
for i in 0..3 {
    for j in 0..3 {
        let acc = acc + (i + 1) * (j + 1)
    }
}
assert_eq(acc, out)
"#;
    let inp = inputs(&[("out", fe(36))]);
    both_verify(source, &["out"], &[], &inp);
}

#[test]
fn triple_nested_for() {
    // 2×3×4 = count iterations
    // sum = sum of 1 for each iteration = 24
    let source = r#"
let acc = 0
for i in 0..2 {
    for j in 0..3 {
        for k in 0..4 {
            let acc = acc + 1
        }
    }
}
assert_eq(acc, out)
"#;
    let inp = inputs(&[("out", fe(24))]);
    both_verify(source, &["out"], &[], &inp);
}

#[test]
fn inner_product_arrays() {
    // dot product: a[0]*b[0] + a[1]*b[1] + a[2]*b[2] + a[3]*b[3]
    // = 1*5 + 2*6 + 3*7 + 4*8 = 5+12+21+32 = 70
    let source = r#"
let a = [a0, a1, a2, a3]
let b = [b0, b1, b2, b3]
let dot = a[0]*b[0] + a[1]*b[1] + a[2]*b[2] + a[3]*b[3]
assert_eq(dot, out)
"#;
    let inp = inputs(&[
        ("out", fe(70)),
        ("a0", fe(1)),
        ("a1", fe(2)),
        ("a2", fe(3)),
        ("a3", fe(4)),
        ("b0", fe(5)),
        ("b1", fe(6)),
        ("b2", fe(7)),
        ("b3", fe(8)),
    ]);
    both_verify(
        source,
        &["out"],
        &["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"],
        &inp,
    );
}

// ============================================================================
// MEDIUM Priority: Large Circuits (2 tests)
// ============================================================================

#[test]
fn large_circuit_poseidon_chain() {
    let params = PoseidonParams::bn254_t3();
    let mut h = fe(0);
    for i in 0..14 {
        h = poseidon_hash(&params, h, fe(i));
    }

    let source = r#"
let h = poseidon(seed, 0)
let h = poseidon(h, 1)
let h = poseidon(h, 2)
let h = poseidon(h, 3)
let h = poseidon(h, 4)
let h = poseidon(h, 5)
let h = poseidon(h, 6)
let h = poseidon(h, 7)
let h = poseidon(h, 8)
let h = poseidon(h, 9)
let h = poseidon(h, 10)
let h = poseidon(h, 11)
let h = poseidon(h, 12)
let h = poseidon(h, 13)
assert_eq(h, expected)
"#;
    let inp = inputs(&[("expected", h), ("seed", fe(0))]);
    let rc = r1cs_verify(source, &["expected"], &["seed"], &inp);
    assert!(
        rc.cs.num_constraints() >= 5000,
        "14 chained poseidons should have ≥5000 constraints, got {}",
        rc.cs.num_constraints()
    );

    plonkish_verify(source, &["expected"], &["seed"], &inp);
}

#[test]
fn large_circuit_mixed_ops() {
    let params = PoseidonParams::bn254_t3();

    // Build expected values
    let a = fe(10);
    let b = fe(20);
    let h1 = poseidon_hash(&params, a, b);
    let h2 = poseidon_hash(&params, h1, a);
    let h3 = poseidon_hash(&params, h2, b);
    let h4 = poseidon_hash(&params, h3, h1);
    let h5 = poseidon_hash(&params, h4, h2);
    let h6 = poseidon_hash(&params, h5, h3);
    let h7 = poseidon_hash(&params, h6, h4);
    let h8 = poseidon_hash(&params, h7, h5);
    let h9 = poseidon_hash(&params, h8, h6);
    let h10 = poseidon_hash(&params, h9, h7);

    let source = r#"
let h1 = poseidon(a, b)
let h2 = poseidon(h1, a)
let h3 = poseidon(h2, b)
let h4 = poseidon(h3, h1)
let h5 = poseidon(h4, h2)
let h6 = poseidon(h5, h3)
let h7 = poseidon(h6, h4)
let h8 = poseidon(h7, h5)
let h9 = poseidon(h8, h6)
let h10 = poseidon(h9, h7)
let lt = a < b
assert(lt)
let r = if lt { h10 } else { h1 }
assert_eq(r, expected)
"#;
    let inp = inputs(&[("expected", h10), ("a", a), ("b", b)]);
    let rc = r1cs_verify(source, &["expected"], &["a", "b"], &inp);
    assert!(
        rc.cs.num_constraints() >= 3600,
        "mixed ops circuit should have ≥3600 constraints, got {}",
        rc.cs.num_constraints()
    );

    plonkish_verify(source, &["expected"], &["a", "b"], &inp);
}

// ============================================================================
