use constraints::poseidon::{poseidon_hash, PoseidonParams};

use super::helpers::{both_verify, fe, inputs};

#[test]
fn function_chain_3_levels() {
    // add1 → double_add1 → quad_add1
    let source = r#"
fn add1(x) { x + 1 }
fn double_add1(x) { add1(x) + add1(x) }
fn quad_add1(x) { double_add1(x) + double_add1(x) }
assert_eq(quad_add1(a), out)
"#;
    // a=10 → add1(10)=11, double_add1(10)=22, quad_add1(10)=44
    let inp = inputs(&[("out", fe(44)), ("a", fe(10))]);
    both_verify(source, &["out"], &["a"], &inp);
}

#[test]
fn function_chain_4_levels() {
    let source = r#"
fn f1(x) { x * x }
fn f2(x) { f1(x) + 1 }
fn f3(x) { f2(x) * 2 }
fn f4(x) { f3(x) - 3 }
assert_eq(f4(a), out)
"#;
    // a=5 → f1=25, f2=26, f3=52, f4=49
    let inp = inputs(&[("out", fe(49)), ("a", fe(5))]);
    both_verify(source, &["out"], &["a"], &inp);
}

#[test]
fn function_multiple_call_sites() {
    let source = r#"
fn double(x) { x + x }
let a2 = double(a)
let b2 = double(b)
let c2 = double(c)
assert_eq(a2 + b2 + c2, out)
"#;
    // a=3, b=5, c=7 → 6+10+14=30
    let inp = inputs(&[("out", fe(30)), ("a", fe(3)), ("b", fe(5)), ("c", fe(7))]);
    both_verify(source, &["out"], &["a", "b", "c"], &inp);
}

#[test]
fn function_with_poseidon() {
    let params = PoseidonParams::bn254_t3();
    let a = fe(1);
    let b = fe(2);
    let c = fe(3);
    let h_ab = poseidon_hash(&params, a, b);
    let h_abc = poseidon_hash(&params, h_ab, c);

    let source = r#"
fn hash_pair(x, y) { poseidon(x, y) }
fn hash_triple(x, y, z) { hash_pair(hash_pair(x, y), z) }
assert_eq(hash_triple(a, b, c), out)
"#;
    let inp = inputs(&[("out", h_abc), ("a", a), ("b", b), ("c", c)]);
    both_verify(source, &["out"], &["a", "b", "c"], &inp);
}

// ============================================================================
// MEDIUM Priority: Boolean Logic Chains (4 tests)
