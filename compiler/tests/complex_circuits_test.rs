//! Complex integration tests for Achronyme circuits.
//!
//! Covers large Merkle trees, nullifier/commitment patterns, hash chains,
//! function chaining, boolean logic chains, nested loops, and negative tests.

use std::collections::HashMap;

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(n: u64) -> FieldElement {
    FieldElement::from_u64(n)
}

fn inputs(pairs: &[(&str, FieldElement)]) -> HashMap<String, FieldElement> {
    pairs.iter().map(|(n, v)| (n.to_string(), *v)).collect()
}

/// Compile source → IR → R1CS → witness → verify. Returns the compiler.
fn r1cs_verify(
    source: &str,
    pub_names: &[&str],
    wit_names: &[&str],
    inp: &HashMap<String, FieldElement>,
) -> R1CSCompiler {
    let mut program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::new();
    rc.set_proven_boolean(proven);
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(inp).unwrap();
    rc.cs.verify(&w).unwrap();
    rc
}

/// Compile source → IR → Plonkish → witness → verify. Returns the compiler.
fn plonkish_verify(
    source: &str,
    pub_names: &[&str],
    wit_names: &[&str],
    inp: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let program = IrLowering::lower_circuit(source, pub_names, wit_names).unwrap();
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(inp, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler.system.verify().expect("verification failed");
    compiler
}

/// Verify on both R1CS and Plonkish backends.
fn both_verify(
    source: &str,
    pub_names: &[&str],
    wit_names: &[&str],
    inp: &HashMap<String, FieldElement>,
) {
    r1cs_verify(source, pub_names, wit_names, inp);
    plonkish_verify(source, pub_names, wit_names, inp);
}

/// Build a power-of-2 Merkle tree from leaves, returning the root.
fn build_merkle_tree(params: &PoseidonParams, leaves: &[FieldElement]) -> FieldElement {
    assert!(leaves.len().is_power_of_two() && leaves.len() >= 2);
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(poseidon_hash(params, pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Get the Merkle proof (siblings, direction_bits) for a leaf at `index`.
fn merkle_proof(
    params: &PoseidonParams,
    leaves: &[FieldElement],
    index: usize,
) -> (Vec<FieldElement>, Vec<FieldElement>) {
    assert!(leaves.len().is_power_of_two());
    let depth = (leaves.len() as f64).log2() as usize;
    let mut level = leaves.to_vec();
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    let mut idx = index;
    for _ in 0..depth {
        let sibling_idx = idx ^ 1;
        siblings.push(level[sibling_idx]);
        directions.push(fe((idx & 1) as u64));
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(poseidon_hash(params, pair[0], pair[1]));
        }
        level = next;
        idx >>= 1;
    }
    (siblings, directions)
}

/// Build Merkle source for a given depth using mux+poseidon pattern.
fn merkle_source(depth: usize) -> String {
    let mut lines = Vec::new();
    for i in 0..depth {
        let prev = if i == 0 {
            "leaf".to_string()
        } else {
            format!("h{}", i - 1)
        };
        lines.push(format!("let l{i} = mux(d{i}, s{i}, {prev})"));
        lines.push(format!("let r{i} = mux(d{i}, {prev}, s{i})"));
        lines.push(format!("let h{i} = poseidon(l{i}, r{i})"));
    }
    lines.push(format!("assert_eq(h{}, root)", depth - 1));
    lines.join("\n")
}

/// Build inputs map for a Merkle proof.
fn merkle_inputs(
    root: FieldElement,
    leaf: FieldElement,
    siblings: &[FieldElement],
    directions: &[FieldElement],
) -> HashMap<String, FieldElement> {
    let mut m = HashMap::new();
    m.insert("root".into(), root);
    m.insert("leaf".into(), leaf);
    for (i, s) in siblings.iter().enumerate() {
        m.insert(format!("s{i}"), *s);
    }
    for (i, d) in directions.iter().enumerate() {
        m.insert(format!("d{i}"), *d);
    }
    m
}

/// Build witness name list for a Merkle proof of given depth.
fn merkle_wit_names(depth: usize) -> Vec<String> {
    let mut names = vec!["leaf".to_string()];
    for i in 0..depth {
        names.push(format!("s{i}"));
    }
    for i in 0..depth {
        names.push(format!("d{i}"));
    }
    names
}

// ============================================================================
// HIGH Priority: Large Merkle Trees (4 tests)
// ============================================================================

#[test]
fn merkle_depth8_256_leaves() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..256).map(|i| fe(i + 1000)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 137;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inp = merkle_inputs(root, leaves[index], &siblings, &directions);

    let source = merkle_source(8);
    let wit_names = merkle_wit_names(8);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let rc = r1cs_verify(&source, &["root"], &wit_refs, &inp);
    // 8 levels × (2 mux + 1 poseidon) + 1 assert_eq ≈ 8×(4+361) + 1 = 5793
    assert!(
        rc.cs.num_constraints() > 2900,
        "expected >2900 constraints for depth-8 Merkle, got {}",
        rc.cs.num_constraints()
    );
}

#[test]
fn merkle_depth8_wrong_leaf_fails() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..256).map(|i| fe(i + 1000)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 137;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let wrong_leaf = fe(99999);
    let inp = merkle_inputs(root, wrong_leaf, &siblings, &directions);

    let source = merkle_source(8);
    let wit_names = merkle_wit_names(8);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let mut program = IrLowering::lower_circuit(&source, &["root"], &wit_refs).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong leaf should fail verification"
    );
}

#[test]
fn merkle_depth8_corner_positions() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..256).map(|i| fe(i + 500)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let source = merkle_source(8);
    let wit_names = merkle_wit_names(8);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    for &index in &[0, 127, 128, 255] {
        let (siblings, directions) = merkle_proof(&params, &leaves, index);
        let inp = merkle_inputs(root, leaves[index], &siblings, &directions);
        r1cs_verify(&source, &["root"], &wit_refs, &inp);
    }
}

#[test]
#[ignore]
fn merkle_depth16_65536_leaves() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..65536).map(|i| fe(i as u64)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 31337;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inp = merkle_inputs(root, leaves[index], &siblings, &directions);

    let source = merkle_source(16);
    let wit_names = merkle_wit_names(16);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let rc = r1cs_verify(&source, &["root"], &wit_refs, &inp);
    assert!(
        rc.cs.num_constraints() > 5800,
        "expected >5800 constraints for depth-16 Merkle, got {}",
        rc.cs.num_constraints()
    );
}

// ============================================================================
// HIGH Priority: Real-World ZK Patterns (8 tests)
// ============================================================================

#[test]
fn nullifier_derivation() {
    let params = PoseidonParams::bn254_t3();
    let secret = fe(12345);
    let leaf_index = fe(7);
    let nullifier = poseidon_hash(&params, secret, leaf_index);

    let source = r#"
let nf = poseidon(secret, leaf_index)
assert_eq(nf, nullifier)
"#;
    let inp = inputs(&[
        ("nullifier", nullifier),
        ("secret", secret),
        ("leaf_index", leaf_index),
    ]);
    both_verify(source, &["nullifier"], &["secret", "leaf_index"], &inp);
}

#[test]
fn commitment_scheme() {
    let params = PoseidonParams::bn254_t3();
    let value = fe(1000);
    let blinding = fe(98765);
    let commitment = poseidon_hash(&params, value, blinding);

    let source = r#"
let cm = poseidon(value, blinding)
assert_eq(cm, commitment)
"#;
    let inp = inputs(&[
        ("commitment", commitment),
        ("value", value),
        ("blinding", blinding),
    ]);
    both_verify(source, &["commitment"], &["value", "blinding"], &inp);
}

#[test]
fn commitment_wrong_blinding_fails() {
    let params = PoseidonParams::bn254_t3();
    let value = fe(1000);
    let blinding = fe(98765);
    let commitment = poseidon_hash(&params, value, blinding);

    let source = "let cm = poseidon(value, blinding)\nassert_eq(cm, commitment)";
    let wrong_blinding = fe(11111);
    let inp = inputs(&[
        ("commitment", commitment),
        ("value", value),
        ("blinding", wrong_blinding),
    ]);

    let mut program =
        IrLowering::lower_circuit(source, &["commitment"], &["value", "blinding"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong blinding should fail verification"
    );
}

#[test]
fn tornado_cash_pattern() {
    let params = PoseidonParams::bn254_t3();

    let secret = fe(42424242);
    let leaf_index = fe(3);
    let blinding = fe(77777);

    // Commitment = poseidon(secret, blinding)
    let commitment = poseidon_hash(&params, secret, blinding);
    // Nullifier = poseidon(secret, leaf_index)
    let nullifier = poseidon_hash(&params, secret, leaf_index);

    // Build a small 8-leaf tree with the commitment at index 3
    let mut leaves: Vec<FieldElement> = (0..8).map(|i| fe(i + 100)).collect();
    leaves[3] = commitment;
    let root = build_merkle_tree(&params, &leaves);

    let (siblings, directions) = merkle_proof(&params, &leaves, 3);

    // Circuit: prove commitment in tree AND derive nullifier
    let source = r#"
let cm = poseidon(secret, blinding)

let l0 = mux(d0, s0, cm)
let r0 = mux(d0, cm, s0)
let h0 = poseidon(l0, r0)

let l1 = mux(d1, s1, h0)
let r1 = mux(d1, h0, s1)
let h1 = poseidon(l1, r1)

let l2 = mux(d2, s2, h1)
let r2 = mux(d2, h1, s2)
let h2 = poseidon(l2, r2)

assert_eq(h2, root)

let nf = poseidon(secret, leaf_index)
assert_eq(nf, nullifier)
"#;

    let mut inp = HashMap::new();
    inp.insert("root".into(), root);
    inp.insert("nullifier".into(), nullifier);
    inp.insert("secret".into(), secret);
    inp.insert("blinding".into(), blinding);
    inp.insert("leaf_index".into(), leaf_index);
    for (i, s) in siblings.iter().enumerate() {
        inp.insert(format!("s{i}"), *s);
    }
    for (i, d) in directions.iter().enumerate() {
        inp.insert(format!("d{i}"), *d);
    }

    let rc = r1cs_verify(
        source,
        &["root", "nullifier"],
        &[
            "secret",
            "blinding",
            "leaf_index",
            "s0",
            "s1",
            "s2",
            "d0",
            "d1",
            "d2",
        ],
        &inp,
    );
    // commitment hash + 3-level merkle + nullifier hash = 5×361 + 6 mux + 2 assert_eq ≈ 1819
    assert!(
        rc.cs.num_constraints() > 1800,
        "tornado pattern should have >1800 constraints, got {}",
        rc.cs.num_constraints()
    );
}

#[test]
fn hash_chain_10() {
    let params = PoseidonParams::bn254_t3();
    let mut h = fe(0);
    for i in 0..10 {
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
assert_eq(h, expected)
"#;
    let inp = inputs(&[("expected", h), ("seed", fe(0))]);
    let rc = r1cs_verify(source, &["expected"], &["seed"], &inp);
    // 10 poseidons × 361 + 1 assert_eq = 3611
    assert!(
        rc.cs.num_constraints() > 3600,
        "10-chain should have >3600 constraints, got {}",
        rc.cs.num_constraints()
    );
}

#[test]
fn selective_disclosure_age() {
    let source = r#"
let old_enough = age >= 18
assert(old_enough)
"#;
    let inp = inputs(&[("age", fe(25))]);
    both_verify(source, &[], &["age"], &inp);
}

#[test]
fn selective_disclosure_underage_fails() {
    let source = "let old_enough = age >= 18\nassert(old_enough)";
    let inp = inputs(&[("age", fe(15))]);

    let mut program = IrLowering::lower_circuit(source, &[], &["age"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "underage should fail assertion");
}

#[test]
fn selective_disclosure_with_commitment() {
    let params = PoseidonParams::bn254_t3();
    let age = fe(25);
    let blinding = fe(55555);
    let commitment = poseidon_hash(&params, age, blinding);

    let source = r#"
let cm = poseidon(age, blinding)
assert_eq(cm, commitment)
let old_enough = age >= 18
assert(old_enough)
"#;
    let inp = inputs(&[
        ("commitment", commitment),
        ("age", age),
        ("blinding", blinding),
    ]);
    r1cs_verify(source, &["commitment"], &["age", "blinding"], &inp);
}

// ============================================================================
// MEDIUM Priority: Function Inlining (4 tests)
// ============================================================================

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
// ============================================================================

#[test]
fn boolean_chain_true() {
    // (a < b) && (c > d) || !(e == f) with a=3,b=7,c=10,d=2,e=1,f=2
    // (3<7)=T && (10>2)=T || !(1==2)=T → T && T || T = T
    let source = r#"
let r = (a < b) && (c > d) || !(e == f)
assert(r)
"#;
    let inp = inputs(&[
        ("a", fe(3)),
        ("b", fe(7)),
        ("c", fe(10)),
        ("d", fe(2)),
        ("e", fe(1)),
        ("f", fe(2)),
    ]);
    both_verify(source, &[], &["a", "b", "c", "d", "e", "f"], &inp);
}

#[test]
fn boolean_chain_false() {
    // (a < b) && (c > d) || !(e == f) with a=7,b=3,c=2,d=10,e=5,f=5
    // (7<3)=F && (2>10)=F || !(5==5)=F → F && F || F = F
    let source = r#"
let r = (a < b) && (c > d) || !(e == f)
assert_eq(r, expected)
"#;
    let inp = inputs(&[
        ("expected", fe(0)),
        ("a", fe(7)),
        ("b", fe(3)),
        ("c", fe(2)),
        ("d", fe(10)),
        ("e", fe(5)),
        ("f", fe(5)),
    ]);
    r1cs_verify(source, &["expected"], &["a", "b", "c", "d", "e", "f"], &inp);
}

#[test]
fn boolean_with_mux() {
    // if (a < b) && !(c == d) { x } else { y }
    // a=3,b=7,c=1,d=2 → (T) && (T) = T → x=100
    let source = r#"
let cond = (a < b) && !(c == d)
let r = if cond { x } else { y }
assert_eq(r, out)
"#;
    let inp = inputs(&[
        ("out", fe(100)),
        ("a", fe(3)),
        ("b", fe(7)),
        ("c", fe(1)),
        ("d", fe(2)),
        ("x", fe(100)),
        ("y", fe(200)),
    ]);
    both_verify(source, &["out"], &["a", "b", "c", "d", "x", "y"], &inp);
}

#[test]
fn boolean_chain_constraint_count() {
    // Complex boolean expression should produce many constraints
    let source = r#"
let r1 = a < b
let r2 = c > d
let r3 = e == f
let r4 = r1 && r2
let r5 = !r3
let r6 = r4 || r5
assert(r6)
"#;
    let inp = inputs(&[
        ("a", fe(3)),
        ("b", fe(7)),
        ("c", fe(10)),
        ("d", fe(2)),
        ("e", fe(1)),
        ("f", fe(2)),
    ]);
    let rc = r1cs_verify(source, &[], &["a", "b", "c", "d", "e", "f"], &inp);
    // 2 IsLt (~760 each) + 1 IsEq (2) + And (3) + Not (1) + Or (3) + Assert (2) ≈ 1531
    assert!(
        rc.cs.num_constraints() > 1500,
        "boolean chain should have >1500 constraints, got {}",
        rc.cs.num_constraints()
    );
}

// ============================================================================
// MEDIUM Priority: Nested For Loops (3 tests)
// ============================================================================

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
}

// ============================================================================
// MEDIUM Priority: Negative Tests (6 tests)
// ============================================================================

#[test]
fn negative_wrong_poseidon_preimage() {
    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(&params, fe(1), fe(2));

    let source = "let h = poseidon(a, b)\nassert_eq(h, expected)";
    let inp = inputs(&[("expected", expected), ("a", fe(99)), ("b", fe(88))]);

    let mut program = IrLowering::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong Poseidon preimage should fail"
    );
}

#[test]
fn negative_assert_false() {
    let source = "assert(flag)";
    let inp = inputs(&[("flag", fe(0))]);

    let mut program = IrLowering::lower_circuit(source, &[], &["flag"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "assert(0) should fail");
}

#[test]
fn negative_comparison_wrong() {
    let source = "let r = a >= b\nassert(r)";
    let inp = inputs(&[("a", fe(3)), ("b", fe(7))]);

    let mut program = IrLowering::lower_circuit(source, &[], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "3 >= 7 should fail assertion");
}

#[test]
fn negative_recursion_rejected() {
    let source = r#"
fn f(x) { f(x) }
assert_eq(f(a), out)
"#;
    let result = IrLowering::lower_circuit(source, &["out"], &["a"]);
    assert!(result.is_err(), "recursion should be rejected at lowering");
}

#[test]
fn negative_merkle_wrong_sibling() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..8).map(|i| fe(i + 100)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 2;
    let (mut siblings, directions) = merkle_proof(&params, &leaves, index);
    siblings[0] = fe(99999); // corrupt sibling
    let inp = merkle_inputs(root, leaves[index], &siblings, &directions);

    let source = merkle_source(3);
    let wit_names = merkle_wit_names(3);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let mut program = IrLowering::lower_circuit(&source, &["root"], &wit_refs).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong sibling should fail verification"
    );
}

#[test]
fn negative_division_by_zero() {
    let source = "let r = x / y\nassert_eq(r, out)";
    let inp = inputs(&[("x", fe(42)), ("y", fe(0)), ("out", fe(0))]);

    let mut program = IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "division by zero should fail");
}
