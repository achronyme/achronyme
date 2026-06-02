use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::IrLowering;
use memory::FieldElement;
use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

use super::helpers::{
    both_verify, build_merkle_tree, fe, inputs, merkle_proof, plonkish_verify, r1cs_verify,
};

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

    // Also verify Plonkish rejects wrong blinding
    let program_p =
        IrLowering::lower_circuit(source, &["commitment"], &["value", "blinding"]).unwrap();
    let mut pc = PlonkishCompiler::new();
    pc.compile_ir(&program_p).expect("compilation failed");
    let wg_p = PlonkishWitnessGenerator::from_compiler(&pc);
    wg_p.generate(&inp, &mut pc.system.assignments)
        .expect("witness gen failed");
    assert!(
        pc.system.verify().is_err(),
        "wrong blinding should fail Plonkish verification"
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

    plonkish_verify(
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

    plonkish_verify(source, &["expected"], &["seed"], &inp);
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

    // Also verify Plonkish rejects underage
    let program_p = IrLowering::lower_circuit(source, &[], &["age"]).unwrap();
    let mut pc = PlonkishCompiler::new();
    let err = pc.compile_ir_with_witness(&program_p, &inp);
    assert!(err.is_err(), "underage should fail Plonkish assertion");
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
    both_verify(source, &["commitment"], &["age", "blinding"], &inp);
}

// ============================================================================
// MEDIUM Priority: Function Inlining (4 tests)
