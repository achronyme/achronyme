//! Regression pin: a repeatedly-instantiated cacheable component body
//! whose lowering lifts constant outputs is deferred to a single
//! `ComponentCall`, and its constant outputs are replayed (mangled
//! per instance) into the parent instead of re-scanned from inlined
//! nodes. The second instance is a cache hit exercising that replay;
//! if the replay dropped or mis-mangled a constant output the second
//! instance's constraints would be inconsistent with the witness and
//! verification would fail. See
//! `test/circomlib/deferred_const_output_test.circom`.

use std::collections::HashMap;
use std::path::Path;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

#[test]
fn deferred_const_output_replay_r1cs_verifies() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/deferred_const_output_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result =
        circom::compile_file(&path, &lib_dirs).expect("DeferredConstOutput compile failed");
    let prove_ir = &compile_result.prove_ir;

    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .expect("DeferredConstOutput instantiation failed");
    ir::passes::optimize(&mut program);

    // Distinct runtime inputs so each Num2BitsLocal(8) instance is
    // cacheable (runtime-signal input, no const inputs / array args):
    // one eager lowering + one deferred cache hit.
    let a: u64 = 0b1011_0101; // 181
    let b: u64 = 0b0110_1010; // 106
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(a));
    user_inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(b));

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    )
    .expect("DeferredConstOutput witness computation failed");
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &all_signals)
        .expect("DeferredConstOutput R1CS compilation failed");

    r1cs.cs.verify(&witness).expect(
        "DeferredConstOutput R1CS verification failed — deferred \
         const-output replay diverged from eager inlining",
    );
}
