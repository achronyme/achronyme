//! Post-O1 witness replay must reproduce the fused-path witness.
//!
//! The fused prove path (`compile_ir_with_witness`) computes the witness
//! during constraint emission — before `optimize_r1cs` — and re-fills
//! substitution-eliminated wires afterward. A reusable prover instead
//! REPLAYS the recorded witness ops after `optimize_r1cs`: same circuit,
//! new inputs, no recompilation.
//!
//! These differentials pin that a `WitnessGenerator` captured AFTER
//! `optimize_r1cs` reproduces the fused witness bit-for-bit. The
//! dangerous case: ops that read wires directly by index (`ArtikCall`
//! inputs in the big-integer hint programs) must still see correct
//! values even when those wires were eliminated as R1CS variables —
//! the replay must compute every recorded wire first and apply the
//! substitution fixup last, exactly like the fused path.

use std::collections::HashMap;
use std::path::Path;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

type Fe = FieldElement<Bn254Fr>;

/// Run the fused pipeline on a fixture, then replay a post-O1
/// `WitnessGenerator` over the same input env and require bit equality.
fn assert_post_o1_replay_matches_fused(fixture: &str, inputs_u64: &[(&str, u64)]) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(format!("test/circomlib/{fixture}"));
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs).expect("fixture must compile");

    let fe_captures: HashMap<String, Fe> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    let inputs: HashMap<String, Fe> = inputs_u64
        .iter()
        .map(|(n, v)| (n.to_string(), Fe::from_u64(*v)))
        .collect();
    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .expect("witness hints");
    for (name, fe) in &fe_captures {
        all_signals.entry(name.clone()).or_insert(*fe);
    }

    // Fused path: witness computed during emission, optimized, re-filled.
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    let mut fused = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .expect("fused compile");
    let stats = compiler.optimize_r1cs();
    assert!(
        stats.variables_eliminated > 0,
        "fixture must exercise substitution elimination for this differential to bite"
    );
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            fused[*var_idx] = lc.evaluate(&fused).expect("fused refill");
        }
    }
    compiler.cs.verify(&fused).expect("fused witness verifies");

    // Reusable-prover flow: generator captured after optimize_r1cs,
    // replayed against the same input env.
    let generator = WitnessGenerator::from_compiler(&compiler);
    let replayed = generator
        .generate(&all_signals)
        .expect("post-O1 replay must execute");

    assert_eq!(replayed.len(), fused.len());
    let mismatches = replayed
        .iter()
        .zip(fused.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(
        mismatches, 0,
        "replayed witness must equal the fused witness on every wire"
    );
    compiler
        .cs
        .verify(&replayed)
        .expect("replayed witness verifies");
}

/// Direct-input shape: the lifted big-integer call reads the circuit's
/// own input signals (protected from substitution). Inputs are the
/// secp256k1 generator G and 2G in 64-bit little-endian limbs.
#[test]
fn post_o1_replay_matches_fused_on_secp_addunequal() {
    assert_post_o1_replay_matches_fused(
        "fn_witness_decompose_secp256k1_addunequal_test.circom",
        &[
            ("x1_0", 0x59F2_815B_16F8_1798),
            ("x1_1", 0x029B_FCDB_2DCE_28D9),
            ("x1_2", 0x55A0_6295_CE87_0B07),
            ("x1_3", 0x79BE_667E_F9DC_BBAC),
            ("y1_0", 0x9C47_D08F_FB10_D4B8),
            ("y1_1", 0xFD17_B448_A685_5419),
            ("y1_2", 0x5DA4_FBFC_0E11_08A8),
            ("y1_3", 0x483A_DA77_26A3_C465),
            ("x2_0", 0xABAC_09B9_5C70_9EE5),
            ("x2_1", 0x5C77_8E4B_8CEF_3CA7),
            ("x2_2", 0x3045_406E_95C0_7CD8),
            ("x2_3", 0xC604_7F94_41ED_7D6D),
            ("y2_0", 0x2364_31A9_50CF_E52A),
            ("y2_1", 0xF7F6_3265_3266_D0E1),
            ("y2_2", 0xA3C5_8419_466C_EAEE),
            ("y2_3", 0x1AE1_68FE_A63D_C339),
        ],
    );
}

/// Eliminated-intermediate shape: the lifted call reads signals that are
/// linear combinations of the inputs, which `optimize_r1cs` substitutes
/// away — the exact shape where a replay that prunes or skips recorded
/// ops diverges from the fused witness.
#[test]
fn post_o1_replay_matches_fused_on_mod_inv_intermediate() {
    assert_post_o1_replay_matches_fused(
        "fn_witness_lift_bigint_mod_inv_intermediate_test.circom",
        &[("a_0", 5), ("a_1", 2), ("p_0", 0xFFFF_FFF9), ("p_1", 0)],
    );
}
