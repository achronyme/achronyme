use std::collections::HashMap;

use circom::{compile_file, compile_template_library, instantiate_template_into};
use ir_core::IrType;
use ir_forge::types::{CircuitExpr, FieldConst, ProveIR};
use memory::{Bn254Fr, FieldElement};

use super::common::{dummy_span, lib_dirs, workspace_root};
use super::stats::{collect_circuit_node_stats, collect_extended_stats};

// ---------------------------------------------------------------------------
// Side A — pure-circom (top-level Sha256(64) entry, works today)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn probe_pure_circom_sha256_64() {
    let path = workspace_root().join("test/circomlib/sha256_test.circom");
    let result = compile_file(&path, &lib_dirs()).expect("compile pure-circom Sha256(64)");
    let prove_ir = result.prove_ir;

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SIDE A — pure-circom (entry = sha256_test.circom, Sha256(64))");
    eprintln!("================================================================");
    eprintln!();
    eprintln!("[ProveIR header]");
    eprintln!("  body.len()     = {}", prove_ir.body.len());
    eprintln!("  captures       = {:?}", prove_ir.captures.len());
    eprintln!("  public_inputs  = {}", prove_ir.public_inputs.len());
    eprintln!("  witness_inputs = {}", prove_ir.witness_inputs.len());
    eprintln!("  output_names   = {}", result.output_names.len());
    eprintln!();

    eprintln!("[ProveIR CircuitNode stats — pure-circom]");
    let pure_stats = collect_circuit_node_stats(&prove_ir.body);
    pure_stats.print("pure-circom");

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let extended = prove_ir
        .instantiate_with_outputs_extended::<Bn254Fr>(&fe_captures, &result.output_names)
        .expect("pure-circom instantiate_extended succeeds");

    eprintln!();
    eprintln!("[ExtendedInstruction stats — pure-circom (instantiate_with_outputs_extended)]");
    let pure_ext_stats = collect_extended_stats(&extended.body);
    pure_ext_stats.print("pure-circom");

    eprintln!();
    eprintln!("[Sanity: the Lysis path completes for this side]");
    let lysis =
        prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &result.output_names);
    match lysis {
        Ok(prog) => eprintln!(
            "  ✓ instantiate_lysis_with_outputs OK — {} flat instructions",
            prog.len()
        ),
        Err(e) => panic!("pure-circom Lysis FAILED unexpectedly: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Side B — .ach dispatch (instantiate_template_into → flat body)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn probe_ach_dispatch_sha256_64() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SIDE B — .ach dispatch (library.instantiate_template Sha256(64))");
    eprintln!("================================================================");
    eprintln!();
    eprintln!(
        "[Library header] templates exposed: {}",
        library.template_names().count()
    );

    let template_args: Vec<FieldConst> = vec![FieldConst::from_u64(64)];

    // Sha256(nBits): signal input in[nBits]. Build 64 dummy var keys
    // matching the row-major naming convention `in_<i>`.
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..64u64 {
        signal_inputs.insert(format!("in_{i}"), CircuitExpr::Var(format!("user_in_{i}")));
    }

    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("library instantiate_template_into Sha256(64) succeeds at the inliner level");

    eprintln!();
    eprintln!(
        "[Inliner output — instantiate_template_into.body.len() = {}]",
        instantiation.body.len()
    );
    eprintln!(
        "[Inliner output — outputs.len() = {}]",
        instantiation.outputs.len()
    );

    eprintln!();
    eprintln!("[CircuitNode stats — .ach dispatch (raw inliner output)]");
    let dispatch_stats = collect_circuit_node_stats(&instantiation.body);
    dispatch_stats.print(".ach-dispatch");

    // Build a synthetic ProveIR that mirrors what the .ach prove block
    // ends up with after `body.extend(instantiation.body)`. We add 64
    // witness-input declarations matching the user's `user_in_<i>`
    // references so the captures resolve cleanly.
    let mut witness_inputs = Vec::new();
    for i in 0..64u64 {
        witness_inputs.push(ir_forge::types::ProveInputDecl {
            name: format!("user_in_{i}"),
            array_size: None,
            ir_type: IrType::Field,
        });
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    eprintln!();
    eprintln!(
        "[Synthetic ProveIR shape] body.len() = {}",
        synthetic.body.len()
    );

    // Try instantiate_extended FIRST — it's the ProveIR-side step
    // before Lysis. We expect it to succeed (or at worst surface a
    // ProveIR-level lowering error, NOT the frame overflow which is
    // a Lysis issue).
    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended_result = synthetic.instantiate_extended::<Bn254Fr>(&captures);

    match extended_result {
        Ok(extended) => {
            eprintln!();
            eprintln!("[ExtendedInstruction stats — .ach dispatch (instantiate_extended)]");
            let dispatch_ext_stats = collect_extended_stats(&extended.body);
            dispatch_ext_stats.print(".ach-dispatch");

            eprintln!();
            eprintln!("[Now driving through Lysis — expecting frame overflow]");
            let lysis_result = synthetic.instantiate_lysis::<Bn254Fr>(&captures);
            match lysis_result {
                Ok(prog) => eprintln!(
                    "  ! Lysis SUCCEEDED on .ach dispatch ({} insts) — \
                     this contradicts the failure premise; recheck sha256_64 vs Sha256_2",
                    prog.len()
                ),
                Err(e) => {
                    eprintln!("  ✓ Lysis failed as expected: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!();
            eprintln!("[!] instantiate_extended itself failed (ProveIR-side): {e}");
            eprintln!(
                "    This means the .ach dispatch can't even build the ExtendedInstruction \
                 stream — the bug is upstream of Lysis."
            );
        }
    }
}
