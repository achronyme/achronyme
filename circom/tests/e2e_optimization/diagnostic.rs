use std::collections::HashMap;
use std::path::Path;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// ── R1CS optimization diagnostic ─────────────────────────────────

/// Diagnostic: dump all constraints for Num2Bits(8) before and after
/// optimization to verify soundness.
#[test]
fn num2bits_optimization_diagnostic() {
    use constraints::r1cs::Variable;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circom/num2bits_8.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs).unwrap();
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap();
    ir::passes::optimize(&mut program);

    // Print IR instructions to understand wire names
    eprintln!("\n=== IR Instructions ===");
    for (i, inst) in program.iter().enumerate() {
        eprintln!("  [{i:3}] {inst}");
    }

    let inputs: HashMap<String, FieldElement<Bn254Fr>> = [("in", 13u64)]
        .iter()
        .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap();
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    let mut witness = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap();

    // Print constraints BEFORE optimization
    eprintln!(
        "\n=== Constraints BEFORE optimization ({}) ===",
        compiler.cs.num_constraints()
    );
    for (i, c) in compiler.cs.constraints().iter().enumerate() {
        let a_val = c.a.evaluate(&witness).unwrap();
        let b_val = c.b.evaluate(&witness).unwrap();
        let c_val = c.c.evaluate(&witness).unwrap();

        let fmt_lc = |lc: &constraints::LinearCombination| -> String {
            let simplified = lc.simplify();
            if simplified.terms().is_empty() {
                return "0".to_string();
            }
            simplified
                .terms()
                .iter()
                .map(|(v, coeff)| {
                    let coeff_u64 = coeff.to_canonical()[0];
                    if *v == Variable::ONE {
                        format!("{coeff_u64}")
                    } else if coeff_u64 == 1 {
                        format!("w{}", v.index())
                    } else {
                        format!("{coeff_u64}·w{}", v.index())
                    }
                })
                .collect::<Vec<_>>()
                .join(" + ")
        };

        eprintln!(
            "  [{i:2}] ({}) * ({}) = ({})   | A={}, B={}, C={}",
            fmt_lc(&c.a),
            fmt_lc(&c.b),
            fmt_lc(&c.c),
            a_val.to_canonical()[0],
            b_val.to_canonical()[0],
            c_val.to_canonical()[0],
        );
    }

    // Print which variables are public
    eprintln!("\n=== Variable layout ===");
    eprintln!(
        "  Public inputs: {} (indices 1..={})",
        compiler.cs.num_pub_inputs(),
        compiler.cs.num_pub_inputs()
    );
    eprintln!("  Total variables: {}", compiler.cs.num_variables());
    for (name, var) in &compiler.bindings {
        eprintln!(
            "  w{} = {name} = {}",
            var.index(),
            witness[var.index()].to_canonical()[0]
        );
    }

    // Optimize
    let stats = compiler.optimize_r1cs();
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }

    // Print what was substituted
    eprintln!(
        "\n=== Substitutions ({} variables eliminated) ===",
        stats.variables_eliminated
    );
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            let fmt_lc = |lc: &constraints::LinearCombination| -> String {
                let simplified = lc.simplify();
                if simplified.terms().is_empty() {
                    return "0".to_string();
                }
                simplified
                    .terms()
                    .iter()
                    .map(|(v, coeff)| {
                        let coeff_u64 = coeff.to_canonical()[0];
                        if *v == Variable::ONE {
                            format!("{coeff_u64}")
                        } else if coeff_u64 == 1 {
                            format!("w{}", v.index())
                        } else {
                            format!("{coeff_u64}·w{}", v.index())
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" + ")
            };
            eprintln!("  w{var_idx} → {}", fmt_lc(lc));
        }
    }

    // Print constraints AFTER optimization
    eprintln!(
        "\n=== Constraints AFTER optimization ({}) ===",
        compiler.cs.num_constraints()
    );
    for (i, c) in compiler.cs.constraints().iter().enumerate() {
        let a_val = c.a.evaluate(&witness).unwrap();
        let b_val = c.b.evaluate(&witness).unwrap();
        let c_val = c.c.evaluate(&witness).unwrap();

        let fmt_lc = |lc: &constraints::LinearCombination| -> String {
            let simplified = lc.simplify();
            if simplified.terms().is_empty() {
                return "0".to_string();
            }
            simplified
                .terms()
                .iter()
                .map(|(v, coeff)| {
                    let coeff_u64 = coeff.to_canonical()[0];
                    if *v == Variable::ONE {
                        format!("{coeff_u64}")
                    } else if coeff_u64 == 1 {
                        format!("w{}", v.index())
                    } else {
                        format!("{coeff_u64}·w{}", v.index())
                    }
                })
                .collect::<Vec<_>>()
                .join(" + ")
        };

        eprintln!(
            "  [{i:2}] ({}) * ({}) = ({})   | A·B={}, C={}",
            fmt_lc(&c.a),
            fmt_lc(&c.b),
            fmt_lc(&c.c),
            a_val.mul(&b_val).to_canonical()[0],
            c_val.to_canonical()[0],
        );
    }

    // Verify
    compiler.cs.verify(&witness).unwrap();
    eprintln!("\n  ✓ Optimized system VERIFIED with witness (in=13)");
}
