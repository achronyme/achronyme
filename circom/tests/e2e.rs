//! E2E test harness for Circom → ProveIR → R1CS pipeline.
//!
//! Scans `test/circom/*.circom` files and runs each through three tiers:
//!   1. **Parse**: `parser::parse_circom()` succeeds
//!   2. **Lower**: `compile_to_prove_ir()` succeeds (parse + analysis + lowering)
//!   3. **R1CS**:  instantiate → optimize → R1CS compile → verify
//!
//! Each `.circom` file may have a companion `.inputs.toml` with signal values.
//! Without inputs, tier 3 is skipped.
//!
//! TOML format:
//! ```toml
//! [inputs]
//! in = 42          # scalar signal
//! in = [3, 10]     # array → in_0=3, in_1=10
//!
//! [expected]
//! constraints = 17 # optional: assert constraint count
//! ```

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

// ── R1CS optimization benchmark ──────────────────────────────────

/// Benchmark: compare constraint counts before/after R1CS linear
/// constraint elimination for key circomlib circuits.
///
/// The `cirO0` / `cirO1` / `cirO2` columns are measured directly against
/// `circom` 2.2.3 (`circom --r1cs --Ox -l test/circomlib`) and reported
/// as **total constraints (non-linear + linear)**, matching the semantics
/// of `R1CSCompiler::cs::num_constraints()`. Re-measure these literals
/// whenever the upstream `circom` baseline shifts; stale values silently
/// distort the achronyme-vs-circom narrative.
#[test]
fn r1cs_optimization_benchmark() {
    /// Compile a circom circuit and return constraint counts at three
    /// optimisation levels:
    /// - `before_opt`  -- raw R1CS output, no optimization.
    /// - `after_o1`    -- after `optimize_r1cs()` (O1 linear elimination).
    /// - `after_o2_s`  -- after `optimize_r1cs_o2_sparse()` (sparse DEDUCE).
    ///
    /// The sparse path is measured on a clone of the pre-opt constraint
    /// vec so the live R1CSCompiler keeps its O1-substitution map for
    /// witness verification.
    fn compile_and_measure(
        name: &str,
        circom_file: &str,
        inputs: &HashMap<String, FieldElement<Bn254Fr>>,
    ) -> (usize, usize, usize) {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(circom_file);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];

        let tp = std::time::Instant::now();
        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("{name} compilation failed: {e}"));
        let t_lower = tp.elapsed();

        let prove_ir = &compile_result.prove_ir;
        let capture_values = &compile_result.capture_values;
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();

        let tp = std::time::Instant::now();
        let mut program = prove_ir
            .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
            .unwrap_or_else(|e| panic!("{name} instantiation failed: {e}"));
        let t_inst = tp.elapsed();

        let tp = std::time::Instant::now();
        ir::passes::optimize(&mut program);
        let t_opt = tp.elapsed();

        let tp = std::time::Instant::now();
        let mut all_signals =
            circom::witness::compute_witness_hints_with_captures(prove_ir, inputs, capture_values)
                .unwrap_or_else(|e| panic!("{name} witness failed: {e}"));
        for (cname, fe) in &fe_captures {
            all_signals.entry(cname.clone()).or_insert(*fe);
        }
        let t_wit = tp.elapsed();

        let tp = std::time::Instant::now();
        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        let mut witness = compiler
            .compile_ir_with_witness(&program, &all_signals)
            .unwrap_or_else(|e| panic!("{name} R1CS failed: {e}"));
        let t_r1cs = tp.elapsed();

        let before = compiler.cs.num_constraints();

        // Snapshot the unoptimised constraint set for the sparse path so
        // we can measure it independently of the live R1CSCompiler.
        let pre_opt_constraints: Vec<constraints::r1cs::Constraint<Bn254Fr>> =
            compiler.cs.constraints().to_vec();
        let num_pub_inputs = compiler.cs.num_pub_inputs();

        let tp = std::time::Instant::now();
        let stats = compiler.optimize_r1cs();
        let after_o1 = stats.constraints_after;
        let t_r1cs_opt = tp.elapsed();

        // Run sparse O2 on the snapshot. Bypasses R1CSCompiler entirely
        // -- the result feeds the constraint-count comparison only;
        // witness fixup keeps using the O1 substitution map below.
        let tp = std::time::Instant::now();
        let mut sparse_constraints = pre_opt_constraints;
        let (_subs, sparse_stats) =
            constraints::r1cs_optimize::optimize_o2_sparse(&mut sparse_constraints, num_pub_inputs);
        let after_o2_s = sparse_stats.constraints_after;
        let t_r1cs_o2_sparse = tp.elapsed();

        // Re-fill substituted wires
        if let Some(subs) = &compiler.substitution_map {
            for (var_idx, lc) in subs {
                witness[*var_idx] = lc.evaluate(&witness).unwrap();
            }
        }

        // Verify optimized system (O1 path -- the one with a fixed-up
        // witness). Sparse O2 produces a different constraint set whose
        // own substitution map we discarded; re-verifying it is not in
        // scope here (covered by sparse_* unit tests in r1cs_optimize).
        compiler
            .cs
            .verify(&witness)
            .unwrap_or_else(|e| panic!("{name} verification FAILED after optimization: {e}"));

        eprintln!(
            "||  {name:24} lower={:.0}ms inst={:.0}ms opt={:.0}ms wit={:.0}ms r1cs={:.0}ms r1csO1={:.0}ms r1csO2s={:.0}ms nodes={}",
            t_lower.as_secs_f64() * 1000.0,
            t_inst.as_secs_f64() * 1000.0,
            t_opt.as_secs_f64() * 1000.0,
            t_wit.as_secs_f64() * 1000.0,
            t_r1cs.as_secs_f64() * 1000.0,
            t_r1cs_opt.as_secs_f64() * 1000.0,
            t_r1cs_o2_sparse.as_secs_f64() * 1000.0,
            prove_ir.body.len(),
        );

        (before, after_o1, after_o2_s)
    }

    /// Witness-less variant of `compile_and_measure` for circuits whose
    /// witness path needs domain-specific inputs the benchmark can't
    /// fabricate (e.g. EdDSAVerifier requires a valid signature). Builds
    /// R1CS without a witness, runs O1 + sparse-O2 against the resulting
    /// constraint set, and reports the same `(before, after_o1, after_o2_s)`
    /// triple. Skips `cs.verify` because no witness exists.
    fn compile_and_measure_witnessless(name: &str, circom_file: &str) -> (usize, usize, usize) {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(circom_file);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];

        let tp = std::time::Instant::now();
        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("{name} compilation failed: {e}"));
        let t_lower = tp.elapsed();

        let prove_ir = &compile_result.prove_ir;
        let capture_values = &compile_result.capture_values;
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();

        let tp = std::time::Instant::now();
        let mut program = prove_ir
            .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
            .unwrap_or_else(|e| panic!("{name} instantiation failed: {e}"));
        let t_inst = tp.elapsed();

        let tp = std::time::Instant::now();
        ir::passes::optimize(&mut program);
        let t_opt = tp.elapsed();

        let tp = std::time::Instant::now();
        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        compiler
            .compile_ir(&program)
            .unwrap_or_else(|e| panic!("{name} R1CS compile failed: {e}"));
        let t_r1cs = tp.elapsed();

        let before = compiler.cs.num_constraints();

        let pre_opt_constraints: Vec<constraints::r1cs::Constraint<Bn254Fr>> =
            compiler.cs.constraints().to_vec();
        let num_pub_inputs = compiler.cs.num_pub_inputs();

        let tp = std::time::Instant::now();
        let stats = compiler.optimize_r1cs();
        let after_o1 = stats.constraints_after;
        let t_r1cs_opt = tp.elapsed();

        let tp = std::time::Instant::now();
        let mut sparse_constraints = pre_opt_constraints;
        let (_subs, sparse_stats) =
            constraints::r1cs_optimize::optimize_o2_sparse(&mut sparse_constraints, num_pub_inputs);
        let after_o2_s = sparse_stats.constraints_after;
        let t_r1cs_o2_sparse = tp.elapsed();

        eprintln!(
            "||  {name:24} lower={:.0}ms inst={:.0}ms opt={:.0}ms r1cs={:.0}ms r1csO1={:.0}ms r1csO2s={:.0}ms nodes={} (witness-less)",
            t_lower.as_secs_f64() * 1000.0,
            t_inst.as_secs_f64() * 1000.0,
            t_opt.as_secs_f64() * 1000.0,
            t_r1cs.as_secs_f64() * 1000.0,
            t_r1cs_opt.as_secs_f64() * 1000.0,
            t_r1cs_o2_sparse.as_secs_f64() * 1000.0,
            prove_ir.body.len(),
        );

        (before, after_o1, after_o2_s)
    }

    eprintln!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║            R1CS Constraint Benchmark: achronyme vs circom               ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ {:26} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>7} ║",
        "Circuit", "achO0", "achO1", "cirO0", "cirO1", "cirO2", "Elim", "Time"
    );
    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");

    /// Format and print a benchmark row.
    fn print_row(
        name: &str,
        b: usize,
        a: usize,
        cir_o0: &str,
        cir_o1: &str,
        cir_o2: &str,
        ms: f64,
    ) {
        eprintln!(
            "║ {:26} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>5.0}ms ║",
            name,
            b,
            a,
            cir_o0,
            cir_o1,
            cir_o2,
            b - a,
            ms,
        );
    }

    let t0 = std::time::Instant::now();

    // Collected (name, achO1, achO2-sparse, circom-O2-baseline-str) per
    // circuit. Printed in the second comparison table after the main
    // achronyme-vs-circom view -- focuses the reader on the hypothesis
    // under test ("does sparse DEDUCE recover constraints we miss with
    // O1 alone?") without breaking the existing column layout.
    let mut sparse_summary: Vec<(&str, usize, usize, &str)> = Vec::new();

    // Num2Bits(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        &[("in", 13)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Num2Bits(8)",
        b,
        a,
        "9",
        "9",
        "9",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Num2Bits(8)", a, asp, "9"));

    // IsZero
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "IsZero",
        "test/circom/iszero.circom",
        &[("in", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "IsZero",
        b,
        a,
        "2",
        "2",
        "2",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("IsZero", a, asp, "2"));

    // LessThan(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        &[("in_0", 3), ("in_1", 10)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "LessThan(8)",
        b,
        a,
        "12",
        "12",
        "9",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("LessThan(8)", a, asp, "9"));

    // Pedersen(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &(0..8)
            .map(|i| (format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(i % 2)))
            .collect(),
    );
    print_row(
        "Pedersen(8)",
        b,
        a,
        "243",
        "95",
        "13",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Pedersen(8)", a, asp, "13"));

    // EscalarMulFix(253)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        &(0..253)
            .map(|i| (format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0)))
            .collect(),
    );
    print_row(
        "EscalarMulFix(253)",
        b,
        a,
        "153",
        "62",
        "11",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EscalarMulFix(253)", a, asp, "11"));

    // EscalarMulAny(254)
    let t = std::time::Instant::now();
    let mut ema_inputs = HashMap::new();
    for i in 0..254 {
        ema_inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    ema_inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    ema_inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    let (b, a, asp) = compile_and_measure(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        &ema_inputs,
    );
    print_row(
        "EscalarMulAny(254)",
        b,
        a,
        "7907",
        "2312",
        "2310",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EscalarMulAny(254)", a, asp, "2310"));

    // Poseidon(2)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        &[("inputs_0", 1), ("inputs_1", 2)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Poseidon(2)",
        b,
        a,
        "765",
        "517",
        "240",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Poseidon(2)", a, asp, "240"));

    // MiMCSponge(2,220,1)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        &[("ins_0", 1), ("ins_1", 2), ("k", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "MiMCSponge(2,220,1)",
        b,
        a,
        "1767",
        "1321",
        "1320",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("MiMCSponge(2,220,1)", a, asp, "1320"));

    // Point2Bits_Strict (BabyJubjub Edwards point → 256-bit packing)
    // Identity point input — cross-template `proven_boolean` lever
    // surfaces here because Num2Bits feeds CompConstant + AliasCheck
    // chain in a single template, a pattern not present in the eight
    // legacy circuits above.
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Point2Bits_Strict",
        "test/circomlib/point2bits_test.circom",
        &[("in_0", 0), ("in_1", 1)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Point2Bits_Strict",
        b,
        a,
        "2838",
        "1301",
        "1293",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Point2Bits_Strict", a, asp, "1293"));

    // Bits2Point_Strict (256-bit packing → BabyJubjub Edwards point)
    // Inputs marked public via `{public [in]}` in the fixture so the
    // `in[254] === 0` and `signCalc.out === in[255]` constraints
    // survive optimisation rather than being lawfully substituted away.
    let t = std::time::Instant::now();
    let mut b2p_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    b2p_inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    for i in 1..256 {
        b2p_inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    let (b, a, asp) = compile_and_measure(
        "Bits2Point_Strict",
        "test/circomlib/bits2point_test.circom",
        &b2p_inputs,
    );
    print_row(
        "Bits2Point_Strict",
        b,
        a,
        "2589",
        "1050",
        "1043",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Bits2Point_Strict", a, asp, "1043"));

    // Sha256_2 (2 × 216-bit field-element inputs → 216-bit truncated
    // SHA-256 digest). Distinct shape from `Sha256(N)`: hardcoded
    // length encoding + 2× Num2Bits(216) + Bits2Num(216).
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Sha256_2",
        "test/circomlib/sha256_2_test.circom",
        &[("a", 1), ("b", 2)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Sha256_2",
        b,
        a,
        "204462",
        "31699",
        "30134",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Sha256_2", a, asp, "30134"));

    // EdDSAPoseidon (Poseidon-hash variant of the EdDSA verifier).
    // Inherits the Pointbits cross-template advantage via its single
    // internal `Point2Bits_Strict` invocation on the hash output.
    let t = std::time::Instant::now();
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut eddsa_p_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    eddsa_p_inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    eddsa_p_inputs.insert(
        "Ax".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    eddsa_p_inputs.insert(
        "Ay".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    eddsa_p_inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    eddsa_p_inputs.insert(
        "R8x".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    eddsa_p_inputs.insert(
        "R8y".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    eddsa_p_inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));
    let (b, a, asp) = compile_and_measure(
        "EdDSAPoseidon",
        "test/circomlib/eddsaposeidon_test.circom",
        &eddsa_p_inputs,
    );
    print_row(
        "EdDSAPoseidon",
        b,
        a,
        "21254",
        "8086",
        "4217",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EdDSAPoseidon", a, asp, "4217"));

    // EdDSAVerifier(1) — Pedersen-hash variant. No `enabled` escape,
    // verifier always asserts a valid signature, so the benchmark
    // measures constraint shape via the witness-less path. Inherits
    // the Pointbits advantage 3× over (2× Bits2Point_Strict + 1×
    // Point2Bits_Strict in the verifier body).
    let t = std::time::Instant::now();
    let (b, a, asp) =
        compile_and_measure_witnessless("EdDSAVerifier(1)", "test/circomlib/eddsa_test.circom");
    print_row(
        "EdDSAVerifier(1)",
        b,
        a,
        "42919",
        "16498",
        "7417",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EdDSAVerifier(1)", a, asp, "7417"));

    // Tornado Cash Withdraw(20) — vendored from tornadocash/tornado-core,
    // ported to circom 2.0. Tree depth 20 (mainnet). Body: 2× Pedersen +
    // 2× Num2Bits(248) + 20× MiMCSponge + 20× DualMux + 4 binding
    // squares. Witness-less because constructing a valid Pedersen-MiMC
    // merkle proof witness requires running the deposit ceremony off-line.
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure_witnessless(
        "Tornado Withdraw(20)",
        "test/circomlib/tornado_test.circom",
    );
    print_row(
        "Tornado Withdraw(20)",
        b,
        a,
        "59009",
        "36451",
        "28275",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Tornado Withdraw(20)", a, asp, "28275"));

    // Semaphore(32) — semaphore-protocol/semaphore v4 main circuit.
    // Body: LessThan(251) + BabyPbk + 2× Poseidon(2) +
    // BinaryMerkleRoot(32) (32× Poseidon(2) inside). Witness-less
    // because constructing a valid (secret, merkle proof) pair requires
    // the Semaphore identity setup off-line.
    let t = std::time::Instant::now();
    let (b, a, asp) =
        compile_and_measure_witnessless("Semaphore(32)", "test/circomlib/semaphore_test.circom");
    print_row(
        "Semaphore(32)",
        b,
        a,
        "37044",
        "22216",
        "9383",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Semaphore(32)", a, asp, "9383"));

    // Poseidon arity sweep (t = 3, 4, 8, 16). The existing benchmark
    // already covers t=2; this sweep tests how the optimiser scales
    // with the t×t MDS-matrix multiplication and the
    // `(t * nRoundsF + nRoundsP)`-element round-constant vector at
    // wider hashes. Witness uses small consecutive integers.
    for t in [3usize, 4, 8, 16] {
        let label = format!("Poseidon({t})");
        let circ = format!("test/circomlib/poseidon_{t}_test.circom");
        let inputs: HashMap<String, FieldElement<Bn254Fr>> = (0..t)
            .map(|i| {
                (
                    format!("inputs_{i}"),
                    FieldElement::<Bn254Fr>::from_u64((i as u64) + 1),
                )
            })
            .collect();
        let t_w = std::time::Instant::now();
        let (b, a, asp) = compile_and_measure(&label, &circ, &inputs);
        let (cir_o0, cir_o1, cir_o2) = match t {
            3 => ("931", "605", "261"),
            4 => ("1163", "736", "297"),
            8 => ("1965", "1171", "402"),
            16 => ("3675", "2092", "609"),
            _ => unreachable!(),
        };
        print_row(
            &label,
            b,
            a,
            cir_o0,
            cir_o1,
            cir_o2,
            t_w.elapsed().as_secs_f64() * 1000.0,
        );
        // Leak the label into a 'static slice via Box::leak so the
        // benchmark summary table can hold a stable &str. Fine in a
        // test run — the leak lives until process exit.
        let label_static: &'static str = Box::leak(label.into_boxed_str());
        sparse_summary.push((label_static, a, asp, cir_o2));
    }

    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ Total achronyme time: {:>5.0}ms {:>42} ║",
        t0.elapsed().as_secs_f64() * 1000.0,
        ""
    );
    eprintln!("╚════════════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    // Second table: O1 vs O2-sparse vs circom O2.
    //
    // Validates the hypothesis "sparse DEDUCE recovers constraints O1
    // misses, even on circuits where achronyme already matches or beats
    // circom O2". `gain` is achO1 - achO2s (constraints removed by the
    // sparse pass over O1 alone). `delta` is achO2s - cirO2 (positive
    // means achronyme remains behind, negative means we beat circom).
    eprintln!("+--- DEDUCE-sparse vs circom O2 ----------------------------------+");
    eprintln!(
        "| {:24} | {:>6} | {:>6} | {:>6} | {:>+6} | {:>5} |",
        "Circuit", "achO1", "achO2s", "cirO2", "delta", "gain"
    );
    eprintln!("+--------------------------+--------+--------+--------+--------+-------+");
    for (name, a_o1, a_o2s, cir_o2_str) in &sparse_summary {
        let cir_o2: i64 = cir_o2_str.parse().unwrap_or(0);
        let delta: i64 = *a_o2s as i64 - cir_o2;
        let gain: i64 = *a_o1 as i64 - *a_o2s as i64;
        eprintln!(
            "| {:24} | {:>6} | {:>6} | {:>6} | {:>+6} | {:>5} |",
            name, a_o1, a_o2s, cir_o2_str, delta, gain
        );
    }
    eprintln!("+------------------------------------------------------------------+");
    eprintln!();
}
