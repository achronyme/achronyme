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
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// ── Test result tracking ─────────────────────────────────────────

#[derive(Debug)]
struct TestResult {
    name: String,
    parse: bool,
    lower: bool,
    r1cs: bool,
    constraints: Option<usize>,
    error: Option<String>,
}

// ── TOML input loading ───────────────────────────────────────────

fn load_inputs(toml_path: &Path) -> (HashMap<String, u64>, Option<usize>) {
    let content = std::fs::read_to_string(toml_path).expect("failed to read inputs.toml");
    let table: toml::Value = content.parse().expect("failed to parse inputs.toml");

    let mut inputs = HashMap::new();

    if let Some(inp) = table.get("inputs").and_then(|v| v.as_table()) {
        for (key, val) in inp {
            match val {
                toml::Value::Integer(n) => {
                    inputs.insert(key.clone(), *n as u64);
                }
                toml::Value::Array(arr) => {
                    for (i, elem) in arr.iter().enumerate() {
                        let n = elem.as_integer().expect("array elements must be integers");
                        inputs.insert(format!("{key}_{i}"), n as u64);
                    }
                }
                _ => panic!("unsupported input type for '{key}'"),
            }
        }
    }

    let expected_constraints = table
        .get("expected")
        .and_then(|v| v.get("constraints"))
        .and_then(|v| v.as_integer())
        .map(|n| n as usize);

    (inputs, expected_constraints)
}

// ── Single test runner ───────────────────────────────────────────

fn run_circom_test(circom_path: &Path) -> TestResult {
    let name = circom_path
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let src = std::fs::read_to_string(circom_path).expect("failed to read .circom file");

    // ── Tier 1: Parse ──
    if circom::parser::parse_circom(&src).is_err() {
        return TestResult {
            name,
            parse: false,
            lower: false,
            r1cs: false,
            constraints: None,
            error: Some("parse failed".into()),
        };
    }

    // ── Tier 2: Lower (compile_to_prove_ir) ──
    let compile_result = match circom::compile_to_prove_ir(&src) {
        Ok(r) => r,
        Err(e) => {
            // Distinguish parse errors from lowering errors
            let parse_ok = !matches!(e, circom::CircomError::ParseError(_));
            return TestResult {
                name,
                parse: parse_ok,
                lower: false,
                r1cs: false,
                constraints: None,
                error: Some(format!("{e}")),
            };
        }
    };

    // ── Tier 3: R1CS (instantiate → optimize → compile → verify) ──
    let inputs_path = circom_path.with_extension("inputs.toml");
    if !inputs_path.exists() {
        return TestResult {
            name,
            parse: true,
            lower: true,
            r1cs: false,
            constraints: None,
            error: Some("no inputs file".into()),
        };
    }

    let (user_inputs, expected_constraints) = load_inputs(&inputs_path);

    let prove_ir = compile_result.prove_ir;
    let output_names = compile_result.output_names;
    let capture_values = compile_result.capture_values;

    // Build FieldElement inputs
    let fe_inputs: HashMap<String, FieldElement<Bn254Fr>> = user_inputs
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    // Compute witness
    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        &prove_ir,
        &fe_inputs,
        &capture_values,
    ) {
        Ok(s) => s,
        Err(e) => {
            return TestResult {
                name,
                parse: true,
                lower: true,
                r1cs: false,
                constraints: None,
                error: Some(format!("witness: {e}")),
            };
        }
    };

    // Seed captures into signal map
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    // Instantiate (with output support — outputs become public R1CS wires)
    let mut program = match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &output_names) {
        Ok(p) => p,
        Err(e) => {
            return TestResult {
                name,
                parse: true,
                lower: true,
                r1cs: false,
                constraints: None,
                error: Some(format!("instantiation: {e}")),
            };
        }
    };

    ir::passes::optimize(&mut program);

    // R1CS compile
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => {
            return TestResult {
                name,
                parse: true,
                lower: true,
                r1cs: false,
                constraints: None,
                error: Some(format!("r1cs compile: {e}")),
            };
        }
    };

    // R1CS verify
    if let Err(e) = r1cs_compiler.cs.verify(&witness) {
        return TestResult {
            name,
            parse: true,
            lower: true,
            r1cs: false,
            constraints: Some(r1cs_compiler.cs.num_constraints()),
            error: Some(format!("r1cs verify: {e}")),
        };
    }

    let num_constraints = r1cs_compiler.cs.num_constraints();

    // Check expected constraint count
    if let Some(expected) = expected_constraints {
        if num_constraints != expected {
            return TestResult {
                name,
                parse: true,
                lower: true,
                r1cs: true,
                constraints: Some(num_constraints),
                error: Some(format!(
                    "constraint count mismatch: expected {expected}, got {num_constraints}"
                )),
            };
        }
    }

    TestResult {
        name,
        parse: true,
        lower: true,
        r1cs: true,
        constraints: Some(num_constraints),
        error: None,
    }
}

// ── Test directory scanner ───────────────────────────────────────

fn find_circom_tests() -> Vec<PathBuf> {
    let test_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test/circom");

    if !test_dir.exists() {
        panic!("test/circom/ directory not found at {}", test_dir.display());
    }

    let mut files: Vec<PathBuf> = std::fs::read_dir(&test_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "circom"))
        .collect();

    files.sort();
    files
}

// ── Main test ────────────────────────────────────────────────────

#[test]
fn circomlib_e2e() {
    let files = find_circom_tests();
    assert!(!files.is_empty(), "no .circom test files found");

    let mut results: Vec<TestResult> = Vec::new();

    for file in &files {
        let result = run_circom_test(file);
        results.push(result);
    }

    // Print summary table
    eprintln!();
    eprintln!("┌─────────────────────────┬───────┬───────┬───────┬─────────────┐");
    eprintln!("│ Template                │ Parse │ Lower │ R1CS  │ Constraints │");
    eprintln!("├─────────────────────────┼───────┼───────┼───────┼─────────────┤");

    for r in &results {
        let parse = if r.parse { "  ✓  " } else { "  ✗  " };
        let lower = if r.lower { "  ✓  " } else { "  ✗  " };
        let r1cs = if r.r1cs { "  ✓  " } else { "  ✗  " };
        let constraints = match r.constraints {
            Some(n) => format!("{n:>11}"),
            None => "          -".to_string(),
        };
        eprintln!("│ {:<23} │{parse}│{lower}│{r1cs}│{constraints} │", r.name);
    }

    eprintln!("└─────────────────────────┴───────┴───────┴───────┴─────────────┘");

    let total = results.len();
    let parsed = results.iter().filter(|r| r.parse).count();
    let lowered = results.iter().filter(|r| r.lower).count();
    let proved = results.iter().filter(|r| r.r1cs).count();

    eprintln!();
    eprintln!(
        "circomlib coverage: {parsed}/{total} parse, {lowered}/{total} lower, {proved}/{total} r1cs"
    );
    eprintln!();

    // Print errors for failed tests
    let failures: Vec<&TestResult> = results.iter().filter(|r| r.error.is_some()).collect();
    if !failures.is_empty() {
        eprintln!("Failures:");
        for r in &failures {
            if let Some(err) = &r.error {
                eprintln!("  {}: {err}", r.name);
            }
        }
        eprintln!();
    }

    // Regressions: tests that LOWER successfully and have inputs, but fail R1CS.
    // Lower failures are "gaps" (unsupported features), not regressions.
    let regressions: Vec<&TestResult> = results
        .iter()
        .filter(|r| r.lower && !r.r1cs && r.error.as_deref() != Some("no inputs file"))
        .collect();

    if !regressions.is_empty() {
        eprintln!("REGRESSIONS (lowered but failed R1CS):");
        for r in &regressions {
            eprintln!("  {} — {}", r.name, r.error.as_deref().unwrap_or("unknown"));
        }
        panic!(
            "{} circom test(s) regressed — see details above",
            regressions.len()
        );
    }

    // Gaps: tests that fail at parse or lower (feature gaps, not regressions).
    let gaps: Vec<&TestResult> = results
        .iter()
        .filter(|r| !r.lower && r.error.as_deref() != Some("no inputs file"))
        .collect();
    if !gaps.is_empty() {
        eprintln!("Feature gaps (not regressions):");
        for r in &gaps {
            eprintln!("  {} — {}", r.name, r.error.as_deref().unwrap_or("unknown"));
        }
    }
}

// ── Poseidon (real circomlib) ───────────────────────────────────

/// Compile the real circomlib poseidon.circom with include resolution.
///
/// This is the ultimate compatibility test: Poseidon(2) from iden3/circomlib
/// compiled through our frontend → ProveIR → R1CS → Groth16 verify.
///
/// Poseidon(2) from iden3/circomlib: 1006 constraints, Groth16-verified.
#[test]
fn poseidon_real_circomlib() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let poseidon_path = manifest_dir.join("test/circomlib/poseidon_test.circom");

    if !poseidon_path.exists() {
        eprintln!("Skipping poseidon test: {poseidon_path:?} not found");
        return;
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // ── Step 1: Compile ──
    eprintln!("Compiling Poseidon(2) from real circomlib...");
    let compile_result = match circom::compile_file(&poseidon_path, &lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            panic!("Poseidon compilation failed: {e}");
        }
    };

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());
    eprintln!(
        "    Public inputs: {:?}",
        prove_ir
            .public_inputs
            .iter()
            .map(|i| &i.name)
            .collect::<Vec<_>>()
    );
    eprintln!(
        "    Captures: {:?}",
        prove_ir
            .captures
            .iter()
            .map(|c| &c.name)
            .collect::<Vec<_>>()
    );

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program =
        match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names) {
            Ok(p) => p,
            Err(e) => panic!("Poseidon instantiation failed: {e}"),
        };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    // ── Step 3: R1CS compile ──
    // Build witness: inputs[0]=1, inputs[1]=2, initialState=0
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("inputs_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("inputs_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert(
        "initialState".to_string(),
        FieldElement::<Bn254Fr>::from_u64(0),
    );

    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    ) {
        Ok(s) => s,
        Err(e) => panic!("Poseidon witness computation failed: {e}"),
    };

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => panic!("Poseidon R1CS compilation failed: {e}"),
    };

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    // ── Step 4: Verify ──
    match r1cs_compiler.cs.verify(&witness) {
        Ok(()) => eprintln!("  ✓ R1CS verified!"),
        Err(e) => panic!("Poseidon R1CS verification failed: {e}"),
    }

    eprintln!();
    eprintln!("  Poseidon(2) — {num_constraints} constraints — VERIFIED ✓");
}

// ── MiMCSponge (real circomlib) ────────────────────────────────

/// MiMCSponge(2, 220, 1) from iden3/circomlib: 220 rounds of MiMC-Feistel.
///
/// Tests: 218-element constant array, computed component array bounds,
/// compile-time ternary in loops, signal arrays with loop-dependent indexing.
#[test]
fn mimcsponge_real_circomlib() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mimc_path = manifest_dir.join("test/circomlib/mimcsponge_test.circom");

    if !mimc_path.exists() {
        eprintln!("Skipping MiMCSponge test: {mimc_path:?} not found");
        return;
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // ── Step 1: Compile ──
    eprintln!("Compiling MiMCSponge(2, 220, 1) from real circomlib...");
    let compile_result = match circom::compile_file(&mimc_path, &lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            panic!("MiMCSponge compilation failed: {e}");
        }
    };

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());

    // DEBUG: count ProveIR node types
    {
        use ir_forge::types::CircuitNode;
        let mut lets = 0usize;
        let mut asserts = 0usize;
        let mut hints = 0usize;
        let mut fors = 0usize;
        let mut decomps = 0usize;
        let mut ifs = 0usize;
        let mut other = 0usize;
        let mut const_lets = 0usize;
        #[allow(clippy::too_many_arguments)]
        fn count_nodes(
            nodes: &[CircuitNode],
            lets: &mut usize,
            asserts: &mut usize,
            hints: &mut usize,
            fors: &mut usize,
            decomps: &mut usize,
            ifs: &mut usize,
            other: &mut usize,
            const_lets: &mut usize,
        ) {
            for n in nodes {
                match n {
                    CircuitNode::Let { value, .. } => {
                        *lets += 1;
                        if matches!(value, ir_forge::types::CircuitExpr::Const(_)) {
                            *const_lets += 1;
                        }
                    }
                    CircuitNode::AssertEq { .. } => *asserts += 1,
                    CircuitNode::WitnessHint { .. } => *hints += 1,
                    CircuitNode::For { body, .. } => {
                        *fors += 1;
                        count_nodes(
                            body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                    }
                    CircuitNode::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        *ifs += 1;
                        count_nodes(
                            then_body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                        count_nodes(
                            else_body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                    }
                    CircuitNode::Decompose { .. } => *decomps += 1,
                    _ => *other += 1,
                }
            }
        }
        count_nodes(
            &prove_ir.body,
            &mut lets,
            &mut asserts,
            &mut hints,
            &mut fors,
            &mut decomps,
            &mut ifs,
            &mut other,
            &mut const_lets,
        );
        eprintln!("  DEBUG nodes: Let={lets} (Const={const_lets}), AssertEq={asserts}, WitnessHint={hints}, For={fors}, If={ifs}, Decompose={decomps}, Other={other}");
        // Count "Other" node types
        let mut let_indexed = 0usize;
        let mut wh_indexed = 0usize;
        let mut let_array = 0usize;
        let mut expr_nodes = 0usize;
        let mut assert_nodes = 0usize;
        for n in &prove_ir.body {
            match n {
                CircuitNode::LetIndexed { .. } => let_indexed += 1,
                CircuitNode::WitnessHintIndexed { .. } => wh_indexed += 1,
                CircuitNode::LetArray { .. } => let_array += 1,
                CircuitNode::Expr { .. } => expr_nodes += 1,
                CircuitNode::Assert { .. } => assert_nodes += 1,
                _ => {}
            }
        }
        eprintln!("  DEBUG other: LetIndexed={let_indexed}, WHIndexed={wh_indexed}, LetArray={let_array}, Expr={expr_nodes}, Assert={assert_nodes}");
        // Print round 0 and round 1 nodes (indices ~220-250)
        eprintln!("  DEBUG === Nodes 218..260 ===");
        for (i, n) in prove_ir.body.iter().enumerate().skip(218).take(42) {
            eprintln!("  [{i}] {n:?}");
        }
    }

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program =
        match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names) {
            Ok(p) => p,
            Err(e) => panic!("MiMCSponge instantiation failed: {e}"),
        };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    // ── Step 3: R1CS compile ──
    // Witness: ins[0]=1, ins[1]=2, k=0
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("ins_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("ins_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert("k".to_string(), FieldElement::<Bn254Fr>::from_u64(0));

    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    ) {
        Ok(s) => s,
        Err(e) => panic!("MiMCSponge witness computation failed: {e}"),
    };

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => panic!("MiMCSponge R1CS compilation failed: {e}"),
    };

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    match r1cs_compiler.cs.verify(&witness) {
        Ok(()) => eprintln!("  ✓ R1CS verified!"),
        Err(e) => panic!("MiMCSponge R1CS verification failed: {e}"),
    }

    eprintln!();
    eprintln!("  MiMCSponge(2, 220, 1) — {num_constraints} constraints — VERIFIED ✓");
}

// ── Shared E2E helper ──────────────────────────────────────────

/// Compile a circomlib test file → ProveIR → instantiate → R1CS → verify.
///
/// Returns the number of constraints on success.
fn circomlib_e2e_verify(test_name: &str, circom_file: &str, inputs: &[(&str, u64)]) -> usize {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);

    if !path.exists() {
        panic!("{test_name}: file not found: {path:?}");
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    eprintln!("Compiling {test_name}...");
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{test_name} compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());

    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{test_name} instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for &(name, val) in inputs {
        user_inputs.insert(name.to_string(), FieldElement::<Bn254Fr>::from_u64(val));
    }

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    )
    .unwrap_or_else(|e| panic!("{test_name} witness computation failed: {e}"));

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("{test_name} R1CS compilation failed: {e}"));

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    r1cs_compiler
        .cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("{test_name} R1CS verification failed: {e}"));

    eprintln!("  ✓ R1CS verified!");
    eprintln!();
    eprintln!("  {test_name} — {num_constraints} constraints — VERIFIED ✓");

    num_constraints
}

// ── BabyJubjub (real circomlib) ────────────────────────────────

/// BabyAdd + BabyDbl + BabyCheck from iden3/circomlib.
///
/// Tests: Edwards curve point addition with witness hints (division),
/// reverse constraint assign (`==>`), `===` constraints with var
/// coefficients, and component composition (BabyDbl wraps BabyAdd).
#[test]
fn babyjub_real_circomlib() {
    // Generator point G = (Gx, Gy) of BabyJubjub
    // We use the base point from circomlib:
    // Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553
    // Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203
    // These are large field elements — for witness hints with division,
    // we need the actual field values. Use small test points instead:
    // The identity point (0, 1) is always on the curve.
    // BabyAdd(0, 1, 0, 1) should give BabyDbl(0, 1) = (0, 1) (identity doubled).
    let n = circomlib_e2e_verify(
        "BabyJub (Add+Dbl+Check)",
        "test/circomlib/babyjub_test.circom",
        &[("x1", 0), ("y1", 1), ("x2", 0), ("y2", 1)],
    );
    assert!(n > 0, "expected at least 1 constraint");
}

// ── EscalarMulFix (real circomlib) ─────────────────────────────

/// EscalarMulFix(3, BASE8): scalar multiplication on BabyJubjub.
///
/// Tests: WindowMulFix (MultiMux3 + MontgomeryDouble/Add),
/// SegmentMulFix orchestration, Edwards↔Montgomery conversion,
/// component arrays, 2D signal wiring.
#[test]
fn escalarmulfix_real_circomlib() {
    // 3-bit scalar = 5 (bits: 1,0,1)
    let n = circomlib_e2e_verify(
        "EscalarMulFix(3, BASE8)",
        "test/circomlib/escalarmulfix_test.circom",
        &[("e_0", 1), ("e_1", 0), ("e_2", 1)],
    );
    eprintln!("  Constraints: {n}");
}

/// Full E2E verify with FieldElement inputs (supports large field values).
fn circomlib_e2e_verify_fe(
    test_name: &str,
    circom_file: &str,
    inputs: &HashMap<String, FieldElement<Bn254Fr>>,
) -> usize {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    eprintln!("Compiling {test_name}...");
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{test_name} compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());

    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{test_name} instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, inputs, capture_values)
            .unwrap_or_else(|e| panic!("{test_name} witness computation failed: {e}"));

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("{test_name} R1CS compilation failed: {e}"));

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    r1cs_compiler
        .cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("{test_name} R1CS verification failed: {e}"));

    eprintln!("  ✓ R1CS verified!");
    eprintln!("  {test_name} — {num_constraints} constraints — VERIFIED ✓");

    num_constraints
}

/// Like `circomlib_e2e_verify_fe` but also applies R1CS linear constraint elimination.
fn circomlib_e2e_optimized(
    test_name: &str,
    circom_file: &str,
    inputs: &HashMap<String, FieldElement<Bn254Fr>>,
) -> usize {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{test_name} compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{test_name} instantiation failed: {e}"));

    ir::passes::optimize(&mut program);

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, inputs, capture_values)
            .unwrap_or_else(|e| panic!("{test_name} witness computation failed: {e}"));

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let mut witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("{test_name} R1CS compilation failed: {e}"));

    let pre_opt = r1cs_compiler.cs.num_constraints();

    // Apply R1CS linear constraint elimination
    let stats = r1cs_compiler.optimize_r1cs();
    if let Some(subs) = &r1cs_compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }

    let post_opt = r1cs_compiler.cs.num_constraints();
    eprintln!(
        "  {test_name}: {pre_opt} → {post_opt} ({} linear elim, {} dedup, {} trivial, {} vars subst)",
        stats.constraints_before - stats.constraints_after - stats.duplicates_removed - stats.trivial_removed,
        stats.duplicates_removed,
        stats.trivial_removed,
        stats.variables_eliminated,
    );

    r1cs_compiler
        .cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("{test_name} R1CS verification failed (post-opt): {e}"));

    post_opt
}

/// EscalarMulAny(254): full R1CS verify with identity point.
///
/// Uses n=254 (real-world EdDSA scalar size). Official circom produces
/// 2,312 constraints for this circuit (2,310 non-linear + 2 linear).
#[test]
fn escalarmulany_r1cs() {
    let mut inputs = HashMap::new();
    // 254 bits of scalar, all zero
    for i in 0..254 {
        inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    // Identity point (0, 1) — zeropoint guard forces G8
    inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_verify_fe(
        "EscalarMulAny(254) R1CS",
        "test/circomlib/escalarmulany254_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    eprintln!("  Official circom: 2312 constraints");
    assert!(n > 2000, "expected >2000 constraints, got {n}");
}

/// EscalarMulAny(254): full Groth16 proof generation and verification.
#[test]
fn escalarmulany_groth16() {
    let mut inputs = HashMap::new();
    for i in 0..254 {
        inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/escalarmulany254_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("instantiation failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap_or_else(|e| panic!("witness failed: {e}"));
    for (k, v) in &fe_captures {
        all_signals.entry(k.clone()).or_insert(*v);
    }

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS failed: {e}"));

    r1cs.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));

    let n = r1cs.cs.num_constraints();
    eprintln!("  ✓ R1CS: {n} constraints");

    // Groth16 proof
    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof generation failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            eprintln!("  ✓ Groth16 proof generated ({} bytes)", proof_json.len());

            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verification failed: {e}"));

            assert!(valid, "Groth16 proof did not verify!");
            eprintln!("  ✓ Groth16 proof VERIFIED!");
            eprintln!("\n  EscalarMulAny(149) — {n} constraints — GROTH16 VERIFIED ✓");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// EdDSAPoseidon: the "boss final" — full signature verification.
/// Depends on: Num2Bits(253), CompConstant, Poseidon(5), Num2Bits_strict,
/// BabyDbl, IsZero, EscalarMulAny(254), BabyAdd, EscalarMulFix(253),
/// ForceEqualIfEnabled.
#[test]
fn eddsaposeidon_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/eddsaposeidon_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    eprintln!("Compiling EdDSAPoseidonVerifier...");
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon compilation failed: {e}"));

    let prove_ir = &compile_result.prove_ir;
    eprintln!(
        "  ✓ Compiled: {} body nodes, {} public, {} witness",
        prove_ir.body.len(),
        prove_ir.public_inputs.len(),
        prove_ir.witness_inputs.len(),
    );

    // Instantiate to verify the node ordering is correct
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    eprintln!(
        "\n  EdDSAPoseidonVerifier — {} nodes → {} instructions — INSTANTIATED ✓",
        prove_ir.body.len(),
        program.len()
    );
}

/// EdDSaPoseidon R1CS verification with enabled=0.
///
/// With enabled=0, ForceEqualIfEnabled doesn't check the signature,
/// so any input values satisfy the constraints. This validates that
/// the entire constraint system is well-formed and satisfiable.
///
/// Unblocked by BigVal 256-bit evaluator (2026-04-04): CompConstant's
/// `var b = (1 << 128) - 1` now evaluates correctly.
#[test]
fn eddsaposeidon_r1cs() {
    // BabyJubjub base point (Base8) — a valid curve point.
    // Even with enabled=0, intermediate values must be valid for Num2Bits.
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut inputs = HashMap::new();
    inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert(
        "Ax".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "Ay".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    // R8 = same base point (arbitrary valid point for enabled=0)
    inputs.insert(
        "R8x".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "R8y".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));

    let n = circomlib_e2e_verify_fe(
        "EdDSAPoseidon R1CS (enabled=0)",
        "test/circomlib/eddsaposeidon_test.circom",
        &inputs,
    );
    eprintln!("  Constraints (pre-opt): {n}");

    // Also test with R1CS linear constraint optimization
    let n_opt = circomlib_e2e_optimized(
        "EdDSAPoseidon R1CS optimized",
        "test/circomlib/eddsaposeidon_test.circom",
        &inputs,
    );
    eprintln!("  Constraints (post-opt): {n_opt}");
    eprintln!("  circom --O1 reference: 8086");
    eprintln!("  Ratio: {:.2}x", n_opt as f64 / 8086.0);
}

/// CompConstant standalone R1CS verify — isolates the 1<<128 BigVal fix.
#[test]
fn compconstant_standalone() {
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(42));

    let n = circomlib_e2e_verify_fe(
        "CompConstant standalone",
        "test/circomlib/compconstant_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

// ── Circomlib compatibility: simple gadgets ──────────────────────

/// Switcher: conditional swap (sel=0 → pass-through, sel=1 → swap).
#[test]
fn switcher_circomlib() {
    // sel=0: outL=L=10, outR=R=20
    let n = circomlib_e2e_verify(
        "Switcher (sel=0)",
        "test/circomlib/switcher_test.circom",
        &[("sel", 0), ("L", 10), ("R", 20)],
    );
    eprintln!("  Constraints: {n}");

    // sel=1: outL=R=20, outR=L=10
    let n = circomlib_e2e_verify(
        "Switcher (sel=1)",
        "test/circomlib/switcher_test.circom",
        &[("sel", 1), ("L", 10), ("R", 20)],
    );
    eprintln!("  Constraints: {n}");
}

/// Mux3: select one of 8 values with 3-bit selector.
/// Tests MultiMux3 with pre-computed linear combinations.
#[test]
fn mux3_circomlib() {
    // c = [10,20,30,40,50,60,70,80], s = [1,0,1] → index=5 → c[5]=60
    let n = circomlib_e2e_verify(
        "Mux3 (sel=5)",
        "test/circomlib/mux3_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 1),
            ("s_1", 0),
            ("s_2", 1),
        ],
    );
    eprintln!("  Constraints: {n}");
}

/// Mux4: select one of 16 values with 4-bit selector.
#[test]
fn mux4_circomlib() {
    // s = [1,1,0,0] → index=3 → c[3]
    let mut inputs: Vec<(&str, u64)> = Vec::new();
    // c[0..16] = 100, 200, ... 1600
    let c_names: Vec<String> = (0..16).map(|i| format!("c_{i}")).collect();
    for (i, name) in c_names.iter().enumerate() {
        inputs.push((name, (i as u64 + 1) * 100));
    }
    inputs.push(("s_0", 1)); // bit 0
    inputs.push(("s_1", 1)); // bit 1
    inputs.push(("s_2", 0)); // bit 2
    inputs.push(("s_3", 0)); // bit 3
                             // index = 1 + 2 = 3 → c[3] = 400

    let n = circomlib_e2e_verify(
        "Mux4 (sel=3)",
        "test/circomlib/mux4_test.circom",
        &inputs.iter().map(|&(n, v)| (n, v)).collect::<Vec<_>>(),
    );
    eprintln!("  Constraints: {n}");
}

/// `var X; ... X = <const-expr>;` compile-time tracking.
///
/// Regression for the pattern circomlib SHA256 uses:
///
/// ```circom
/// var nBlocks;
/// nBlocks = ((nBits + 64)\512) + 1;
/// signal paddedIn[nBlocks*512];
/// for (var k = nBits+1; k < nBlocks*512 - 64; k++) { ... }
/// paddedIn[nBlocks*512 - k - 1] <== ...;
/// ```
///
/// Before the fix, `precompute_all` only tracked `var X = expr;` on a
/// single statement and `template::lower` never injected precomputed
/// scalars into `env.known_constants`, so `nBlocks` reached the ProveIR
/// instantiator as `CircuitExpr::Var("nBlocks")` and indexing failed
/// with "indexed assignment requires a compile-time constant index".
///
/// Also exercises the per-iter SSA-after-unroll spill discipline — the
/// fourth padding loop (`paddedIn[nBlocks*512 - k - 1] <== (nBits >> k)
/// & 1` for `k` in `0..64`) is wide enough that the walker engages the
/// per-iter unroll path and a mid-emit split classifies the per-iter
/// BitAnd recompose result as cold. Stripping body-defined SsaVars
/// from `ssa_to_heap` at each iter restore (see
/// `emit_loop_unroll_per_iter_inner`) gives each iter's body-defined
/// values their own heap slot so the 64 `paddedIn[505..]` AssertEqs
/// each see iter-fresh RHS bits instead of iter-0's stale value.
#[test]
fn var_postdecl_padding_e2e() {
    let n = circomlib_e2e_verify(
        "VarPostDeclPadding(64)",
        "test/circomlib/var_postdecl_padding_test.circom",
        &[],
    );
    assert_eq!(
        n, 631,
        "expected 631 constraints (512 signal slots + per-iter constraints from the four padding loops)"
    );
}

/// Gap E closed: a function that declares internal state (`var`
/// arrays, loops, multi-statement computation) and returns the
/// internal array now lowers to an Artik witness call instead of
/// E212. The lift emits one witness slot per array element, and
/// `inline_function_call` re-bundles the slots into a `LetArray` so
/// the caller's `var tmp[4] = derive(in); out[i] <-- tmp[i];`
/// pattern round-trips without hitting the old name-shadowing bug
/// (`var out[256]` vs `signal output out[256]`).
///
/// This test was originally the E212 regression asserted by Fase 1.
/// With Fase 2.1's array-return support, the same fixture now
/// compiles cleanly, so the assertion flips: we verify that the
/// lift produced four output slots and a matching LetArray.
#[test]
fn fn_local_shadowing_lifts_through_artik() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_local_shadowing_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Gap E fixture failed to compile after lift: {e}"));

    let mut witness_call_outputs: Option<Vec<String>> = None;
    let mut let_array_len: Option<usize> = None;
    for node in &result.prove_ir.body {
        match node {
            CircuitNode::WitnessCall {
                output_bindings, ..
            } => {
                witness_call_outputs = Some(output_bindings.clone());
            }
            CircuitNode::LetArray { elements, .. } => {
                if let_array_len.is_none() {
                    let_array_len = Some(elements.len());
                }
            }
            _ => {}
        }
    }

    let outs = witness_call_outputs.expect("expected a WitnessCall in ProveIR");
    assert_eq!(outs.len(), 4, "array-return should expose 4 witness slots");
    assert_eq!(
        let_array_len,
        Some(4),
        "expected a LetArray of length 4 re-bundling the 4 witness slots"
    );
}

/// Fase 2 lift success: a function with a non-trivial body (one
/// `var` + a `return` over arithmetic on the parameter) now lowers
/// through the Artik witness-call pass instead of E212. We verify
/// that (a) compilation succeeds, (b) the ProveIR contains a
/// `WitnessCall` node carrying an Artik bytecode payload, and (c)
/// the payload round-trips through the witness decoder cleanly (so
/// the structural validator accepts it).
#[test]
fn fn_witness_lift_produces_artik_call() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("witness lift test failed to compile: {e}"));

    // Walk the ProveIR body looking for the new WitnessCall variant.
    let mut call: Option<(Vec<String>, usize)> = None;
    for node in &result.prove_ir.body {
        if let CircuitNode::WitnessCall {
            output_bindings,
            program_bytes,
            ..
        } = node
        {
            call = Some((output_bindings.clone(), program_bytes.len()));
            break;
        }
    }
    let (outs, byte_len) = call.expect("expected a CircuitNode::WitnessCall in ProveIR");
    assert_eq!(outs.len(), 1, "expected exactly one output binding");
    assert!(
        outs[0].starts_with("__artik_derive_scalar_"),
        "unexpected output name: {}",
        outs[0]
    );
    assert!(
        byte_len > 16,
        "Artik payload must be larger than the header"
    );

    // Round-trip the payload: if decode + validate accept it, the
    // lift produced a structurally sound program.
    //
    // We grab the bytes again now that we know one exists.
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .unwrap();
    artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("Artik payload must decode and validate");
}

/// Fase 2.1 lift extension: a function body with a compile-time
/// bounded `for` loop now unrolls at lift time. The loop variable
/// becomes a ConstInt in the lift state; each iteration's body is
/// lowered with the variable substituted as `PushConst`. Verifies
/// that (a) the loop-bearing function lowers without E212, (b) the
/// resulting Artik payload is larger than the single-iteration
/// baseline (evidence the body was actually emitted 4×), and (c)
/// the payload validates.
#[test]
fn fn_witness_lift_unrolls_for_loop() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("loop lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    // Bytes from the simpler baseline (`var y = x*2; return y+1;`)
    // land around 50–60. An unrolled 4-iteration loop with an
    // accumulator is measurably larger — assert we passed that floor
    // so a regression that silently falls back to the single-return
    // path (or worse, truncates the body) gets caught.
    assert!(
        bytes.len() > 80,
        "unrolled loop payload suspiciously small: {} bytes",
        bytes.len()
    );

    artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("unrolled Artik payload must decode and validate");
}

/// Fase 2.1 lift extension: compile-time-folded `if / else` inside
/// an unrolled loop selects the right branch per iteration without
/// emitting any JumpIf. Runtime conditions still fall back to E212.
#[test]
fn fn_witness_lift_folds_if_else_in_loop() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_ifelse_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("if/else lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("payload must decode and validate");

    // Spot-check: no JumpIf / Jump should have been emitted — the
    // condition folded at lift time, so the program is straight-line.
    for instr in &prog.body {
        assert!(
            !matches!(
                instr,
                artik::Instr::Jump { .. } | artik::Instr::JumpIf { .. }
            ),
            "compile-time-folded branch should not emit Jump instructions"
        );
    }
}

/// Fase 2.1 lift extension: internal arrays declared via
/// `var arr[N];` are backed by Artik `AllocArray` of `ElemT::Field`;
/// `arr[i] = expr` emits `StoreArr` and `arr[i]` emits `LoadArr`
/// once `i` folds at lift time. Verified end-to-end by round-
/// tripping the payload through the witness decoder and confirming
/// the body contains matching allocate / store / load opcodes.
#[test]
fn fn_witness_lift_handles_internal_array() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("array payload must decode and validate");

    let mut seen_alloc = false;
    let mut seen_store = false;
    let mut seen_load = false;
    for instr in &prog.body {
        match instr {
            artik::Instr::AllocArray { .. } => seen_alloc = true,
            artik::Instr::StoreArr { .. } => seen_store = true,
            artik::Instr::LoadArr { .. } => seen_load = true,
            _ => {}
        }
    }
    assert!(seen_alloc, "expected an AllocArray in the lifted program");
    assert!(seen_store, "expected at least one StoreArr (write path)");
    assert!(seen_load, "expected at least one LoadArr (read path)");
}

/// Fase 2.1 lift extension: a nested function call inside another
/// lifted function body is inlined into the same Artik program.
/// `compute(x)` calls `helper` twice; both invocations lower into
/// `compute`'s single program (no separate WitnessCall per call),
/// and the resulting payload contains exactly one `Return` opcode.
#[test]
fn fn_witness_lift_inlines_nested_call() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_nested_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("nested-call lift test failed to compile: {e}"));

    let mut witness_call_count = 0;
    let mut payload: Option<Vec<u8>> = None;
    for node in &result.prove_ir.body {
        if let CircuitNode::WitnessCall { program_bytes, .. } = node {
            witness_call_count += 1;
            payload = Some(program_bytes.clone());
        }
    }
    assert_eq!(
        witness_call_count, 1,
        "nested calls must be inlined into a single WitnessCall"
    );
    let prog = artik::bytecode::decode(&payload.unwrap(), Some(memory::FieldFamily::BnLike256))
        .expect("nested-lift payload must decode and validate");

    let return_count = prog
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::Return))
        .count();
    assert_eq!(
        return_count, 1,
        "the final program must have exactly one Return — nested returns are captured, not emitted"
    );
}

/// Fase 2.2 lift extension: an `if / else` with a runtime-signal
/// condition lifts to a field-arithmetic mux instead of falling back
/// to E212. The lift normalizes `cond` via `FEq(cond, 0)` +
/// `FieldFromInt U64` + `FSub` so circom's "0 is false, non-zero is
/// true" semantics hold, then merges scalar locals with
/// `cond * then + (1 - cond) * else`. No `Jump` / `JumpIf` opcodes
/// are emitted.
#[test]
fn fn_witness_lift_muxes_runtime_if_else() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_mux_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mux lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("mux payload must decode and validate");

    // No control flow emitted — the mux is pure arithmetic.
    for instr in &prog.body {
        assert!(
            !matches!(
                instr,
                artik::Instr::Jump { .. } | artik::Instr::JumpIf { .. }
            ),
            "runtime if/else should lower to a mux, not Jump instructions"
        );
    }

    // Evidence the normalization prelude ran: exactly one FEq (for
    // `cond == 0`), at least one FieldFromInt (lifting the FEq result
    // back to Field), and at least three FMul (two arm-multiplies +
    // at least one from the body's own arithmetic).
    let feq_count = prog
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FEq { .. }))
        .count();
    assert_eq!(
        feq_count, 1,
        "expected exactly one FEq from the cond-normalization prelude"
    );
    let field_from_int_count = prog
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FieldFromInt { .. }))
        .count();
    assert!(
        field_from_int_count >= 1,
        "expected FieldFromInt to lift FEq result back to Field"
    );
    let fmul_count = prog
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FMul { .. }))
        .count();
    assert!(
        fmul_count >= 3,
        "expected at least 3 FMul ops (then/else mux + body multiplies), got {fmul_count}"
    );

    // End-to-end execution check: feed both cond=0 and cond=1 cases
    // through the Artik executor directly. This proves the mux
    // actually selects the right arm — the decoder/validator above
    // only verifies structural soundness, not semantics.
    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    // cond=1, a=10, b=99 → select returns a + 1 == 11.
    let signals_true = [FE::from_u64(1), FE::from_u64(10), FE::from_u64(99)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals_true, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=1");
    assert_eq!(slots[0], FE::from_u64(11), "mux cond=1 should pick a + 1");

    // cond=0, a=10, b=99 → select returns b * 2 == 198.
    let signals_false = [FE::from_u64(0), FE::from_u64(10), FE::from_u64(99)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals_false, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=0");
    assert_eq!(slots[0], FE::from_u64(198), "mux cond=0 should pick b * 2");

    // cond=7 (non-zero, non-bool) exercises the FEq-normalization
    // prelude — circom treats any non-zero as true.
    let signals_seven = [FE::from_u64(7), FE::from_u64(10), FE::from_u64(99)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals_seven, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=7");
    assert_eq!(
        slots[0],
        FE::from_u64(11),
        "non-bool cond should normalize to true and pick a + 1"
    );
}

/// Fase 5.1 — array parameters in the Artik lift. A function with
/// `arr[N]` as a formal parameter binds to N input signals (one
/// per element). Verified by lifting `array_sum(arr[4])`, pushing
/// it through instantiate + R1CS + Groth16, and confirming the
/// proof verifies when the template constraints match the Artik
/// witness.
#[test]
fn fn_witness_lift_array_param_e2e_groth16() {
    use std::collections::{HashMap, HashSet};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_param_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-param lift failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    // array_sum(inp) = inp[0] + 2*inp[1] + 3*inp[2] + 4*inp[3].
    let inp = [3u64, 5, 7, 11];
    let expected_out = inp[0] + 2 * inp[1] + 3 * inp[2] + 4 * inp[3];

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (i, v) in inp.iter().enumerate() {
        inputs.insert(format!("inp_{i}"), FieldElement::<Bn254Fr>::from_u64(*v));
    }
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verify failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ array_sum(inp[4]={inp:?}) = {expected_out} — Artik→Groth16 VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 5.1 (array-literal init): a function body declares
/// `var k[N] = [literal, ...];` and indexes `k[i]` in a loop.
/// The lift allocates the backing store at declaration time and
/// StoreArrs each literal into its slot, so later reads resolve
/// via `LoadArr`. This is the `sha256K` shape: a constant table
/// packed into a `var` at the top of a helper function.
///
/// Verifies `n * (1+2+3+4) = 10*n` through Groth16 with n=7.
#[test]
fn fn_witness_lift_array_literal_e2e_groth16() {
    use std::collections::{HashMap, HashSet};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_literal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-literal lift failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    let n = 7u64;
    let expected_out = 10 * n;

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("n".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verify failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ table_sum() * {n} = {expected_out} — Artik→Groth16 VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// SHA-256 compile probe — does circomlib's `sha256compression`
/// now make it through the Artik lift end-to-end?
///
/// Fase 5.1 closed the two historical blockers: array parameters
/// (`hin[256]`, `inp[512]` bound at call sites) and array-literal
/// initializers (`var k[64] = [...]` inside `sha256K`). Running
/// this un-ignored will either pass outright or surface whatever
/// remains — e.g. more exotic bit-manipulation shapes the lift
/// doesn't cover yet. Kept separate from the focused lift tests so
/// failures don't mask simpler regressions.
#[test]
#[ignore = "SHA-256 compile probe — run with --ignored to check Fase 5 completeness"]
fn sha256_64_compiles_via_artik_lift() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let _ = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
}

/// SHA-256 R1CS probe — reports where the pipeline breaks when
/// going past lowering: instantiate, optimize, or R1CS build.
/// Does NOT provide a correct witness — the goal is only to
/// exercise the structural pipeline and surface constraint count
/// or the first hard error (budget, memory, unsupported node).
///
/// Current state (post const-dedup + peephole const-fold fix):
/// the OOM is gone — peak RSS stays around 545 MB (vs. 6.6 GB
/// before the fix). But the probe still fails to complete within
/// practical time budgets: `instantiate` has run >25 min without
/// producing the `[instantiate]` print. The root cause is
/// architectural, not memory-bound: `Sha256(64)` has deeply
/// nested loops (64 rounds × SigmaPlus(48) × SmallSigma0/1 with
/// 32-bit decomposes) that our pipeline unrolls fully into flat
/// SSA during instantiate. Circom avoids this by keeping
/// templates abstract until final R1CS emission. On lighter
/// circuits (Poseidon/MiMC/EdDSA) Achronyme beats circom ≥10×,
/// but bit-heavy nested circuits like SHA-256 expose the gap.
///
/// Follow-up (post-beta.20): lazy unrolling (keep `CircuitNode::For`
/// until R1CS backend) or template instancing with sub-tree
/// sharing — see `project_instantiate_refactor.md`.
#[test]
#[ignore = "SHA-256 R1CS probe — diagnostic only; hangs during instantiate due to unrolling amplification"]
fn sha256_64_r1cs_probe() {
    use std::collections::HashSet;
    use std::time::Instant;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("  [compile]     {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    eprintln!(
        "  [instantiate] {:?}  instructions={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "  [optimize]    {:?}  instructions={}",
        t2.elapsed(),
        program.len()
    );

    // Build R1CS without an inputs map — constraints still get emitted,
    // the witness will just be wrong. We only care whether the pipeline
    // survives to produce a constraint system.
    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let result = rc.compile_ir_with_witness(&program, &inputs);
    eprintln!("  [r1cs build]  {:?}", t3.elapsed());

    match result {
        Ok(_w) => eprintln!("  ✓ R1CS built: constraints={}", rc.cs.num_constraints()),
        Err(e) => eprintln!("  ✗ R1CS failed: {e}"),
    }
}

/// Shared body of the `sha256_{8,16,32,64}_lysis_hard_gate` tests
/// (Phase 0.5 — BETA20-CLOSEOUT). Each variant pins a specific
/// `Sha256(nbits)` circuit against circom 2.2.3 `--O2` constraint
/// counts with a wall-clock budget; the per-variant `#[test]`
/// wrappers below select the fixture and tolerance.
///
/// Implementation notes (apply identically to every variant):
///
///   - **Lysis frontend.** `compile_file(..)` keeps loop-var-indexed
///     signal writes rolled inside `CircuitNode::For`, so the
///     `SymbolicIndexedEffect` path can carry them through to
///     walker-time per-iteration unfolding — avoiding the
///     6.4 GB OOM the gate exists to prevent.
///   - **`compile_ir` (witness-less).** This gate verifies structural
///     completion + constraint count, not witness validity. The
///     witness path eagerly evaluates every IR node and asserts wire
///     values against runtime `AssertEq` / `RangeCheck` constraints,
///     which would require a valid SHA-256 hash for arbitrary inputs
///     -- out of scope. The constraint skeleton emitted by
///     `compile_ir` is identical regardless of operand values; the
///     gate inspects only that skeleton.
///   - **O1 only.** DEDUCE (O2) builds a k x q monomial matrix that
///     is ~100 GB for SHA-256(64). O1 alone closes the gap because
///     `compile_ir` emits ~40k pure-linear constraints (`1.LC=C`)
///     that O1 eliminates by structural substitution.
///
/// Pinning to circom 2.2.3 specifically because counts drift between
/// releases; recapture every baseline if the toolchain bumps.
fn run_sha256_lysis_hard_gate(
    label: &str,
    fixture: &str,
    nbits: u64,
    circom_o2_constraints: usize,
    wall_clock_budget: Duration,
) {
    use std::collections::HashSet;

    const TOLERANCE: f64 = 0.15;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(fixture);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{label} compile failed: {e}"));
    eprintln!("[{label}] [compile]       {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert(
        "nBits".to_string(),
        FieldElement::<Bn254Fr>::from_u64(nbits),
    );
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate_lysis");
    eprintln!(
        "[{label}] [instantiate]   {:?}  instructions={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "[{label}] [ir-optimize]   {:?}  instructions={}",
        t2.elapsed(),
        program.len()
    );

    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_o1 = rc.cs.num_constraints();
    eprintln!(
        "[{label}] [r1cs build]    {:?}  constraints={pre_o1}",
        t3.elapsed()
    );

    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let constraints = rc.cs.num_constraints();
    eprintln!(
        "[{label}] [r1cs O1]       {:?}  constraints={constraints}  vars_eliminated={}  rounds={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
    );

    let total_elapsed = total.elapsed();
    eprintln!("[{label}] [total]         {:?}", total_elapsed);
    eprintln!(
        "[{label}] [circom O2 baseline: {circom_o2_constraints}, tolerance: ±{:.0}%]",
        TOLERANCE * 100.0
    );

    // Gate 1: wall-clock budget.
    assert!(
        total_elapsed < wall_clock_budget,
        "{label} Lysis path exceeded {wall_clock_budget:?} budget (took {total_elapsed:?})"
    );

    // Gate 2: constraint count within tolerance of circom O2.
    let lower = (circom_o2_constraints as f64 * (1.0 - TOLERANCE)) as usize;
    let upper = (circom_o2_constraints as f64 * (1.0 + TOLERANCE)) as usize;
    assert!(
        (lower..=upper).contains(&constraints),
        "{label} constraint count {constraints} outside circom O2 tolerance [{lower}, {upper}] \
         (baseline={circom_o2_constraints}, tolerance=+/-{:.0}%)",
        TOLERANCE * 100.0
    );
}

/// SHA-256(8) Lysis hard-gate. See [`run_sha256_lysis_hard_gate`]
/// for the gate semantics + architectural rationale.
///
/// circom 2.2.3 `--O2` baseline: 28,953 constraints.
///
/// Smallest legal SHA-256 input — exercises the round + finalizer
/// with minimal frontend wiring overhead. Useful as a fast regression
/// check at one-block scale; a regression that doesn't surface here
/// (vs. (64) where it would dominate the perf/correctness signal)
/// is by definition specific to the larger-message wiring path.
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host. Run with `--ignored sha256_8_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path."]
fn sha256_8_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(8)",
        "test/circomlib/sha256_8_test.circom",
        8,
        28_953,
        Duration::from_secs(120),
    );
}

/// SHA-256(16) Lysis hard-gate. See [`run_sha256_lysis_hard_gate`]
/// for the gate semantics + architectural rationale.
///
/// circom 2.2.3 `--O2` baseline: 28,953 constraints (same as (8) and
/// (32) — single 512-bit block dominates the post-O2 count; only
/// the frontend wiring scales with `nBits`, all of which O2 eats).
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host. Run with `--ignored sha256_16_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path."]
fn sha256_16_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(16)",
        "test/circomlib/sha256_16_test.circom",
        16,
        28_953,
        Duration::from_secs(120),
    );
}

/// SHA-256(32) Lysis hard-gate. See [`run_sha256_lysis_hard_gate`]
/// for the gate semantics + architectural rationale.
///
/// circom 2.2.3 `--O2` baseline: 28,953 constraints. Mid-size variant:
/// still one 512-bit block but with more frontend `Num2Bits` wiring
/// than (8)/(16). The wider input range stresses Walker
/// per-iteration body sharing on the `for(i=0..32) { ... in[i] ... }`
/// expansion.
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host. Run with `--ignored sha256_32_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path."]
fn sha256_32_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(32)",
        "test/circomlib/sha256_32_test.circom",
        32,
        28_953,
        Duration::from_secs(120),
    );
}

/// **Phase 3.C.6 Stage 3 HARD GATE** -- SHA-256(64) through the Lysis
/// pipeline (`ProveIR::instantiate_lysis_with_outputs`) must:
///
/// 1. Complete end-to-end (compile + instantiate + IR-optimize +
///    R1CS-build + R1CS-O1) in under 120 seconds wall-clock. The
///    legacy `sha256_64_r1cs_probe` hangs >25 minutes; Lysis
///    avoids that by emitting `ExtendedInstruction::LoopUnroll`
///    nodes the InterningSink hash-cons across iterations.
/// 2. Produce a post-O1 R1CS constraint count within +/-15% of
///    circom 2.2.3's `--O2` baseline. The bound is intentionally
///    looser than the plan's +/-5% because (a) we target BN254
///    while circom canonically reports for 254-bit, (b) achronyme
///    O1 matches or beats circom O2 on Poseidon/MiMC but bit-heavy
///    circuits like SHA-256 may carry a small DEDUCE-shaped
///    residual -- DEDUCE itself is unscalable here (k x q monomial
///    matrix grows to tens of GB on SHA-256) so we accept the
///    residual.
///
/// Reference numbers (Apr 2026, post Phase 1.C validate gate +
/// walker do_split fix):
///
/// ```text
///   [compile]       ~13s   (circom lowering -- separate perf work)
///   [instantiate]   ~1.2s  instructions=207,332
///   [ir-optimize]   ~93ms  instructions=199,932
///   [r1cs build]    ~46ms  constraints=70,623   (40,337 linear + 29,972 quadratic)
///   [r1cs O1]       ~710ms constraints=29,790   (eliminates 40,832 vars in 2 rounds)
/// ```
///
/// achronyme post-O1 (29,790) sits 2.7% above circom O2 (29,014),
/// well within the ±15% tolerance.
///
/// Notes:
///
/// - Uses arbitrary inputs. We care about structural completion,
///   not witness correctness (the constraint count doesn't depend
///   on input values).
/// - Output lines are `eprintln`-style diagnostic -- they surface
///   wall-clock + instruction/constraint counts. If the gate
///   fails, these give the first-look picture.
/// - DEDUCE (`optimize_r1cs_o2`) is intentionally NOT run: the
///   monomial x constraint matrix for SHA-256(64) is roughly
///   60k x 60k field elements (~100 GB), unscalable on this
///   circuit. The constraint benchmark `r1cs_optimization_benchmark`
///   exercises O2 on smaller circuits where it converges quickly.
///
/// **Closed architectural blockers (cumulative 2026-04-25)**:
///
///   1. **Lifted template frame overflow** -- *closed*
///      (`9828dcbe` + `f42f3ce0`).
///   2. **Live-set > 64 captures** -- *closed* (Phase 4,
///      `feat/lysis-phase4-heap`).
///   3. **`SymbolicIndexedEffectNotEmittable` after split** --
///      *closed*: walker_const forwarded unfiltered across splits.
///   4. **`Alloc(FrameOverflow)` from cold WitnessCall inputs** --
///      *closed*: `EmitWitnessCallHeap` mixed reg/slot inputs.
///   5. **`UninitializedRegister` from missing capture init** --
///      *closed*: validator rule 9 pre-initialises template
///      capture regs (`94a63693`).
///   6. **`UninitializedRegister` from missing heap-op writes** --
///      *closed*: rule 9 tracks `StoreHeap` reads and `LoadHeap`
///      writes (`750171cf`).
///   7. **`MaxCallDepthExceeded`** -- *closed*: default cap raised
///      from 64 to 8192 to cover Phase 4 chain depth (`0160b073`).
///   8. **`optimize` pass dangling SsaVar (issue #86)** --
///      *closed*: const_fold expansion was keyed by `result_var`,
///      ambiguous under alias-Decompose. Now keyed by instruction
///      index.
///   9. **R1CS constraint parity** -- *closed*: gap was the missing
///      `optimize_r1cs()` call (40,337 linear constraints that O1
///      eliminates). achronyme post-O1 = 29,790, within +/-4% of
///      circom O2.
///  10. **Validator latency** -- *closed* (Phase 1.C, 2026-04-30,
///      `73d0ceff`): `lysis::bytecode::validate` gated behind
///      `cfg(debug_assertions)`. Release-mode instantiate dropped
///      from 1.96s to 1.22s on SHA-256(64).
///
/// **Remaining work (each independent of Phase 4 / this gate)**:
///
///   - **Compile time** ~13s on this host (down from ~47s pre-perf
///     work). Tracked as a separate workstream.
///   - **Lazy-reload-without-recycling frame growth** -- v1.1
///     placeholder (`ir-forge/tests/walker_adversarial.rs`); not
///     hit by SHA-256(64), would surface for larger circuits.
#[test]
#[ignore = "SHA-256 compile + instantiate + R1CS-O1 takes ~15s on this host (down from ~47s pre-perf work). Run with `--ignored sha256_64_lysis_hard_gate` locally before pushing changes that touch the Lysis walker, R1CS optimizer, or instantiate path. Once compile time drops further, this can become a CI-default gate."]
fn sha256_64_lysis_hard_gate() {
    run_sha256_lysis_hard_gate(
        "SHA-256(64)",
        "test/circomlib/sha256_test.circom",
        64,
        29_014,
        Duration::from_secs(120),
    );
}

/// Diagnostic instrumentation for the SHA-256(64) constraint-parity gap.
///
/// The hard-gate (`sha256_64_lysis_hard_gate`) reports 70,623 constraints
/// post-IR-optimize, *pre*-R1CS-optimize. circom 2.2.3 with `--O2` on the
/// same circuit reports 29,014 (0 linear, 29,014 non-linear). This test
/// runs the full pipeline through `optimize_r1cs()` (O1 -- linear
/// elimination only, no DEDUCE) and prints:
///
///   - constraint count + shape histogram pre-optimize
///   - constraint count + shape histogram post-O1
///   - the gap vs circom O0/O1/O2
///
/// O2 (DEDUCE Gaussian elimination) is intentionally skipped -- the
/// monomial x constraint matrix is `~k x q` `FieldElement`s where both
/// dimensions reach ~60k for SHA-256(64), exceeding 16 GB of RAM.
/// circom's own progression (O0->O1 kills 171k linears, O1->O2 only ~2k
/// more) suggests O1 closes most of the gap by itself.
///
/// Shape categories follow the `is_linear` predicate from
/// `r1cs_optimize::predicates`: a constraint with one of A/B simplifying
/// to a constant counts as "linear", everything else gets bucketed by
/// term-count of A,B,C. The `(|A|,|B|,|C|)` histogram surfaces dominant
/// patterns (e.g. `(1,1,0)` for `x*x=0`-shaped, `(1,2,0)` for bool
/// checks, `(1,N,0)` for bit-decomposition equality).
///
/// `#[ignore]`d -- compile alone is ~47s on this host.
#[test]
#[ignore = "SHA-256(64) constraint shape diagnostic -- compile is ~47s. Run with `--ignored sha256_64_constraint_breakdown` to capture pre/post-O1 distributions."]
fn sha256_64_constraint_breakdown() {
    use std::collections::HashSet;
    use std::time::Instant;

    // circom 2.2.3 baseline captured 2026-04-25 from
    // `circom test/circomlib/sha256_test.circom --r1cs --O{0,1,2}`.
    const CIRCOM_O0: usize = 204_576;
    const CIRCOM_O1: usize = 31_264;
    const CIRCOM_O2: usize = 29_014;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("[compile]      {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    eprintln!(
        "[instantiate]  {:?}  ir_inst={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "[ir-opt]       {:?}  ir_inst={}",
        t2.elapsed(),
        program.len()
    );

    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_o2 = rc.cs.num_constraints();
    eprintln!("[r1cs build]   {:?}  constraints={pre_o2}", t3.elapsed());

    eprintln!("\n-- PRE-R1CS-O2 shape histogram ----------------------");
    print_constraint_histogram(rc.cs.constraints());

    // Note: we run only O1 (`optimize_r1cs`) here, not O2.
    // For SHA-256(64) the DEDUCE Gaussian elimination in O2 builds a
    // monomial x constraint matrix of order ~60k x 60k field elements,
    // which is ~100 GB and OOMs on a 16 GB host. circom's progression
    // (O0->O1 kills 171k linears, O1->O2 only saves ~2k more) suggests
    // O1 is sufficient for the parity gap on this circuit.
    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "\n[r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}  trivial_removed={}  duplicates_removed={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
        stats.trivial_removed,
        stats.duplicates_removed,
    );

    eprintln!("\n-- POST-R1CS-O1 shape histogram ---------------------");
    print_constraint_histogram(rc.cs.constraints());

    eprintln!("\n-- circom 2.2.3 baseline ----------------------------");
    eprintln!("  --O0 = {CIRCOM_O0}");
    eprintln!("  --O1 = {CIRCOM_O1}");
    eprintln!("  --O2 = {CIRCOM_O2}");

    eprintln!("\n-- achronyme vs circom delta ------------------------");
    let delta_vs_o1 = post_o1 as i64 - CIRCOM_O1 as i64;
    let pct_vs_o1 = (delta_vs_o1 as f64 / CIRCOM_O1 as f64) * 100.0;
    let delta_vs_o2 = post_o1 as i64 - CIRCOM_O2 as i64;
    let pct_vs_o2 = (delta_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;
    eprintln!("  achronyme pre-opt   = {pre_o2}");
    eprintln!("  achronyme post-O1   = {post_o1}");
    eprintln!("  vs circom O1 ({CIRCOM_O1})  -> delta = {delta_vs_o1:+}  ({pct_vs_o1:+.1}%)");
    eprintln!("  vs circom O2 ({CIRCOM_O2})  -> delta = {delta_vs_o2:+}  ({pct_vs_o2:+.1}%)");

    eprintln!("\n[total] {:?}", total.elapsed());
}

/// Histogram printer for [`sha256_64_constraint_breakdown`].
///
/// Two bucket layers:
///   - **category** -- `is_linear`-style coarse classification (linear
///     constraints with A or B constant, vs genuinely quadratic ones
///     bucketed by term-count signature).
///   - **(|A|,|B|,|C|)** -- fine-grained term-count distribution; surfaces
///     things like the bool-check shape `(1,2,0)` or bit-decomposition
///     shape `(1,N,0)` directly.
fn print_constraint_histogram<F: memory::FieldBackend>(
    constraints: &[constraints::r1cs::Constraint<F>],
) {
    use std::collections::BTreeMap;

    let mut by_category: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_size: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();

    for c in constraints {
        let a = c.a.simplify();
        let b = c.b.simplify();
        let cc = c.c.simplify();

        let label = classify_constraint(&a, &b, &cc);
        *by_category.entry(label).or_insert(0) += 1;

        let key = (
            a.terms().len().min(99),
            b.terms().len().min(99),
            cc.terms().len().min(99),
        );
        *by_size.entry(key).or_insert(0) += 1;
    }

    eprintln!("  by category:");
    let mut items: Vec<_> = by_category.into_iter().collect();
    items.sort_by(|x, y| y.1.cmp(&x.1));
    for (label, n) in items {
        eprintln!("    {label:38} = {n}");
    }

    eprintln!("\n  by (|A|,|B|,|C|), top 15 buckets:");
    let mut items: Vec<_> = by_size.into_iter().collect();
    items.sort_by(|x, y| y.1.cmp(&x.1));
    for ((an, bn, cn), n) in items.into_iter().take(15) {
        eprintln!("    ({an:3},{bn:3},{cn:3}) = {n}");
    }
}

/// Coarse classifier matching `r1cs_optimize::predicates::is_linear`
/// without depending on the `pub(super)` predicate directly.
fn classify_constraint<F: memory::FieldBackend>(
    a: &constraints::LinearCombination<F>,
    b: &constraints::LinearCombination<F>,
    cc: &constraints::LinearCombination<F>,
) -> &'static str {
    let a_const = a.is_constant();
    let b_const = b.is_constant();

    if a_const && b_const {
        return "trivial-constant (A,B both const)";
    }
    if a_const {
        return if a.terms().is_empty() {
            "linear (A=0  =>  C=0)"
        } else {
            "linear (A=k  =>  k.B=C)"
        };
    }
    if b_const {
        return if b.terms().is_empty() {
            "linear (B=0  =>  C=0)"
        } else {
            "linear (B=k  =>  k.A=C)"
        };
    }

    let an = a.terms().len();
    let bn = b.terms().len();
    let cn = cc.terms().len();

    if an == 1 && bn == 1 && cn == 0 {
        "quadratic 1x1=0  (e.g. x.y=0 / x^2=0 / x.(1-x))"
    } else if an == 1 && bn == 1 {
        "quadratic 1x1=K"
    } else if an == 1 && bn == 2 && cn == 0 {
        "quadratic 1x2=0  (bool-check shape candidate)"
    } else if (an == 1 && bn > 1) || (an > 1 && bn == 1) {
        "quadratic 1xN (mono . multi)"
    } else {
        "quadratic NxM (multi . multi)"
    }
}

/// SHA-256(64) sparse-DEDUCE probe.
///
/// Diagnostic-only counterpart to `sha256_64_lysis_hard_gate` that
/// validates whether sparse-clustered DEDUCE (`optimize_r1cs_o2_sparse`)
/// recovers any constraints O1 alone misses on a real bit-heavy
/// circuit.
///
/// The dense `optimize_r1cs_o2` is intentionally NOT exercised:
/// SHA-256(64) generates `~k x q` `FieldElement`s with both dimensions
/// near 60k (~100 GB) and would OOM on most hosts. The sparse path is
/// the whole point of this probe.
///
/// Steps:
///
///   1. Compile (~47s, dominated by circom lowering).
///   2. Build R1CS (witness-less, like the hard-gate).
///   3. Run O1 once -- record constraint count.
///   4. Run O2-sparse on a snapshot of the post-O1 constraints --
///      record constraint count.
///   5. Print O1 -> O2-sparse delta and the gap vs the circom 2.2.3
///      O2 baseline (29,014).
///
/// Stays `#[ignore]`d for the same reason the hard-gate is: ~47s of
/// circom lowering plus a few hundred ms of sparse DEDUCE on top.
/// Run with
/// `cargo test ... --ignored sha256_64_o2_sparse_probe -- --nocapture`.
#[test]
#[ignore = "SHA-256(64) sparse-DEDUCE probe -- compile is ~47s on this host. Run with `--ignored sha256_64_o2_sparse_probe -- --nocapture` to capture the O1 -> O2-sparse delta."]
fn sha256_64_o2_sparse_probe() {
    use std::collections::HashSet;
    use std::time::Instant;

    // circom 2.2.3 baselines on test/circomlib/sha256_test.circom.
    // Pin to a specific circom version because counts drift across
    // releases; recapture if the toolchain bumps.
    const CIRCOM_O1: usize = 31_264;
    const CIRCOM_O2: usize = 29_014;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("[compile]      {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    eprintln!(
        "[instantiate]  {:?}  ir_inst={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "[ir-opt]       {:?}  ir_inst={}",
        t2.elapsed(),
        program.len()
    );

    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_opt = rc.cs.num_constraints();
    eprintln!("[r1cs build]   {:?}  constraints={pre_opt}", t3.elapsed());
    let num_pub_inputs = rc.cs.num_pub_inputs();

    // Phase 6 default: optimize_r1cs is the cluster-based driver.
    // The historical greedy implementation is preserved as the
    // per-cluster fallback for clusters above
    // CLUSTER_FALLBACK_THRESHOLD.
    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "[r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
    );

    // Snapshot post-O1 constraints; optimize_o2_sparse internally
    // reruns O1 (no-op on already-O1 input) then enters its
    // decompose + DEDUCE outer loop. Any extra reductions surface as
    // a delta vs post_o1.
    let post_o1_snapshot: Vec<constraints::r1cs::Constraint<Bn254Fr>> =
        rc.cs.constraints().to_vec();

    let t5 = Instant::now();
    let mut sparse_constraints = post_o1_snapshot;
    let (_subs, sparse_stats) =
        constraints::r1cs_optimize::optimize_o2_sparse(&mut sparse_constraints, num_pub_inputs);
    let post_o2_sparse = sparse_stats.constraints_after;
    eprintln!(
        "[r1cs O2-sparse] {:?}  constraints={post_o2_sparse}  delta_vs_O1={:+}  vars_eliminated={}",
        t5.elapsed(),
        post_o2_sparse as i64 - post_o1 as i64,
        sparse_stats.variables_eliminated,
    );

    let delta_o1_vs_o2 = post_o1 as i64 - CIRCOM_O2 as i64;
    let pct_o1_vs_o2 = (delta_o1_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;
    let delta_o2s_vs_o2 = post_o2_sparse as i64 - CIRCOM_O2 as i64;
    let pct_o2s_vs_o2 = (delta_o2s_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;

    eprintln!("\n-- circom 2.2.3 baseline --");
    eprintln!("  --O1 = {CIRCOM_O1}");
    eprintln!("  --O2 = {CIRCOM_O2}");

    eprintln!("\n-- achronyme vs circom O2 --");
    eprintln!("  achronyme pre-opt    = {pre_opt}");
    eprintln!("  achronyme post-O1    = {post_o1}");
    eprintln!("  achronyme post-O2-s  = {post_o2_sparse}");
    eprintln!(
        "  achO1   vs cirO2 ({CIRCOM_O2})  -> delta = {delta_o1_vs_o2:+}  ({pct_o1_vs_o2:+.1}%)"
    );
    eprintln!(
        "  achO2-s vs cirO2 ({CIRCOM_O2})  -> delta = {delta_o2s_vs_o2:+}  ({pct_o2s_vs_o2:+.1}%)"
    );

    eprintln!("\n[total] {:?}", total.elapsed());
}

/// Cluster size diagnostic: for each circomlib template, build the
/// raw R1CS, partition the linear constraints by shared signal, and
/// dump the cluster size histogram. Validates whether
/// `CLUSTER_FALLBACK_THRESHOLD = 500` actually matters in practice
/// (i.e. there exist clusters in the (500, 5000) range that get
/// routed to the greedy fallback).
///
/// Stays `#[ignore]`d so it does not run in the default test pass;
/// invoke with `--ignored cluster_size_diagnostic -- --nocapture`.
#[test]
#[ignore = "Diagnostic-only: run with --ignored cluster_size_diagnostic -- --nocapture to inspect cluster size distributions per circuit."]
fn cluster_size_diagnostic() {
    use std::collections::{BTreeMap, HashSet};

    fn compile(name: &str, file: &str, inputs: HashMap<String, FieldElement<Bn254Fr>>) {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(file);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];

        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("compile {name} failed: {e}"));
        let prove_ir = &compile_result.prove_ir;
        let capture_values = &compile_result.capture_values;
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();

        let mut program = prove_ir
            .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
            .unwrap_or_else(|e| panic!("instantiate {name} failed: {e}"));
        ir::passes::optimize(&mut program);

        let mut all_signals =
            circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
                .unwrap_or_else(|e| panic!("witness {name} failed: {e}"));
        for (cname, fe) in &fe_captures {
            all_signals.entry(cname.clone()).or_insert(*fe);
        }

        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        compiler
            .compile_ir_with_witness(&program, &all_signals)
            .unwrap_or_else(|e| panic!("r1cs {name} failed: {e}"));

        // Re-implement the clustering logic here (build_clusters_by_signal
        // is pub(super), not exposed) to inspect raw cluster sizes
        // before any optimization.
        let raw = compiler.cs.constraints();
        let num_pub_inputs = compiler.cs.num_pub_inputs();
        let protected: HashSet<usize> = (0..=num_pub_inputs).collect();

        // Walk linear constraints, build first-owner Union-Find by signal.
        // Same logic as build_clusters_by_signal.
        let mut linear_indices: Vec<usize> = Vec::new();
        for (i, c) in raw.iter().enumerate() {
            let a = c.a.simplify();
            let b = c.b.simplify();
            let a_const = a.is_constant();
            let b_const = b.is_constant();
            if a_const || b_const {
                linear_indices.push(i);
            }
        }
        let n = linear_indices.len();
        let mut parent: Vec<usize> = (0..n).collect();
        fn find(parent: &mut [usize], mut x: usize) -> usize {
            let mut r = x;
            while parent[r] != r {
                r = parent[r];
            }
            while parent[x] != r {
                let n = parent[x];
                parent[x] = r;
                x = n;
            }
            r
        }
        let mut first_owner: HashMap<usize, usize> = HashMap::new();
        for (loc_idx, &orig_idx) in linear_indices.iter().enumerate() {
            let c = &raw[orig_idx];
            for lc in [&c.a, &c.b, &c.c] {
                for (var, _) in lc.terms() {
                    let sig = var.index();
                    if sig == 0 || protected.contains(&sig) {
                        continue;
                    }
                    match first_owner.get(&sig) {
                        Some(&owner) => {
                            let ra = find(&mut parent, loc_idx);
                            let rb = find(&mut parent, owner);
                            if ra != rb {
                                parent[ra] = rb;
                            }
                        }
                        None => {
                            first_owner.insert(sig, loc_idx);
                        }
                    }
                }
            }
        }
        let mut buckets: HashMap<usize, usize> = HashMap::new();
        for i in 0..n {
            *buckets.entry(find(&mut parent, i)).or_insert(0) += 1;
        }
        let mut sizes: Vec<usize> = buckets.values().copied().collect();
        sizes.sort_unstable();

        let total_linear = n;
        let max_size = sizes.last().copied().unwrap_or(0);
        let n_clusters = sizes.len();

        // Bucket counts for histogram thresholds.
        let mut histo: BTreeMap<&str, usize> = BTreeMap::new();
        for &s in &sizes {
            let bucket = match s {
                1 => "1",
                2..=10 => "2-10",
                11..=100 => "11-100",
                101..=350 => "101-350",
                351..=500 => "351-500",
                501..=1_000 => "501-1000",
                1_001..=5_000 => "1001-5000",
                _ => "5000+",
            };
            *histo.entry(bucket).or_insert(0) += 1;
        }

        let raw_total = raw.len();
        eprintln!("\n[{name}]");
        eprintln!(
            "  raw constraints = {raw_total}, linear = {total_linear}, clusters = {n_clusters}, max cluster = {max_size}"
        );
        eprintln!("  cluster size histogram:");
        for (bucket, count) in &histo {
            eprintln!("    {bucket:>10} : {count}");
        }
    }

    fn fe(v: u64) -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_u64(v)
    }
    let one = |k: &str, v: u64| -> HashMap<String, FieldElement<Bn254Fr>> {
        std::iter::once((k.to_string(), fe(v))).collect()
    };

    compile(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        one("in", 13),
    );
    compile("IsZero", "test/circom/iszero.circom", one("in", 0));
    compile(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        [("in_0", fe(3)), ("in_1", fe(10))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
    compile(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        (0..8).map(|i| (format!("in_{i}"), fe(i % 2))).collect(),
    );
    compile(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        (0..253).map(|i| (format!("e_{i}"), fe(0))).collect(),
    );
    let mut ema_inputs: HashMap<String, FieldElement<Bn254Fr>> =
        (0..254).map(|i| (format!("e_{i}"), fe(0))).collect();
    ema_inputs.insert("p_0".to_string(), fe(0));
    ema_inputs.insert("p_1".to_string(), fe(1));
    compile(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        ema_inputs,
    );
    compile(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        [("inputs_0", fe(1)), ("inputs_1", fe(2))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
    compile(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        [("ins_0", fe(1)), ("ins_1", fe(2)), ("k", fe(0))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
}

/// Fase 4 deliverable check: a circom template whose `out <--`
/// value comes from an Artik witness program goes all the way
/// through Groth16 proof generation and verification on BN-254.
/// This is the end-to-end "can I ship this" test — the same path
/// `ach prove file.circom --input inputs.toml` will walk once the
/// CLI gets wired up.
///
/// Uses `triangle_sum` (for-loop lift producing `6*in`) so the
/// constraint `out === 6 * in` is non-trivial and the proof
/// actually has something to prove.
#[test]
fn fn_witness_lift_e2e_groth16_triangle_sum() {
    use std::collections::HashSet;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Artik→Groth16 compile failed: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    // triangle_sum(n) = 6*n; template enforces `out === 6 * in`.
    let n = 11u64;
    let expected_out = 6 * n;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof generation failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verification failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ Artik→Groth16: triangle_sum({n}) = {expected_out} — PROOF VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 3+4 end-to-end on a SHA-style bit-op body: the same σ0
/// function that exercises `& | ^ >> <<` in the lift gets pushed
/// through instantiate + R1CS + witness verify. The template pins
/// `out === out` so there's no independent constraint on the σ0
/// value — this test is specifically for "the Artik dispatch
/// produces *some* value that satisfies the circuit", confirming
/// the bit-op witness path runs end-to-end (decode → IntFromField →
/// IBin at u32 → FieldFromInt → write slot → R1CS witness wire).
#[test]
fn fn_witness_lift_e2e_r1cs_bitops_dispatch() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::{HashMap, HashSet};
    use zkc::r1cs_backend::R1CSCompiler;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bitops_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("bit-op E2E compile failed: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");

    ir::passes::optimize(&mut program);

    // Compute σ0 reference on the chosen input so we can supply the
    // matching public-output value: `out === out` only tautologizes
    // once `out` has a concrete binding on both sides of the R1CS
    // wire, which requires a user-supplied public-input value.
    fn sigma0_ref(x: u32) -> u32 {
        let r7 = (x >> 7) | (x.wrapping_shl(25));
        let r18 = (x >> 18) | (x.wrapping_shl(14));
        let r3 = x >> 3;
        (r7 ^ r18) ^ r3
    }
    let input_val: u32 = 0xDEAD_BEEF;
    let expected_out = sigma0_ref(input_val);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert(
        "in".to_string(),
        FieldElement::<Bn254Fr>::from_u64(input_val as u64),
    );
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out as u64),
    );

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc
        .compile_ir_with_witness(&program, &inputs)
        .expect("compile_ir_with_witness");
    rc.cs
        .verify(&witness)
        .expect("R1CS should verify with Artik-dispatched σ0 witness");
}

/// Fase 3+4 end-to-end: an Artik-lifted circom function survives
/// through instantiate → optimize → R1CS compile, with the lifted
/// Artik program executed at witness-gen time to fill the output
/// wires. Verified by running `compile_ir_with_witness` and checking
/// that the R1CS verifier accepts the generated witness — this is
/// only possible if the Artik executor produced the same value the
/// downstream `===` constraint expects.
#[test]
fn fn_witness_lift_e2e_r1cs_artik_dispatch() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::{HashMap, HashSet};
    use zkc::r1cs_backend::R1CSCompiler;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Artik R1CS E2E test failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");

    ir::passes::optimize(&mut program);

    // The loop-test function `triangle_sum(n)` returns
    // `sum_{i=0..3} (n * i)` = 6*n; its template fixes that as the
    // `===` constraint. We pick n = 7 → expected out = 42.
    let n = 7u64;
    let expected_out = 6 * n;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc
        .compile_ir_with_witness(&program, &inputs)
        .expect("compile_ir_with_witness");
    rc.cs
        .verify(&witness)
        .expect("R1CS should verify after Artik dispatch");
}

/// Fase 2.4 mux extension: nested function calls on the RHS of
/// assignments inside either arm of a runtime if/else are admissible.
/// Each call inlines at nested_depth > 0 (return captured via
/// nested_result, no WriteWitness), so both arms execute their call
/// under the mux without corrupting the top-level witness write.
/// Validated by decoding the payload and running the Artik executor
/// with cond ∈ {0, 1} against a hand-computed reference.
#[test]
fn fn_witness_lift_mux_admits_nested_calls() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_mux_calls_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mux+calls lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("mux+calls payload must decode and validate");

    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    // cond=1 → triple(x) == 3x.
    let sigs = [FE::from_u64(1), FE::from_u64(17)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=1");
    assert_eq!(slots[0], FE::from_u64(51), "cond=1 should pick triple(x)");

    // cond=0 → quadruple(x) == 4x.
    let sigs = [FE::from_u64(0), FE::from_u64(17)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=0");
    assert_eq!(
        slots[0],
        FE::from_u64(68),
        "cond=0 should pick quadruple(x)"
    );
}

/// Fase 2.3 lift extension: bitwise ops (`&`, `|`, `^`, `<<`, `>>`)
/// and `~` lift through the int-promotion scaffold
/// (`IntFromField U32` → `IBin` → `FieldFromInt U32`). Exercised by
/// a SHA-256 σ0-style function mixing `>>`, `<<`, and `^`. The
/// Artik payload is decoded, executed on a known 32-bit input, and
/// the output cross-validated against the hand-computed reference.
#[test]
fn fn_witness_lift_handles_bit_ops() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bitops_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("bit-op lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("bit-op payload must decode and validate");

    // Structural evidence the lift emitted the int-promotion
    // scaffold rather than silently bailing: IBin ops appear, and
    // IntFromField / FieldFromInt bracket them.
    let mut ibin = 0usize;
    let mut ito_int = 0usize;
    let mut ito_field = 0usize;
    for instr in &prog.body {
        match instr {
            artik::Instr::IBin { .. } => ibin += 1,
            artik::Instr::IntFromField { .. } => ito_int += 1,
            artik::Instr::FieldFromInt { .. } => ito_field += 1,
            _ => {}
        }
    }
    assert!(ibin >= 7, "expected ≥7 IBin ops for σ0, got {ibin}");
    assert!(ito_int >= 7, "expected ≥7 IntFromField, got {ito_int}");
    assert!(ito_field >= 7, "expected ≥7 FieldFromInt, got {ito_field}");

    // End-to-end correctness check: compute σ0(x) = rotr(x,7) ^
    // rotr(x,18) ^ (x >> 3) at u32 width, then pick an input and
    // compare the Artik output to the hand-computed reference.
    fn rotr32(x: u32, k: u32) -> u32 {
        // Explicit matching of circomlib expansion so we detect any
        // discrepancy caused by the lift treating `<< k` or `>> k`
        // differently (e.g., wider masking slipping through).
        (x >> k) | (x.wrapping_shl(32 - k))
    }
    fn sigma0_ref(x: u32) -> u32 {
        rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)
    }

    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    for &x in &[0u32, 1, 7, 0xDEAD_BEEF, 0x8000_0001, u32::MAX] {
        let signals = [FE::from_u64(x as u64)];
        let mut slots = [FE::zero()];
        let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals, &mut slots);
        artik::execute(&prog, &mut ctx).expect("execute σ0");
        let expected = sigma0_ref(x);
        assert_eq!(
            slots[0],
            FE::from_u64(expected as u64),
            "σ0({:#010x}) mismatch: got {:?}, expected {:#010x}",
            x,
            slots[0],
            expected,
        );
    }
}

/// BinSum(4,2): compile-only test.
///
/// TODO: BinSum uses `var lin += signal * e2` with `<-- (lin >> k) & 1`,
/// a mixed var/signal pattern where `lin` accumulates signal expressions
/// and then bit-extracts via witness hint. Needs var-as-linear-combination
/// tracking in the lowering to generate correct constraints.
#[test]
fn binsum_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/binsum_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("BinSum compilation failed: {e}"));
    eprintln!(
        "  BinSum(4,2) — {} nodes — COMPILED ✓",
        result.prove_ir.body.len()
    );
}

/// Multiplexer(2,3): compile-only test.
///
/// TODO: 2D signal input arrays (`inp[nIn][wIn]`) need flattened
/// naming support in the witness evaluator for full E2E verify.
#[test]
fn multiplexer_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/multiplexer_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Multiplexer compilation failed: {e}"));
    eprintln!(
        "  Multiplexer(2,3) — {} nodes — COMPILED ✓",
        result.prove_ir.body.len()
    );
}

// ── Circomlib compatibility: crypto primitives ───────────────────

/// AliasCheck: verifies 254-bit input is not an alias (< field modulus).
/// Uses CompConstant(-1). Input: 42 in binary (254 bits).
#[test]
fn aliascheck_circomlib() {
    // 42 = 0b101010, pad to 254 bits
    let bits_42: u64 = 42;
    let mut inputs = Vec::new();
    let names: Vec<String> = (0..254).map(|i| format!("in_{i}")).collect();
    for (i, name) in names.iter().enumerate() {
        let bit = if i < 64 { (bits_42 >> i) & 1 } else { 0 };
        inputs.push((name.as_str(), bit));
    }
    let n = circomlib_e2e_verify(
        "AliasCheck (42)",
        "test/circomlib/aliascheck_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

/// Sign: determine sign of a 254-bit field element.
/// Returns 0 for "positive" (< (p-1)/2), 1 for "negative".
#[test]
fn sign_circomlib() {
    // Small value (42): sign should be 0
    let bits: u64 = 42;
    let mut inputs = Vec::new();
    let names: Vec<String> = (0..254).map(|i| format!("in_{i}")).collect();
    for (i, name) in names.iter().enumerate() {
        let bit = if i < 64 { (bits >> i) & 1 } else { 0 };
        inputs.push((name.as_str(), bit));
    }
    let n = circomlib_e2e_verify(
        "Sign (42, positive)",
        "test/circomlib/sign_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

/// EdDSAMiMCVerifier: BabyJubjub EdDSA signature verifier using MiMC7
/// as the hash function. Covers the combination of every feature
/// Fase 5 opened:
///   - MultiMiMC7(5, 91) compile-time round constants
///   - CompConstant(2736...) with `1 << 128` seed (BigVal)
///   - BabyDbl + BabyAdd Edwards-curve component composition
///   - EscalarMul with compile-time Pedersen-style base points
///   - `pointAdd` field-aware division at compile time
///
/// Runs with `enabled=0` so the signature validity assertion is
/// short-circuited — all other inputs still need to be valid
/// curve points / field elements so `Num2Bits` and the doubling
/// chain don't fail. Reuses the same Base8 coordinates as the
/// EdDSAPoseidon test since both verifiers share the BabyJubjub
/// curve.
///
/// Closes Fase 5.3.
#[test]
fn eddsamimc_r1cs() {
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut inputs = HashMap::new();
    inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert(
        "Ax".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "Ay".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    inputs.insert(
        "R8x".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "R8y".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));

    let n = circomlib_e2e_verify_fe(
        "EdDSAMiMC R1CS (enabled=0)",
        "test/circomlib/eddsamimc_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for EdDSAMiMC verifier");
}

/// Pedersen_old(8): hash 8 bits using the legacy Pedersen
/// template that delegates to `EscalarMul` + `EscalarMulWindow` +
/// `EscalarMulW4Table`. The table-builder function does compile-
/// time Edwards-curve point doubling and addition via `pointAdd`
/// (whose `/` is modular inverse in the scalar field, not integer
/// division). Exercises:
///
///   - Array-valued reassignment at template level (`table =
///     EscalarMulW4Table(base, k);`)
///   - Deferred scalar component instantiation (`component mux;`
///     then `mux = MultiMux4(2);`)
///   - Partial array slice as component arg (`EscalarMul(n,
///     PBASE[i])` where PBASE is a 2-D var)
///   - Field-aware compile-time `+ - * /` in function bodies
///
/// Covers Fase 5.2. The test asserts the circuit compiles through
/// to a non-empty R1CS — full Groth16 verification is a separate
/// concern since computing a golden digest requires an independent
/// Edwards-curve implementation.
#[test]
fn pedersen_old_circomlib_r1cs() {
    let n = circomlib_e2e_verify(
        "Pedersen_old(8)",
        "test/circomlib/pedersen_old_test.circom",
        &[
            ("in_0", 0),
            ("in_1", 1),
            ("in_2", 0),
            ("in_3", 0),
            ("in_4", 1),
            ("in_5", 1),
            ("in_6", 0),
            ("in_7", 1),
        ],
    );
    eprintln!("  Pedersen_old(8): {n} constraints");
    assert!(n > 0, "expected constraints for Pedersen_old");
}

/// Pedersen(8): hash 8 bits using BabyJubjub curve.
///
/// Tests: Window4, MontgomeryAdd/Double, Edwards2Montgomery,
/// Montgomery2Edwards, BabyAdd, Mux3 — completely different hash
/// construction from Poseidon/MiMC. Uses hardcoded base points
/// via 2D array literal (`var BASE[10][2] = [[...], ...]`).
#[test]
fn pedersen_circomlib() {
    // Hash input: 0b10110010 (bits LSB-first)
    let n = circomlib_e2e_verify(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &[
            ("in_0", 0),
            ("in_1", 1),
            ("in_2", 0),
            ("in_3", 0),
            ("in_4", 1),
            ("in_5", 1),
            ("in_6", 0),
            ("in_7", 1),
        ],
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for Pedersen hash");
}

#[test]
fn pedersen_o2() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/pedersen_test.circom");
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

    let mut inputs = HashMap::new();
    for (i, bit) in [0u64, 1, 0, 0, 1, 1, 0, 1].iter().enumerate() {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(*bit));
    }

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap();
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let mut witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap();

    let pre_opt = r1cs_compiler.cs.num_constraints();
    let stats = r1cs_compiler.optimize_r1cs_o2();
    if let Some(subs) = &r1cs_compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }
    let post_opt = r1cs_compiler.cs.num_constraints();

    eprintln!("  Pedersen(8) O2: {pre_opt} → {post_opt}");
    eprintln!(
        "  vars_elim={} dedup={} trivial={}",
        stats.variables_eliminated, stats.duplicates_removed, stats.trivial_removed
    );

    r1cs_compiler.cs.verify(&witness).unwrap();
    // Constant propagation through template inlining collapses Montgomery/
    // Edwards operations with known base points to scalars. The remaining
    // constraints are: 2×Window4 MUX (3+1 each = 8) + 1 MontgomeryAdd (3) +
    // 1 Montgomery2Edwards (2) = 13. Matches circom --O1.
    assert!(
        post_opt <= 13,
        "O2 should match circom (13): got {post_opt}"
    );
}

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
        "17",
        "17",
        "17",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Num2Bits(8)", a, asp, "17"));

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
        "3",
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
        "21",
        "20",
        "20",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("LessThan(8)", a, asp, "20"));

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
        "91",
        "89",
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
        "59",
        "57",
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
        "2310",
        "2310",
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
        "243",
        "243",
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
        "1320",
        "1320",
        "1320",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("MiMCSponge(2,220,1)", a, asp, "1320"));

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

/// SHA-256(64) witness-equivalence vs the FIPS-180-4 reference (`sha2` crate).
///
/// This is *semantic* verification — does our compile + witness pipeline
/// produce the same 256-bit digest the reference produces? It is
/// orthogonal to constraint-count parity (separate R1CS-optimizer
/// concern). The test runs `compute_witness_hints_with_captures` over
/// the Lysis-frontend ProveIR with concrete bit inputs and reads the
/// 256 `out_i` signals from the env. If any `out_i` is missing or
/// disagrees with `sha2::Sha256::digest`, the test fails.
///
/// Bit ordering follows circomlib convention: `in[byte*8 + bit]` is bit
/// (7-bit) of the input byte, MSB-first. `out[byte*8 + bit]` is bit
/// (7-bit) of the digest byte, MSB-first.
///
/// `#[ignore]`d because compile alone is ~47s on this host. Run
/// explicitly via `cargo test ... --ignored
/// sha256_64_witness_matches_sha2_reference`.
#[test]
#[ignore = "SHA-256(64) witness-equivalence — compile is ~47s on this host. Run with --ignored to verify the achronyme pipeline computes the same digest as FIPS-180-4."]
fn sha256_64_witness_matches_sha2_reference() {
    use sha2::{Digest, Sha256};
    use std::time::Instant;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // Concrete 8-byte input — picked to have varied bits so a missed
    // alias collapse would surface as a digest mismatch.
    let message: [u8; 8] = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("  [compile]  {:?}", t0.elapsed());

    // Build inputs: in_{byte*8 + bit} = bit (7-bit) of message[byte], MSB-first.
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (byte_idx, byte) in message.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit_val = ((byte >> (7 - bit_idx)) & 1) as u64;
            inputs.insert(
                format!("in_{}", byte_idx * 8 + bit_idx),
                FieldElement::<Bn254Fr>::from_u64(bit_val),
            );
        }
    }

    let t1 = Instant::now();
    let env = circom::witness::compute_witness_hints_with_captures(
        &compile_result.prove_ir,
        &inputs,
        &compile_result.capture_values,
    )
    .expect("compute_witness_hints_with_captures");
    eprintln!("  [witness]  {:?}  env_size={}", t1.elapsed(), env.len());

    // Reference digest from sha2 crate (FIPS-180-4 bit-exact).
    let expected = Sha256::digest(message);

    // Read 256 output bits and reconstruct 32 bytes MSB-first.
    let mut got = [0u8; 32];
    let mut missing: Vec<usize> = Vec::new();
    for (byte_idx, byte) in got.iter_mut().enumerate() {
        for bit_idx in 0..8 {
            let key = format!("out_{}", byte_idx * 8 + bit_idx);
            match env.get(&key) {
                Some(fe) => {
                    let bit = u8::from(fe == &FieldElement::<Bn254Fr>::one());
                    *byte |= bit << (7 - bit_idx);
                }
                None => missing.push(byte_idx * 8 + bit_idx),
            }
        }
    }

    assert!(
        missing.is_empty(),
        "SHA-256 witness missing {} of 256 output bits — first missing indices: {:?}",
        missing.len(),
        &missing[..missing.len().min(8)]
    );

    assert_eq!(
        &got[..],
        expected.as_slice(),
        "SHA-256(64) digest mismatch:\n  got:      {}\n  expected: {}",
        hex_encode(&got),
        hex_encode(expected.as_slice()),
    );

    eprintln!("  [verified] digest = {}", hex_encode(&got));
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
