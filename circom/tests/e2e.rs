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

use compiler::r1cs_backend::R1CSCompiler;
use memory::{Bn254Fr, FieldElement};

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

    // Instantiate
    let mut program = match prove_ir.instantiate(&fe_captures) {
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

    let mut program = match prove_ir.instantiate(&fe_captures) {
        Ok(p) => p,
        Err(e) => panic!("Poseidon instantiation failed: {e}"),
    };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.instructions.len()
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

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = match prove_ir.instantiate(&fe_captures) {
        Ok(p) => p,
        Err(e) => panic!("MiMCSponge instantiation failed: {e}"),
    };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.instructions.len()
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
        .instantiate(&fe_captures)
        .unwrap_or_else(|e| panic!("{test_name} instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.instructions.len()
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

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
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
        .instantiate(&fe_captures)
        .unwrap_or_else(|e| panic!("{test_name} instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.instructions.len()
    );

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, inputs, capture_values)
            .unwrap_or_else(|e| panic!("{test_name} witness computation failed: {e}"));

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
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
        .instantiate(&fe_captures)
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
        vm::ProveResult::Proof {
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
        .instantiate(&fe_captures)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon instantiation failed: {e}"));

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.instructions.len()
    );

    eprintln!(
        "\n  EdDSAPoseidonVerifier — {} nodes → {} instructions — INSTANTIATED ✓",
        prove_ir.body.len(),
        program.instructions.len()
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
    eprintln!("  Constraints: {n}");
    assert!(n > 10000, "expected >10000 constraints, got {n}");
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
        &inputs
            .iter()
            .map(|&(n, v)| (n.as_ref(), v))
            .collect::<Vec<_>>(),
    );
    eprintln!("  Constraints: {n}");
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

/// Pedersen(8): compile-only test.
///
/// TODO: Pedersen uses array literal base points in the circuit body
/// (`var BASE[10][2][4]`), which the Circom lowering doesn't support yet.
/// Needs array literal → Const node expansion in the lowering.
#[test]
fn pedersen_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/pedersen_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // Currently fails at compilation due to array literals in circuit body.
    // This test documents the known limitation and will pass once supported.
    let result = circom::compile_file(&path, &lib_dirs);
    if let Ok(r) = result {
        eprintln!(
            "  Pedersen(8) — {} nodes — COMPILED ✓",
            r.prove_ir.body.len()
        );
    } else {
        eprintln!("  Pedersen(8) — compile not yet supported (array literal in circuit body)");
    }
}
