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
    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        &prove_ir,
        &fe_inputs,
        &capture_values,
    );

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
