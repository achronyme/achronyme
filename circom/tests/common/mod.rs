#![allow(dead_code)]
//! Shared helpers for the circom E2E test binaries.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// ── Test result tracking ─────────────────────────────────────────

#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub parse: bool,
    pub lower: bool,
    pub r1cs: bool,
    pub constraints: Option<usize>,
    pub error: Option<String>,
}

// ── TOML input loading ───────────────────────────────────────────

pub fn load_inputs(toml_path: &Path) -> (HashMap<String, u64>, Option<usize>) {
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

pub fn run_circom_test(circom_path: &Path) -> TestResult {
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

pub fn find_circom_tests() -> Vec<PathBuf> {
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

// ── Shared E2E helper ──────────────────────────────────────────

/// Compile a circomlib test file → ProveIR → instantiate → R1CS → verify.
///
/// Returns the number of constraints on success.
pub fn circomlib_e2e_verify(test_name: &str, circom_file: &str, inputs: &[(&str, u64)]) -> usize {
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

/// Full E2E verify with FieldElement inputs (supports large field values).
pub fn circomlib_e2e_verify_fe(
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
pub fn circomlib_e2e_optimized(
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

/// Shared body of the `sha256_{8,16,32,64}_lysis_hard_gate` tests.
/// Each variant pins a specific `Sha256(nbits)` circuit against
/// circom 2.2.3 `--O2` constraint counts with a wall-clock budget;
/// the per-variant `#[test]` wrappers below select the fixture and
/// tolerance.
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
pub fn run_sha256_lysis_hard_gate(
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

/// Histogram printer for [`sha256_64_constraint_breakdown`].
///
/// Two bucket layers:
///   - **category** -- `is_linear`-style coarse classification (linear
///     constraints with A or B constant, vs genuinely quadratic ones
///     bucketed by term-count signature).
///   - **(|A|,|B|,|C|)** -- fine-grained term-count distribution; surfaces
///     things like the bool-check shape `(1,2,0)` or bit-decomposition
///     shape `(1,N,0)` directly.
pub fn print_constraint_histogram<'a, F, I>(constraints: I)
where
    F: memory::FieldBackend + 'a,
    I: IntoIterator<Item = &'a constraints::r1cs::Constraint<F>>,
{
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
pub fn classify_constraint<F: memory::FieldBackend>(
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

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
