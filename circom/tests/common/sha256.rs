use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

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
pub fn print_constraint_histogram<F: memory::FieldBackend>(
    constraints: &[constraints::r1cs::Constraint<F>],
) {
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
    items.sort_by_key(|x| std::cmp::Reverse(x.1));
    for (label, n) in items {
        eprintln!("    {label:38} = {n}");
    }

    eprintln!("\n  by (|A|,|B|,|C|), top 15 buckets:");
    let mut items: Vec<_> = by_size.into_iter().collect();
    items.sort_by_key(|x| std::cmp::Reverse(x.1));
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
