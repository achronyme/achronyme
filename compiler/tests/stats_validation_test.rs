/// Validates that the static CircuitStats cost model matches actual R1CS
/// constraint counts from the R1CSCompiler backend.
use compiler::r1cs_backend::R1CSCompiler;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::stats::CircuitStats;
use ir::IrLowering;

fn compare_stats(source: &str, public: &[&str], witness: &[&str]) {
    let mut program = IrLowering::lower_circuit(source, public, witness).unwrap();
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);

    // Static cost model
    let stats = CircuitStats::from_program(&program, &proven, None);

    // Actual R1CS compilation
    let mut r1cs = R1CSCompiler::new();
    r1cs.set_proven_boolean(proven);
    r1cs.compile_ir(&program).unwrap();
    let actual = r1cs.cs.num_constraints();

    assert_eq!(
        stats.total_constraints, actual,
        "Static estimate ({}) != actual R1CS count ({}) for: {source}",
        stats.total_constraints, actual
    );
}

#[test]
fn simple_mul() {
    compare_stats("assert_eq(x * y, z)", &["z"], &["x", "y"]);
}

#[test]
fn double_mul() {
    compare_stats("assert_eq(x * y * z, w)", &["w"], &["x", "y", "z"]);
}

#[test]
fn addition_is_free() {
    compare_stats("assert_eq(x + y, z)", &["z"], &["x", "y"]);
}

#[test]
fn subtraction_is_free() {
    compare_stats("assert_eq(x - y, z)", &["z"], &["x", "y"]);
}

#[test]
fn poseidon_hash() {
    compare_stats("assert_eq(poseidon(a, b), h)", &["h"], &["a", "b"]);
}

#[test]
fn range_check_8() {
    compare_stats("range_check(x, 8)", &[], &["x"]);
}

#[test]
fn range_check_64() {
    compare_stats("range_check(x, 64)", &[], &["x"]);
}

#[test]
fn is_eq() {
    compare_stats(
        "let r = x == y\nassert_eq(r, expected)",
        &["expected"],
        &["x", "y"],
    );
}

#[test]
fn is_neq() {
    compare_stats(
        "let r = x != y\nassert_eq(r, expected)",
        &["expected"],
        &["x", "y"],
    );
}

#[test]
fn is_lt_bounded() {
    compare_stats(
        "range_check(x, 8)\nrange_check(y, 8)\nlet r = x < y\nassert_eq(r, expected)",
        &["expected"],
        &["x", "y"],
    );
}

#[test]
fn is_lt_unbounded() {
    compare_stats(
        "let r = x < y\nassert_eq(r, expected)",
        &["expected"],
        &["x", "y"],
    );
}

#[test]
fn mixed_circuit() {
    compare_stats(
        "let prod = x * y\nassert_eq(prod, z)\nlet h = poseidon(x, y)\nassert_eq(h, expected)",
        &["z", "expected"],
        &["x", "y"],
    );
}

#[test]
fn range_check_then_compare() {
    compare_stats(
        "range_check(a, 16)\nrange_check(b, 16)\nassert(a < b)",
        &[],
        &["a", "b"],
    );
}

#[test]
fn boolean_and() {
    compare_stats(
        "range_check(a, 1)\nrange_check(b, 1)\nlet r = a && b\nassert_eq(r, expected)",
        &["expected"],
        &["a", "b"],
    );
}

#[test]
fn boolean_or() {
    compare_stats(
        "range_check(a, 1)\nrange_check(b, 1)\nlet r = a || b\nassert_eq(r, expected)",
        &["expected"],
        &["a", "b"],
    );
}

#[test]
fn mux_selection() {
    compare_stats(
        "range_check(c, 1)\nlet r = if c { x } else { y }\nassert_eq(r, expected)",
        &["expected"],
        &["c", "x", "y"],
    );
}
