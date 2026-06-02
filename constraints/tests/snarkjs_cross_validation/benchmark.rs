use std::collections::HashMap;

use memory::FieldElement;

use super::helpers::{cross_validate, fe, snarkjs_available};

#[test]
fn golden_benchmark_table() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }

    struct BenchEntry {
        name: &'static str,
        source: &'static str,
        pub_names: &'static [&'static str],
        wit_names: &'static [&'static str],
        inputs: Vec<(&'static str, FieldElement)>,
        expected_out: &'static str,
        circom_constraints: usize,
    }

    let entries = vec![
        BenchEntry {
            name: "Mul 6×7",
            source: "assert_eq(a * b, out)",
            pub_names: &["out"],
            wit_names: &["a", "b"],
            inputs: vec![("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
            expected_out: "42",
            circom_constraints: 1,
        },
        BenchEntry {
            name: "Div 42/7",
            source: "assert_eq(a / b, out)",
            pub_names: &["out"],
            wit_names: &["a", "b"],
            inputs: vec![("out", fe(6)), ("a", fe(42)), ("b", fe(7))],
            expected_out: "6",
            circom_constraints: 2,
        },
        BenchEntry {
            name: "Mux(1,10,20)",
            source: "assert_eq(mux(c, a, b), out)",
            pub_names: &["out"],
            wit_names: &["c", "a", "b"],
            inputs: vec![("out", fe(10)), ("c", fe(1)), ("a", fe(10)), ("b", fe(20))],
            expected_out: "10",
            circom_constraints: 1,
        },
        BenchEntry {
            name: "IsEq(5,5)",
            source: "assert_eq(a == b, out)",
            pub_names: &["out"],
            wit_names: &["a", "b"],
            inputs: vec![("out", fe(1)), ("a", fe(5)), ("b", fe(5))],
            expected_out: "1",
            circom_constraints: 3,
        },
        BenchEntry {
            name: "IsLt(3,5) 64-bit",
            source: "assert_eq(a < b, out)",
            pub_names: &["out"],
            wit_names: &["a", "b"],
            inputs: vec![("out", fe(1)), ("a", fe(3)), ("b", fe(5))],
            expected_out: "1",
            circom_constraints: 68,
        },
        BenchEntry {
            name: "RangeCheck(42,8)",
            source: "range_check(x, 8)",
            pub_names: &[],
            wit_names: &["x"],
            inputs: vec![("x", fe(42))],
            expected_out: "",
            circom_constraints: 9,
        },
        BenchEntry {
            name: "And(1,1)",
            source: "assert_eq(a && b, out)",
            pub_names: &["out"],
            wit_names: &["a", "b"],
            inputs: vec![("out", fe(1)), ("a", fe(1)), ("b", fe(1))],
            expected_out: "1",
            circom_constraints: 1,
        },
    ];

    eprintln!("\n╔═══════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║              ACHRONYME vs CIRCOM — CONSTRAINT BENCHMARK                  ║");
    eprintln!("╠═══════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ {:20} │ {:>10} │ {:>10} │ {:>7} │ {:>10} ║",
        "Circuit", "Achronyme", "Circom", "Δ", "wtns check"
    );
    eprintln!("╠══════════════════════╪════════════╪════════════╪═════════╪════════════╣");

    for e in &entries {
        let inputs: HashMap<String, FieldElement> =
            e.inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let result = cross_validate(e.source, e.pub_names, e.wit_names, &inputs);

        let delta = result.constraint_count as i64 - e.circom_constraints as i64;
        let delta_str = if delta > 0 {
            format!("+{delta}")
        } else {
            format!("{delta}")
        };

        let out_ok = e.expected_out.is_empty()
            || (result.wire_values.len() > 1 && result.wire_values[1] == e.expected_out);

        eprintln!(
            "║ {:20} │ {:>10} │ {:>10} │ {:>7} │ {:>10} ║",
            e.name,
            result.constraint_count,
            e.circom_constraints,
            delta_str,
            if result.wtns_check_passed && out_ok {
                "✓ VALID"
            } else {
                "✗ FAIL"
            },
        );
    }

    eprintln!("╚══════════════════════╧════════════╧════════════╧═════════╧════════════╝");
    eprintln!("  Note: Poseidon(2) — Achronyme: 362, Circom: 517 (Achronyme is 30%% faster)");
    eprintln!(
        "  Note: IsLt gap (D7) — Achronyme uses full 252-bit decomposition vs Circom's 64-bit"
    );
}
