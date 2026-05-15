//! Isolated repro of the if/else whole-array-rebind merge glue.
//! Mirrors `long_sub_mod_p`'s shape at minimal size so a failure
//! points at the slot-merge glue, not a 33k-instruction fragment.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use memory::field::Bn254Fr;
use memory::FieldElement;

fn run(sel: u64, expected: [u64; 4]) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circom/artik_if_else_array_rebind_probe.circom");
    let lib_dirs: Vec<PathBuf> = vec![];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("probe failed to compile: {e}"));

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("sel".to_string(), FieldElement::<Bn254Fr>::from_u64(sel));
    for i in 0..4 {
        inputs.insert(
            format!("x_{i}"),
            FieldElement::<Bn254Fr>::from_u64(10 + i as u64),
        );
        inputs.insert(
            format!("y_{i}"),
            FieldElement::<Bn254Fr>::from_u64(20 + i as u64),
        );
    }

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed (sel={sel}): {e}"));

    for (i, want) in expected.iter().enumerate() {
        let key = format!("o_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        assert_eq!(
            *actual,
            FieldElement::<Bn254Fr>::from_u64(*want),
            "o[{i}] must reflect the arm whose guard fires at runtime (sel={sel})"
        );
    }
}

#[test]
fn if_else_array_rebind_selects_then_arm() {
    // sel != 0 → t = idcopy(x) → o == x == [10,11,12,13]
    run(1, [10, 11, 12, 13]);
}

#[test]
fn if_else_array_rebind_selects_else_arm() {
    // sel == 0 → t = idcopy(y) → o == y == [20,21,22,23]
    run(0, [20, 21, 22, 23]);
}
