use super::*;

/// Cross-validates the multi-fragment witness output of
/// `secp256k1_addunequal_func(64, 4, ...)` against a reference vector
/// computed by circom 2.2.3 + snarkjs. Inputs are the secp256k1
/// generator `G` and `2G` (decomposed into 64-bit little-endian
/// limbs); the expected sum `3G` matches both the mathematical
/// definition (G + 2G on secp256k1) and the canonical limb output of
/// the official circomlib function. Pinning these values catches any
/// silent mis-wiring in the decomposition — swapped argument order
/// in `prod_mod_p` / `long_sub_mod_p`, off-by-one in the row-major
/// flattening of the 2D return, or a `CircuitExpr::Var(name)` whose
/// name no longer matches a fragment's `output_bindings`.
#[test]
fn fn_witness_decompose_secp256k1_addunequal_values() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_decompose_secp256k1_addunequal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("secp256k1_addunequal decomposition failed to compile: {e}"));

    // secp256k1 generator G and 2G, 64-bit little-endian limbs.
    let inputs_u64: [(&str, u64); 16] = [
        ("x1_0", 0x59F2_815B_16F8_1798),
        ("x1_1", 0x029B_FCDB_2DCE_28D9),
        ("x1_2", 0x55A0_6295_CE87_0B07),
        ("x1_3", 0x79BE_667E_F9DC_BBAC),
        ("y1_0", 0x9C47_D08F_FB10_D4B8),
        ("y1_1", 0xFD17_B448_A685_5419),
        ("y1_2", 0x5DA4_FBFC_0E11_08A8),
        ("y1_3", 0x483A_DA77_26A3_C465),
        ("x2_0", 0xABAC_09B9_5C70_9EE5),
        ("x2_1", 0x5C77_8E4B_8CEF_3CA7),
        ("x2_2", 0x3045_406E_95C0_7CD8),
        ("x2_3", 0xC604_7F94_41ED_7D6D),
        ("y2_0", 0x2364_31A9_50CF_E52A),
        ("y2_1", 0xF7F6_3265_3266_D0E1),
        ("y2_2", 0xA3C5_8419_466C_EAEE),
        ("y2_3", 0x1AE1_68FE_A63D_C339),
    ];
    let inputs: HashMap<String, FieldElement<Bn254Fr>> = inputs_u64
        .iter()
        .map(|(n, v)| (n.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    // Reference 3G = G + 2G, captured from circom 2.2.3 + snarkjs run
    // on the same fixture; matches the modular arithmetic on
    // secp256k1's prime field. Order is little-endian limbs.
    let expected_outx: [u64; 4] = [
        0x8601_F113_BCE0_36F9,
        0xB531_C845_836F_99B0,
        0x4934_4F85_F89D_5229,
        0xF930_8A01_9258_C310,
    ];
    let expected_outy: [u64; 4] = [
        0x6CB9_FD75_84B8_E672,
        0x6500_A999_34C2_231B,
        0x0FE3_37E6_2A37_F356,
        0x388F_7B0F_632D_E814,
    ];

    for (i, expected) in expected_outx.iter().enumerate() {
        let key = format!("outx_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        let want = FieldElement::<Bn254Fr>::from_u64(*expected);
        assert_eq!(
            *actual, want,
            "outx[{i}] mismatch: got {actual:?}, want {want:?}"
        );
    }
    for (i, expected) in expected_outy.iter().enumerate() {
        let key = format!("outy_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        let want = FieldElement::<Bn254Fr>::from_u64(*expected);
        assert_eq!(
            *actual, want,
            "outy[{i}] mismatch: got {actual:?}, want {want:?}"
        );
    }
}
