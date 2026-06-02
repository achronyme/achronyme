use super::*;

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

/// SHA-256(64) full R1CS-verify-with-witness regression.
///
/// Companion to [`sha256_64_witness_matches_sha2_reference`] and
/// [`sha256_64_lysis_hard_gate`]. Those two cover compile budget +
/// witness-vs-FIPS bit-equivalence respectively, but neither runs the
/// IR's `AssertEq` chain against a populated witness — the hard-gate
/// stops at constraint counting and the witness-equivalence test reads
/// the bit outputs directly out of `compute_witness_hints` (Lysis VM
/// hints) without re-checking that those values satisfy every R1CS
/// constraint produced from the compiled IR.
///
/// That coverage shape can hide regressions where the IR emits
/// constraints that count correctly and produce a satisfying-looking
/// witness on the hint side, yet collapse multiple iter-distinct
/// `AssertEq`s onto a single shared RHS so witness eval rejects the
/// program. This test plugs the gap by running
/// `compile_ir_with_witness` + `cs.verify` on a fixed 8-byte input —
/// any future spill / dataflow regression that produces witness-
/// incompatible constraints surfaces here even when the constraint
/// count stays within the hard-gate's tolerance.
///
/// `#[ignore]`d because the SHA-256(64) compile path is ~13 s on this
/// host. Run with `--ignored sha256_64_r1cs_verify_with_witness`
/// before pushing changes that touch the Walker, instantiate, or
/// witness-hint paths.
#[test]
#[ignore = "SHA-256(64) full R1CS-verify-with-witness regression — compile is ~13s on this host. Run with --ignored before pushing changes that touch the Lysis walker, instantiate, witness, or R1CS pipelines."]
fn sha256_64_r1cs_verify_with_witness() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let message: [u8; 8] = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    for (byte_idx, byte) in message.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit_val = u64::from((byte >> (7 - bit_idx)) & 1);
            inputs.insert(
                format!("in_{}", byte_idx * 8 + bit_idx),
                FieldElement::<Bn254Fr>::from_u64(bit_val),
            );
        }
    }

    let n = circomlib_e2e_verify_fe("SHA-256(64)", "test/circomlib/sha256_test.circom", &inputs);
    assert!(n > 0, "SHA-256(64) must produce non-empty constraint set");
}

/// Sha256_2: 2-input SHA-256 variant (a, b ∈ [0, 2^216)).
///
/// Distinct shape from the parametric `Sha256(N)` already covered by
/// `sha256_64_*` tests:
///   - Hardcoded length encoding via raw `inp[i] <== const` (vs. a
///     parametric padding loop).
///   - Two `Num2Bits(216)` decompositions (216-bit inputs are an
///     unusual size — most templates use 32, 64, or 254).
///   - `Sha256compression` invoked directly without the `Sha256(N)`
///     wrapper.
///
/// Smoke test: compile + instantiate + R1CS-build + verify on small
/// constants. Surfaces any frame-overflow, instantiation amplification,
/// or witness-vs-IR drift specific to this template shape.
#[test]
#[ignore = "Sha256_2 compile + instantiate + R1CS — heavy (single Sha256compression dominates). Run with --ignored sha256_2_real_circomlib."]
fn sha256_2_real_circomlib() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(2));

    let n = circomlib_e2e_optimized("Sha256_2", "test/circomlib/sha256_2_test.circom", &inputs);
    assert!(n > 0, "Sha256_2 must produce non-empty constraint set");
}
