//! Native-vs-interpreted differential for intrinsic-annotated witness
//! programs.
//!
//! Compiles real circomlib-derived fixtures, extracts the lifted Artik
//! programs, and executes each twice over randomized in-range inputs:
//! once as compiled (annotated callees run natively) and once with the
//! annotations stripped (everything interpreted). The witness outputs
//! must be bit-identical — that is the soundness contract of the
//! native intrinsic path.

use std::path::{Path, PathBuf};

use ir_forge::types::{CircuitExpr, CircuitNode};
use memory::{Bn254Fr, FieldElement, FieldFamily};

type Fe = FieldElement<Bn254Fr>;

fn fixture(name: &str) -> (PathBuf, Vec<PathBuf>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    (
        manifest_dir.join(format!("test/circomlib/{name}")),
        vec![manifest_dir.join("test/circomlib")],
    )
}

/// Extract every lifted witness program from a compiled fixture:
/// `(program_bytes, input_signal_exprs, n_outputs)`.
fn witness_calls(body: &[CircuitNode]) -> Vec<(Vec<u8>, Vec<CircuitExpr>, usize)> {
    let mut out = Vec::new();
    for node in body {
        match node {
            CircuitNode::WitnessCall {
                output_bindings,
                input_signals,
                program_bytes,
                ..
            } => out.push((
                program_bytes.clone(),
                input_signals.clone(),
                output_bindings.len(),
            )),
            CircuitNode::For { body, .. } => out.extend(witness_calls(body)),
            CircuitNode::If {
                then_body,
                else_body,
                ..
            } => {
                out.extend(witness_calls(then_body));
                out.extend(witness_calls(else_body));
            }
            _ => {}
        }
    }
    out
}

/// Deterministic xorshift64* — reproducible fuzz vectors.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Run one program twice — annotated (native) and stripped
/// (interpreted) — and compare every witness slot.
fn assert_native_matches_interpreted(
    bytes: &[u8],
    input_signals: &[CircuitExpr],
    n_outputs: usize,
    rng: &mut Rng,
    rounds: usize,
) {
    let prog = artik::bytecode::decode(bytes, Some(FieldFamily::BnLike256)).expect("decode");
    assert!(
        !prog.intrinsics.is_empty(),
        "fixture program must carry intrinsic annotations for this differential to bite"
    );
    let mut stripped = prog.clone();
    stripped.intrinsics.clear();
    let stripped_bytes = artik::bytecode::encode(&stripped);

    for _ in 0..rounds {
        // Constant argument expressions keep their compiled value
        // (e.g. the n / k parameters); runtime signals get random
        // 31-bit digits, nonzero so divisor leading digits stay valid.
        let signals: Vec<Fe> = input_signals
            .iter()
            .map(|expr| match expr {
                CircuitExpr::Const(c) => c.to_field::<Bn254Fr>().expect("const in range"),
                _ => Fe::from_u64((rng.next() & 0x7FFF_FFFE) + 1),
            })
            .collect();

        let mut native_slots = vec![Fe::zero(); n_outputs];
        let mut interp_slots = vec![Fe::zero(); n_outputs];
        artik::execute_into(bytes, &signals, &mut native_slots).expect("native-path execute");
        artik::execute_into(&stripped_bytes, &signals, &mut interp_slots)
            .expect("interpreted execute");
        assert_eq!(
            native_slots, interp_slots,
            "annotated and interpreted executions must agree on every witness slot"
        );
    }
}

/// mod_inv at n=32, k=2: the lifted program's callees (mod_exp, prod,
/// long_div and helpers) carry annotations; the differential drives
/// the full Fermat loop through the native path.
#[test]
fn modinv_fixture_native_matches_interpreted() {
    let (path, lib_dirs) = fixture("fn_witness_lift_bigint_mod_inv_test.circom");
    let result = circom::compile_file(&path, &lib_dirs).expect("compile");
    let calls = witness_calls(&result.prove_ir.body);
    assert!(!calls.is_empty(), "fixture must lift a witness program");
    let mut rng = Rng(0xA1B2C3D4E5F60718);
    for (bytes, inputs, n_out) in &calls {
        assert_native_matches_interpreted(bytes, inputs, *n_out, &mut rng, 12);
    }
}

/// secp256k1 point addition: mod_inv itself is a callee here, so this
/// covers the ModInv annotation (and its full dependency closure) at
/// the production shape n=64, k=4.
#[test]
fn secp256k1_addunequal_fixture_native_matches_interpreted() {
    let (path, lib_dirs) = fixture("fn_witness_decompose_secp256k1_addunequal_test.circom");
    let result = circom::compile_file(&path, &lib_dirs).expect("compile");
    let calls = witness_calls(&result.prove_ir.body);
    assert!(!calls.is_empty(), "fixture must lift a witness program");
    let mut rng = Rng(0x1357_9BDF_2468_ACE0);
    for (bytes, inputs, n_out) in &calls {
        assert_native_matches_interpreted(bytes, inputs, *n_out, &mut rng, 6);
    }
}
