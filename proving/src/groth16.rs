//! Generic Groth16 proof generation using ark-groth16.
//!
//! This module is parameterized over `E: Pairing` so it works with any
//! arkworks-compatible curve (BN254, BLS12-381, etc.). Curve-specific
//! JSON serialization lives in dedicated modules (e.g., `groth16_bn254`).

use std::path::Path;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable as ArkVariable,
};
use ark_snark::SNARK;
use rand::rngs::OsRng;

use constraints::r1cs::ConstraintSystem;
use memory::{Bn254Fr, FieldBackend, FieldElement};

mod cache;
pub use cache::cache_key;
use cache::{load_cached_keys, load_cached_vk, save_cached_keys, save_cached_vk};

// ============================================================================
// Field conversion
// ============================================================================

/// Convert an Achronyme `FieldElement<B>` to an ark scalar field element.
///
/// When converting to a different field (e.g. BN254 → BLS12-381), negative
/// values like `-1` are stored as `p_source - 1`. A naïve byte
/// reinterpretation would give the wrong value in the target field.
///
/// This function detects "negative" source values (canonical > p/2) and
/// maps them to the correct negation in the target field:
///   source < p/2  →  target = source  (positive, same integer)
///   source >= p/2 →  target = -(p_source - source)  (negative, re-negated)
///
/// The implementation is constant-time in `fe`'s canonical value: both
/// branches are always computed and the result is selected via field
/// arithmetic. This matters when a server proves on behalf of remote
/// callers (see `ach-server` / `/api/prove`), where a timing leak on the
/// sign of witness limbs would be observable.
pub fn fe_to_ark<B: FieldBackend, AF: PrimeField>(fe: &FieldElement<B>) -> AF {
    let bytes = fe.to_le_bytes();
    let canonical = fe.to_canonical();
    let half_mod = source_half_modulus::<B>();

    // Constant-time: 1 iff canonical > floor(p/2), else 0.
    let is_neg = ct_gt_u64x4(&canonical, &half_mod);

    // Always compute both branches so the control flow is independent of
    // the secret sign bit.
    let neg = fe.neg();
    let neg_bytes = neg.to_le_bytes();
    let pos_case = AF::from_le_bytes_mod_order(&bytes);
    let neg_case = -AF::from_le_bytes_mod_order(&neg_bytes);

    // Arithmetic select: result = is_neg * neg_case + (1 - is_neg) * pos_case.
    // Field multiplications are constant-time in arkworks, so no branch on
    // `is_neg` ever reaches the generated code.
    let sign = AF::from(is_neg);
    let one_minus_sign = AF::ONE - sign;
    neg_case * sign + pos_case * one_minus_sign
}

/// Constant-time `a > b` for 256-bit little-endian limb arrays.
///
/// Returns `1u64` if `a > b`, else `0u64`. Uses `overflowing_sub` (a
/// constant-time u64 primitive on every target arkworks supports) and
/// accumulates a borrow across limbs without branching on inputs.
#[inline]
fn ct_gt_u64x4(a: &[u64; 4], b: &[u64; 4]) -> u64 {
    // a > b  iff  (b - a) underflows.
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = b[i].overflowing_sub(a[i]);
        let (_, b2) = d1.overflowing_sub(borrow);
        borrow = (b1 as u64) | (b2 as u64);
    }
    borrow
}

/// Compute floor(p/2) for the source field `B` as 4 little-endian u64 limbs.
fn source_half_modulus<B: FieldBackend>() -> [u64; 4] {
    let mod_bytes = B::modulus_le_bytes();
    let m = [
        u64::from_le_bytes(mod_bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(mod_bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(mod_bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(mod_bytes[24..32].try_into().unwrap()),
    ];
    [
        (m[0] >> 1) | ((m[1] & 1) << 63),
        (m[1] >> 1) | ((m[2] & 1) << 63),
        (m[2] >> 1) | ((m[3] & 1) << 63),
        m[3] >> 1,
    ]
}

/// Convert an ark field element to a decimal string.
pub fn fr_to_decimal<F: PrimeField>(f: &F) -> String {
    f.into_bigint().to_string()
}

// ============================================================================
// Circuit adapter (generic)
// ============================================================================

/// Wraps an Achronyme `ConstraintSystem` so ark-groth16 can synthesize it.
#[derive(Clone)]
pub struct AchronymeCircuit<B: FieldBackend = Bn254Fr> {
    pub cs: ConstraintSystem<B>,
    pub witness: Option<Vec<FieldElement<B>>>,
}

impl<B: FieldBackend, AF: PrimeField> ConstraintSynthesizer<AF> for AchronymeCircuit<B> {
    fn generate_constraints(self, ark_cs: ConstraintSystemRef<AF>) -> Result<(), SynthesisError> {
        let num_pub = self.cs.num_pub_inputs();
        let num_vars = self.cs.num_variables();

        let mut var_map: Vec<ArkVariable> = Vec::with_capacity(num_vars);

        // Index 0 → ark's built-in ONE
        var_map.push(ArkVariable::One);

        // Public inputs: indices 1..=num_pub
        for i in 1..=num_pub {
            let val = self
                .witness
                .as_ref()
                .map(|w| fe_to_ark::<B, AF>(&w[i]))
                .unwrap_or_default();
            let v = ark_cs.new_input_variable(|| Ok(val))?;
            var_map.push(v);
        }

        // Witness variables: indices num_pub+1..num_vars
        for i in (num_pub + 1)..num_vars {
            let val = self
                .witness
                .as_ref()
                .map(|w| fe_to_ark::<B, AF>(&w[i]))
                .unwrap_or_default();
            let v = ark_cs.new_witness_variable(|| Ok(val))?;
            var_map.push(v);
        }

        // Convert each (A, B, C) constraint
        for constraint in self.cs.constraints() {
            let a = convert_lc::<B, AF>(&constraint.a, &var_map);
            let b = convert_lc::<B, AF>(&constraint.b, &var_map);
            let c = convert_lc::<B, AF>(&constraint.c, &var_map);
            ark_cs.enforce_constraint(a, b, c)?;
        }

        Ok(())
    }
}

/// Convert an Achronyme `LinearCombination` to an ark `LinearCombination`.
fn convert_lc<B: FieldBackend, AF: PrimeField>(
    lc: &constraints::r1cs::LinearCombination<B>,
    var_map: &[ArkVariable],
) -> ark_relations::r1cs::LinearCombination<AF> {
    let mut ark_lc = ark_relations::r1cs::LinearCombination::zero();
    for (var, coeff) in lc.terms() {
        ark_lc += (fe_to_ark::<B, AF>(coeff), var_map[var.index()]);
    }
    ark_lc
}

// ============================================================================
// Proof generation (generic over Pairing)
// ============================================================================

/// Run trusted setup (or load cached keys).
///
/// `curve_tag` is included in the cache key to prevent collisions between
/// the same circuit compiled for different curves.
///
/// The circuit handed to ark is the wire-compacted system (see
/// `ConstraintSystem::compact_referenced`): every proving-key query
/// vector is sized by the variable count, so each unreferenced wire
/// would cost several identity group elements and a zero QAP column.
/// The cache key is computed over the compacted system; callers that
/// later prove via [`generate_proof_raw`] hit the same entry.
pub fn setup_keys<B: FieldBackend, E: Pairing>(
    cs: &ConstraintSystem<B>,
    cache_dir: &Path,
    curve_tag: &str,
) -> Result<(ark_groth16::ProvingKey<E>, ark_groth16::VerifyingKey<E>), String> {
    let (compacted, _gather) = cs.compact_referenced();
    setup_keys_compacted(compacted, cache_dir, curve_tag)
}

/// [`setup_keys`] body operating on an already-compacted system.
fn setup_keys_compacted<B: FieldBackend, E: Pairing>(
    cs: ConstraintSystem<B>,
    cache_dir: &Path,
    curve_tag: &str,
) -> Result<(ark_groth16::ProvingKey<E>, ark_groth16::VerifyingKey<E>), String> {
    let key = cache_key(&cs, curve_tag);
    let cache_subdir = cache_dir.join(&key);

    if let Some(keys) = load_cached_keys::<E>(&cache_subdir) {
        Ok(keys)
    } else {
        let setup_circuit = AchronymeCircuit { cs, witness: None };
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(setup_circuit, &mut OsRng)
            .map_err(|e| format!("Groth16 setup failed: {e}"))?;
        save_cached_keys(&cache_subdir, &pk, &vk)?;
        Ok((pk, vk))
    }
}

/// Run trusted setup and return only the verifying key.
///
/// Compacts the system exactly like [`setup_keys`] and
/// [`generate_proof_raw`], so the verifying key matches the proofs
/// those produce.
pub fn setup_vk_only<B: FieldBackend, E: Pairing>(
    cs: &ConstraintSystem<B>,
    cache_dir: &Path,
    curve_tag: &str,
) -> Result<ark_groth16::VerifyingKey<E>, String> {
    let (compacted, _gather) = cs.compact_referenced();
    let key = cache_key(&compacted, curve_tag);
    let cache_subdir = cache_dir.join(&key);

    if let Some(vk) = load_cached_vk::<E>(&cache_subdir) {
        return Ok(vk);
    }

    let setup_circuit = AchronymeCircuit {
        cs: compacted,
        witness: None,
    };
    let (_pk, vk) = Groth16::<E>::circuit_specific_setup(setup_circuit, &mut OsRng)
        .map_err(|e| format!("Groth16 setup failed: {e}"))?;
    save_cached_vk(&cache_subdir, &vk)?;
    Ok(vk)
}

/// Generate a Groth16 proof and return raw ark types.
///
/// Curve-specific modules (e.g., `groth16_bn254`) wrap this to add
/// JSON serialization and return `ProveResult`.
///
/// The system is wire-compacted once; the same compacted circuit feeds
/// both setup and prove, and the witness is gathered down to the
/// surviving wires. Public-input extraction is unaffected (compaction
/// keeps `ONE` and the public inputs at their indices).
#[allow(clippy::type_complexity)]
pub fn generate_proof_raw<B: FieldBackend, E: Pairing>(
    cs: &ConstraintSystem<B>,
    witness: &[FieldElement<B>],
    cache_dir: &Path,
    curve_tag: &str,
) -> Result<
    (
        ark_groth16::Proof<E>,
        ark_groth16::VerifyingKey<E>,
        Vec<E::ScalarField>,
    ),
    String,
> {
    let (compacted, gather) = cs.compact_referenced();
    let gathered_witness: Vec<FieldElement<B>> = gather.iter().map(|&old| witness[old]).collect();
    drop(gather);

    let (pk, vk) = setup_keys_compacted::<B, E>(compacted.clone(), cache_dir, curve_tag)?;

    let prove_circuit = AchronymeCircuit {
        cs: compacted,
        witness: Some(gathered_witness),
    };
    let proof = Groth16::<E>::prove(&pk, prove_circuit, &mut OsRng)
        .map_err(|e| format!("Groth16 prove failed: {e}"))?;

    // Extract public inputs (indices 1..=num_pub)
    let num_pub = cs.num_pub_inputs();
    let public_inputs: Vec<E::ScalarField> =
        (1..=num_pub).map(|i| fe_to_ark(&witness[i])).collect();

    // Verify (sanity check)
    let valid = Groth16::<E>::verify(&vk, &public_inputs, &proof)
        .map_err(|e| format!("Groth16 verify failed: {e}"))?;
    if !valid {
        return Err("Groth16 proof verification failed (internal error)".into());
    }

    Ok((proof, vk, public_inputs))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that source_half_modulus computes floor(p/2) correctly for BN254.
    #[test]
    fn half_mod_is_correct() {
        let half = source_half_modulus::<Bn254Fr>();

        let m = memory::field::MODULUS;

        // Verify: 2 * half < p (since p is odd, floor(p/2) * 2 = p - 1)
        let mut double = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let wide = (half[i] as u128) * 2 + carry as u128;
            double[i] = wide as u64;
            carry = (wide >> 64) as u64;
        }
        // 2 * floor(p/2) should equal p - 1 (since p is odd)
        let mut p_minus_1 = m;
        p_minus_1[0] -= 1; // p is odd, so subtracting 1 from limb 0 is safe
        assert_eq!(double, p_minus_1, "2 * floor(p/2) should equal p-1");

        // Verify the carry-bit issue: limb[2] of half must have the MSB set
        // because MOD[3] is odd (LSB = 1), so the carry propagates.
        assert_eq!(m[3] & 1, 1, "BN254 modulus[3] should be odd");
        assert_ne!(
            half[2],
            m[2] / 2,
            "half[2] must differ from naive m[2]/2 due to carry from m[3]"
        );
        assert_eq!(
            half[2],
            (m[2] >> 1) | (1 << 63),
            "half[2] must include carry bit from m[3]"
        );
    }

    /// Verify fe_to_ark correctness at the boundary near p/2.
    #[test]
    fn fe_to_ark_boundary_values() {
        use ark_bn254::Fr as ArkFr;

        // Zero and one should convert to themselves
        let zero = FieldElement::<Bn254Fr>::from_u64(0);
        let one = FieldElement::<Bn254Fr>::from_u64(1);
        let r0: ArkFr = fe_to_ark(&zero);
        let r1: ArkFr = fe_to_ark(&one);
        assert_eq!(r0, ArkFr::from(0u64));
        assert_eq!(r1, ArkFr::from(1u64));

        // -1 (= p - 1) should convert to -1 in the target field
        let neg_one = FieldElement::<Bn254Fr>::from_u64(1).neg();
        let result: ArkFr = fe_to_ark(&neg_one);
        assert_eq!(result, -ArkFr::from(1u64));

        // Small positive should stay positive
        let small = FieldElement::<Bn254Fr>::from_u64(12345);
        let r_small: ArkFr = fe_to_ark(&small);
        assert_eq!(r_small, ArkFr::from(12345u64));

        // Small negative should stay negative
        let neg_small = FieldElement::<Bn254Fr>::from_u64(12345).neg();
        let result: ArkFr = fe_to_ark(&neg_small);
        assert_eq!(result, -ArkFr::from(12345u64));
    }

    /// End-to-end Groth16 over a system with an unreferenced wire: the
    /// compaction inside `generate_proof_raw` must drop the dead slot,
    /// gather the witness, and still produce a verifying proof whose
    /// public inputs come from the original full-width witness. Also
    /// checks `setup_vk_only` yields the SAME verifying key class (the
    /// compacted circuit) by verifying the proof against it.
    #[test]
    fn proof_over_compacted_system_verifies() {
        use ark_bn254::Bn254;
        use constraints::r1cs::LinearCombination;

        // public = x * x, with a dead wire allocated between x and out.
        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let public = cs.alloc_input();
        let x = cs.alloc_witness();
        let _dead = cs.alloc_witness();
        cs.enforce(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(public),
        );

        let witness = vec![
            FieldElement::<Bn254Fr>::from_u64(1),
            FieldElement::<Bn254Fr>::from_u64(49),
            FieldElement::<Bn254Fr>::from_u64(7),
            FieldElement::<Bn254Fr>::from_u64(123_456),
        ];
        cs.verify(&witness).expect("full-width witness satisfies");

        let cache_dir =
            std::env::temp_dir().join(format!("ach-groth16-compact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache_dir);

        let (proof, vk, public_inputs) =
            generate_proof_raw::<Bn254Fr, Bn254>(&cs, &witness, &cache_dir, "bn254-test")
                .expect("proof over compacted system");
        assert_eq!(public_inputs.len(), 1);

        // The standalone vk path must agree with the proving path.
        let vk_only = setup_vk_only::<Bn254Fr, Bn254>(&cs, &cache_dir, "bn254-test")
            .expect("vk over compacted system");
        let valid =
            Groth16::<Bn254>::verify(&vk_only, &public_inputs, &proof).expect("verification ran");
        assert!(valid, "proof must verify against setup_vk_only's key");
        assert_eq!(vk.gamma_abc_g1.len(), vk_only.gamma_abc_g1.len());

        // Warm path: a second prove hits the streamed key cache.
        let (proof2, _, public_inputs2) =
            generate_proof_raw::<Bn254Fr, Bn254>(&cs, &witness, &cache_dir, "bn254-test")
                .expect("warm prove over cached compacted keys");
        let valid2 =
            Groth16::<Bn254>::verify(&vk_only, &public_inputs2, &proof2).expect("verification ran");
        assert!(valid2);

        let _ = std::fs::remove_dir_all(&cache_dir);
    }
}
