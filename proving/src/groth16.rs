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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use constraints::r1cs::ConstraintSystem;
use memory::FieldElement;

// ============================================================================
// Field conversion
// ============================================================================

/// Convert an Achronyme `FieldElement` to an ark scalar field element.
///
/// Uses `from_le_bytes_mod_order` — works for any `PrimeField` regardless
/// of modulus. The caller must ensure the source `FieldElement` was produced
/// under the same prime; otherwise the value wraps mod the target prime.
pub fn fe_to_ark<F: PrimeField>(fe: &FieldElement) -> F {
    F::from_le_bytes_mod_order(&fe.to_le_bytes())
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
pub struct AchronymeCircuit {
    pub cs: ConstraintSystem,
    pub witness: Option<Vec<FieldElement>>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for AchronymeCircuit {
    fn generate_constraints(self, ark_cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
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
                .map(|w| fe_to_ark::<F>(&w[i]))
                .unwrap_or_default();
            let v = ark_cs.new_input_variable(|| Ok(val))?;
            var_map.push(v);
        }

        // Witness variables: indices num_pub+1..num_vars
        for i in (num_pub + 1)..num_vars {
            let val = self
                .witness
                .as_ref()
                .map(|w| fe_to_ark::<F>(&w[i]))
                .unwrap_or_default();
            let v = ark_cs.new_witness_variable(|| Ok(val))?;
            var_map.push(v);
        }

        // Convert each (A, B, C) constraint
        for constraint in self.cs.constraints() {
            let a = convert_lc::<F>(&constraint.a, &var_map);
            let b = convert_lc::<F>(&constraint.b, &var_map);
            let c = convert_lc::<F>(&constraint.c, &var_map);
            ark_cs.enforce_constraint(a, b, c)?;
        }

        Ok(())
    }
}

/// Convert an Achronyme `LinearCombination` to an ark `LinearCombination`.
fn convert_lc<F: PrimeField>(
    lc: &constraints::r1cs::LinearCombination,
    var_map: &[ArkVariable],
) -> ark_relations::r1cs::LinearCombination<F> {
    let mut ark_lc = ark_relations::r1cs::LinearCombination::zero();
    for (var, coeff) in &lc.terms {
        ark_lc += (fe_to_ark::<F>(coeff), var_map[var.index()]);
    }
    ark_lc
}

// ============================================================================
// Proof generation (generic over Pairing)
// ============================================================================

/// Run trusted setup (or load cached keys).
pub fn setup_keys<E: Pairing>(
    cs: &ConstraintSystem,
    cache_dir: &Path,
) -> Result<(ark_groth16::ProvingKey<E>, ark_groth16::VerifyingKey<E>), String> {
    let key = cache_key(cs);
    let cache_subdir = cache_dir.join(&key);

    if let Some(keys) = load_cached_keys::<E>(&cache_subdir) {
        Ok(keys)
    } else {
        let setup_circuit = AchronymeCircuit {
            cs: cs.clone(),
            witness: None,
        };
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(setup_circuit, &mut OsRng)
            .map_err(|e| format!("Groth16 setup failed: {e}"))?;
        save_cached_keys(&cache_subdir, &pk, &vk)?;
        Ok((pk, vk))
    }
}

/// Run trusted setup and return only the verifying key.
pub fn setup_vk_only<E: Pairing>(
    cs: &ConstraintSystem,
    cache_dir: &Path,
) -> Result<ark_groth16::VerifyingKey<E>, String> {
    let key = cache_key(cs);
    let cache_subdir = cache_dir.join(&key);

    if let Some(vk) = load_cached_vk::<E>(&cache_subdir) {
        return Ok(vk);
    }

    let setup_circuit = AchronymeCircuit {
        cs: cs.clone(),
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
pub fn generate_proof_raw<E: Pairing>(
    cs: &ConstraintSystem,
    witness: &[FieldElement],
    cache_dir: &Path,
) -> Result<
    (
        ark_groth16::Proof<E>,
        ark_groth16::VerifyingKey<E>,
        Vec<E::ScalarField>,
    ),
    String,
> {
    let (pk, vk) = setup_keys::<E>(cs, cache_dir)?;

    let prove_circuit = AchronymeCircuit {
        cs: cs.clone(),
        witness: Some(witness.to_vec()),
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
// Cache helpers (generic)
// ============================================================================

/// Compute a SHA256 cache key from the constraint system structure.
pub fn cache_key(cs: &ConstraintSystem) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"achronyme-groth16-cache-v1");
    hasher.update(cs.num_variables().to_le_bytes());
    hasher.update(cs.num_pub_inputs().to_le_bytes());
    hasher.update(cs.num_constraints().to_le_bytes());
    for c in cs.constraints() {
        hash_lc(&mut hasher, &c.a);
        hash_lc(&mut hasher, &c.b);
        hash_lc(&mut hasher, &c.c);
    }
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_lc(hasher: &mut Sha256, lc: &constraints::r1cs::LinearCombination) {
    let mut terms: Vec<_> = lc.terms.iter().collect();
    terms.sort_by_key(|(var, _)| var.index());
    hasher.update((terms.len() as u64).to_le_bytes());
    for (var, coeff) in &terms {
        hasher.update((var.index() as u64).to_le_bytes());
        hasher.update(coeff.to_le_bytes());
    }
}

fn load_cached_vk<E: Pairing>(dir: &Path) -> Option<ark_groth16::VerifyingKey<E>> {
    let vk_path = dir.join("verifying_key.bin");
    let vk_bytes = std::fs::read(&vk_path).ok()?;
    ark_groth16::VerifyingKey::<E>::deserialize_compressed(&vk_bytes[..]).ok()
}

fn save_cached_vk<E: Pairing>(
    dir: &Path,
    vk: &ark_groth16::VerifyingKey<E>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create cache dir: {e}"))?;
    let mut vk_buf = Vec::new();
    vk.serialize_compressed(&mut vk_buf)
        .map_err(|e| format!("failed to serialize verifying key: {e}"))?;
    std::fs::write(dir.join("verifying_key.bin"), &vk_buf)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;
    Ok(())
}

fn load_cached_keys<E: Pairing>(
    dir: &Path,
) -> Option<(ark_groth16::ProvingKey<E>, ark_groth16::VerifyingKey<E>)> {
    let pk_path = dir.join("proving_key.bin");
    let vk_path = dir.join("verifying_key.bin");
    if !pk_path.exists() || !vk_path.exists() {
        return None;
    }
    let pk_bytes = std::fs::read(&pk_path).ok()?;
    let vk_bytes = std::fs::read(&vk_path).ok()?;
    let pk = ark_groth16::ProvingKey::<E>::deserialize_compressed(&pk_bytes[..]).ok()?;
    let vk = ark_groth16::VerifyingKey::<E>::deserialize_compressed(&vk_bytes[..]).ok()?;
    Some((pk, vk))
}

fn save_cached_keys<E: Pairing>(
    dir: &Path,
    pk: &ark_groth16::ProvingKey<E>,
    vk: &ark_groth16::VerifyingKey<E>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create cache dir: {e}"))?;

    let mut pk_buf = Vec::new();
    pk.serialize_compressed(&mut pk_buf)
        .map_err(|e| format!("failed to serialize proving key: {e}"))?;
    std::fs::write(dir.join("proving_key.bin"), &pk_buf)
        .map_err(|e| format!("failed to write proving key: {e}"))?;

    let mut vk_buf = Vec::new();
    vk.serialize_compressed(&mut vk_buf)
        .map_err(|e| format!("failed to serialize verifying key: {e}"))?;
    std::fs::write(dir.join("verifying_key.bin"), &vk_buf)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;

    Ok(())
}
