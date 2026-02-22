//! Native Groth16 proof generation using ark-groth16.
//!
//! Replaces the snarkjs subprocess pipeline with in-process proving.

use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
    Variable as ArkVariable,
};
use ark_snark::SNARK;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use constraints::r1cs::ConstraintSystem;
use memory::FieldElement;
use vm::ProveResult;

// ============================================================================
// Field conversion
// ============================================================================

/// Convert an Achronyme `FieldElement` (BN254 Fr) to an ark `Fr`.
/// Both use the same modulus, so this is a lossless conversion.
fn fe_to_ark(fe: &FieldElement) -> Fr {
    Fr::from_le_bytes_mod_order(&fe.to_le_bytes())
}

// ============================================================================
// Circuit adapter
// ============================================================================

/// Wraps an Achronyme `ConstraintSystem` so ark-groth16 can synthesize it.
#[derive(Clone)]
pub struct AchronymeCircuit {
    cs: ConstraintSystem,
    witness: Option<Vec<FieldElement>>,
}

impl ConstraintSynthesizer<Fr> for AchronymeCircuit {
    fn generate_constraints(self, ark_cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let num_pub = self.cs.num_pub_inputs();
        let num_vars = self.cs.num_variables();

        // Map Achronyme variable indices to ark variables.
        // Index 0 = ONE (implicit in ark), indices 1..=num_pub = public inputs,
        // indices num_pub+1.. = witness variables.
        let mut var_map: Vec<ArkVariable> = Vec::with_capacity(num_vars);

        // Index 0 → ark's built-in ONE
        var_map.push(ArkVariable::One);

        // Public inputs: indices 1..=num_pub
        for i in 1..=num_pub {
            let val = self
                .witness
                .as_ref()
                .map(|w| fe_to_ark(&w[i]))
                .unwrap_or_default();
            let v = ark_cs.new_input_variable(|| Ok(val))?;
            var_map.push(v);
        }

        // Witness variables: indices num_pub+1..num_vars
        for i in (num_pub + 1)..num_vars {
            let val = self
                .witness
                .as_ref()
                .map(|w| fe_to_ark(&w[i]))
                .unwrap_or_default();
            let v = ark_cs.new_witness_variable(|| Ok(val))?;
            var_map.push(v);
        }

        // Convert each (A, B, C) constraint
        for constraint in self.cs.constraints() {
            let a = convert_lc(&constraint.a, &var_map);
            let b = convert_lc(&constraint.b, &var_map);
            let c = convert_lc(&constraint.c, &var_map);
            ark_cs.enforce_constraint(a, b, c)?;
        }

        Ok(())
    }
}

/// Convert an Achronyme `LinearCombination` to an ark `LinearCombination`.
fn convert_lc(
    lc: &constraints::r1cs::LinearCombination,
    var_map: &[ArkVariable],
) -> ark_relations::r1cs::LinearCombination<Fr> {
    let mut ark_lc = ark_relations::r1cs::LinearCombination::zero();
    for (var, coeff) in &lc.terms {
        ark_lc += (fe_to_ark(coeff), var_map[var.index()]);
    }
    ark_lc
}

// ============================================================================
// Proof generation (top-level entry point)
// ============================================================================

/// Run trusted setup (or load cached keys) without proving.
pub fn setup_keys(
    cs: &ConstraintSystem,
    cache_dir: &Path,
) -> Result<(ark_groth16::ProvingKey<Bn254>, ark_groth16::VerifyingKey<Bn254>), String> {
    let key = cache_key(cs);
    let cache_subdir = cache_dir.join(&key);

    if let Some(keys) = load_cached_keys(&cache_subdir) {
        Ok(keys)
    } else {
        let setup_circuit = AchronymeCircuit {
            cs: cs.clone(),
            witness: None,
        };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut OsRng)
            .map_err(|e| format!("Groth16 setup failed: {e}"))?;
        save_cached_keys(&cache_subdir, &pk, &vk)?;
        Ok((pk, vk))
    }
}

/// Run trusted setup and return only the verifying key.
///
/// Tries the cache first (loading only the VK file). On cache miss, runs
/// full setup but only serializes the VK to disk — avoids the cost of
/// writing the much larger proving key when only the VK is needed.
pub fn setup_vk_only(
    cs: &ConstraintSystem,
    cache_dir: &Path,
) -> Result<ark_groth16::VerifyingKey<Bn254>, String> {
    let key = cache_key(cs);
    let cache_subdir = cache_dir.join(&key);

    // Try loading just the VK from cache
    if let Some(vk) = load_cached_vk(&cache_subdir) {
        return Ok(vk);
    }

    // Full setup required — save only VK
    let setup_circuit = AchronymeCircuit {
        cs: cs.clone(),
        witness: None,
    };
    let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut OsRng)
        .map_err(|e| format!("Groth16 setup failed: {e}"))?;
    save_cached_vk(&cache_subdir, &vk)?;
    Ok(vk)
}

/// Generate a native Groth16 proof using ark-groth16.
///
/// Uses cached proving/verifying keys when available.
pub fn generate_proof(
    cs: &ConstraintSystem,
    witness: &[FieldElement],
    cache_dir: &Path,
) -> Result<ProveResult, String> {
    let (pk, vk) = setup_keys(cs, cache_dir)?;

    // Prove
    let prove_circuit = AchronymeCircuit {
        cs: cs.clone(),
        witness: Some(witness.to_vec()),
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut OsRng)
        .map_err(|e| format!("Groth16 prove failed: {e}"))?;

    // 4. Extract public inputs (indices 1..=num_pub)
    let num_pub = cs.num_pub_inputs();
    let public_inputs: Vec<Fr> = (1..=num_pub).map(|i| fe_to_ark(&witness[i])).collect();

    // 5. Verify (sanity check)
    let valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .map_err(|e| format!("Groth16 verify failed: {e}"))?;
    if !valid {
        return Err("Groth16 proof verification failed (internal error)".into());
    }

    // 6. Serialize to snarkjs-compatible JSON
    let proof_json = serialize_proof_json(&proof);
    let public_json = serialize_public_json(&public_inputs);
    let vkey_json = serialize_vkey_json(&vk, num_pub);

    Ok(ProveResult::Proof {
        proof_json,
        public_json,
        vkey_json,
    })
}

// ============================================================================
// JSON serialization (snarkjs-compatible)
// ============================================================================

/// Format a G1 affine point as a JSON array of 3 decimal strings [x, y, "1"].
fn g1_to_json(p: &<Bn254 as Pairing>::G1Affine) -> serde_json::Value {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return serde_json::json!(["0", "1", "0"]);
    }
    let x = p.x().expect("non-zero point has x");
    let y = p.y().expect("non-zero point has y");
    serde_json::json!([
        fr_to_decimal(&x),
        fr_to_decimal(&y),
        "1"
    ])
}

/// Format a G2 affine point as a JSON array of 3 arrays, each with 2 decimal strings.
fn g2_to_json(p: &<Bn254 as Pairing>::G2Affine) -> serde_json::Value {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return serde_json::json!([["0", "0"], ["1", "0"], ["0", "0"]]);
    }
    let x = p.x().expect("non-zero point has x");
    let y = p.y().expect("non-zero point has y");
    // Fq2 has c0, c1 components
    serde_json::json!([
        [fr_to_decimal(&x.c0), fr_to_decimal(&x.c1)],
        [fr_to_decimal(&y.c0), fr_to_decimal(&y.c1)],
        ["1", "0"]
    ])
}

/// Convert an ark field element to a decimal string.
fn fr_to_decimal<F: PrimeField>(f: &F) -> String {
    f.into_bigint().to_string()
}

fn serialize_proof_json(proof: &ark_groth16::Proof<Bn254>) -> String {
    let obj = serde_json::json!({
        "pi_a": g1_to_json(&proof.a),
        "pi_b": g2_to_json(&proof.b),
        "pi_c": g1_to_json(&proof.c),
        "protocol": "groth16",
        "curve": "bn128"
    });
    serde_json::to_string_pretty(&obj).unwrap()
}

fn serialize_public_json(inputs: &[Fr]) -> String {
    let arr: Vec<String> = inputs.iter().map(|f| fr_to_decimal(f)).collect();
    serde_json::to_string_pretty(&arr).unwrap()
}

fn serialize_vkey_json(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    num_pub: usize,
) -> String {
    let mut ic: Vec<serde_json::Value> = Vec::new();
    for p in &vk.gamma_abc_g1 {
        ic.push(g1_to_json(p));
    }
    let obj = serde_json::json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": num_pub,
        "vk_alpha_1": g1_to_json(&vk.alpha_g1),
        "vk_beta_2": g2_to_json(&vk.beta_g2),
        "vk_gamma_2": g2_to_json(&vk.gamma_g2),
        "vk_delta_2": g2_to_json(&vk.delta_g2),
        "IC": ic
    });
    serde_json::to_string_pretty(&obj).unwrap()
}

// ============================================================================
// Cache helpers
// ============================================================================

/// Compute a SHA256 cache key from the constraint system structure.
fn cache_key(cs: &ConstraintSystem) -> String {
    let mut hasher = Sha256::new();
    // Version salt — bump when serialization format or setup algorithm changes
    hasher.update(b"achronyme-groth16-cache-v1");
    // Hash structural parameters
    hasher.update(cs.num_variables().to_le_bytes());
    hasher.update(cs.num_pub_inputs().to_le_bytes());
    hasher.update(cs.num_constraints().to_le_bytes());
    // Hash each constraint's terms
    for c in cs.constraints() {
        hash_lc(&mut hasher, &c.a);
        hash_lc(&mut hasher, &c.b);
        hash_lc(&mut hasher, &c.c);
    }
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn hash_lc(hasher: &mut Sha256, lc: &constraints::r1cs::LinearCombination) {
    // Sort terms by variable index for canonical ordering — avoids
    // cache misses when semantically identical LCs have different term order.
    let mut terms: Vec<_> = lc.terms.iter().collect();
    terms.sort_by_key(|(var, _)| var.index());
    hasher.update((terms.len() as u64).to_le_bytes());
    for (var, coeff) in &terms {
        hasher.update((var.index() as u64).to_le_bytes());
        hasher.update(coeff.to_le_bytes());
    }
}

fn load_cached_vk(dir: &Path) -> Option<ark_groth16::VerifyingKey<Bn254>> {
    let vk_path = dir.join("verifying_key.bin");
    if !vk_path.exists() {
        return None;
    }
    let vk_bytes = std::fs::read(&vk_path).ok()?;
    ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).ok()
}

fn save_cached_vk(
    dir: &Path,
    vk: &ark_groth16::VerifyingKey<Bn254>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create cache dir: {e}"))?;
    let mut vk_buf = Vec::new();
    vk.serialize_compressed(&mut vk_buf)
        .map_err(|e| format!("failed to serialize verifying key: {e}"))?;
    std::fs::write(dir.join("verifying_key.bin"), &vk_buf)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;
    Ok(())
}

fn load_cached_keys(
    dir: &Path,
) -> Option<(
    ark_groth16::ProvingKey<Bn254>,
    ark_groth16::VerifyingKey<Bn254>,
)> {
    let pk_path = dir.join("proving_key.bin");
    let vk_path = dir.join("verifying_key.bin");
    if !pk_path.exists() || !vk_path.exists() {
        return None;
    }
    let pk_bytes = std::fs::read(&pk_path).ok()?;
    let vk_bytes = std::fs::read(&vk_path).ok()?;
    let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..]).ok()?;
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).ok()?;
    Some((pk, vk))
}

fn save_cached_keys(
    dir: &Path,
    pk: &ark_groth16::ProvingKey<Bn254>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
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
