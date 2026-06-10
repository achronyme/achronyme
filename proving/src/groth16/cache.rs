//! Proving/verifying key disk cache: structural cache key over the
//! constraint system + streamed (de)serialization of the ark key pair.

use std::path::Path;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

use constraints::r1cs::ConstraintSystem;
use memory::FieldBackend;

/// Compute a SHA256 cache key from the constraint system structure and curve.
///
/// The `curve_tag` prevents cache collisions between different curves —
/// the same circuit compiled for BN254 and BLS12-381 must use separate
/// cached proving/verifying keys.
pub fn cache_key<B: FieldBackend>(cs: &ConstraintSystem<B>, curve_tag: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"achronyme-groth16-cache-v2");
    hasher.update(curve_tag.as_bytes());
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

fn hash_lc<B: FieldBackend>(hasher: &mut Sha256, lc: &constraints::r1cs::LinearCombination<B>) {
    let mut terms: Vec<_> = lc.terms().iter().collect();
    terms.sort_by_key(|(var, _)| var.index());
    hasher.update((terms.len() as u64).to_le_bytes());
    for (var, coeff) in &terms {
        hasher.update((var.index() as u64).to_le_bytes());
        hasher.update(coeff.to_le_bytes());
    }
}

pub(super) fn load_cached_vk<E: Pairing>(dir: &Path) -> Option<ark_groth16::VerifyingKey<E>> {
    let vk_path = dir.join("verifying_key.bin");
    let vk_bytes = std::fs::read(&vk_path).ok()?;
    ark_groth16::VerifyingKey::<E>::deserialize_compressed(&vk_bytes[..]).ok()
}

pub(super) fn save_cached_vk<E: Pairing>(
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

pub(super) fn load_cached_keys<E: Pairing>(
    dir: &Path,
) -> Option<(ark_groth16::ProvingKey<E>, ark_groth16::VerifyingKey<E>)> {
    let pk_path = dir.join("proving_key.bin");
    let vk_path = dir.join("verifying_key.bin");
    if !pk_path.exists() || !vk_path.exists() {
        return None;
    }
    // Stream from disk: reading the file into a `Vec<u8>` first would
    // hold the serialized bytes and the deserialized key resident at
    // the same time (proving keys are hundreds of MB at circuit scale).
    let pk_file = std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(&pk_path).ok()?);
    let pk = ark_groth16::ProvingKey::<E>::deserialize_compressed(pk_file).ok()?;
    let vk_file = std::io::BufReader::new(std::fs::File::open(&vk_path).ok()?);
    let vk = ark_groth16::VerifyingKey::<E>::deserialize_compressed(vk_file).ok()?;
    Some((pk, vk))
}

pub(super) fn save_cached_keys<E: Pairing>(
    dir: &Path,
    pk: &ark_groth16::ProvingKey<E>,
    vk: &ark_groth16::VerifyingKey<E>,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("failed to create cache dir: {e}"))?;

    // Stream to disk: serializing into a `Vec<u8>` first would hold a
    // second proving-key-sized buffer resident next to the key itself.
    let pk_file = std::fs::File::create(dir.join("proving_key.bin"))
        .map_err(|e| format!("failed to create proving key file: {e}"))?;
    let mut pk_writer = std::io::BufWriter::with_capacity(1 << 20, pk_file);
    pk.serialize_compressed(&mut pk_writer)
        .map_err(|e| format!("failed to serialize proving key: {e}"))?;
    std::io::Write::flush(&mut pk_writer)
        .map_err(|e| format!("failed to write proving key: {e}"))?;

    let mut vk_buf = Vec::new();
    vk.serialize_compressed(&mut vk_buf)
        .map_err(|e| format!("failed to serialize verifying key: {e}"))?;
    std::fs::write(dir.join("verifying_key.bin"), &vk_buf)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;

    Ok(())
}
