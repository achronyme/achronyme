use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::SerdeFormat;
use memory::FieldElement;

/// Convert a halo2 `Fr` back to decimal string via `FieldElement`.
fn fr_to_decimal(f: &Fr) -> String {
    let repr = f.to_repr();
    let bytes: &[u8] = repr.as_ref();
    let mut le_bytes = [0u8; 32];
    le_bytes[..bytes.len()].copy_from_slice(bytes);
    let fe: FieldElement = FieldElement::from_le_bytes(&le_bytes).expect("valid Fr in range");
    fe.to_decimal_string()
}

pub(super) fn serialize_proof_json(
    proof_bytes: &[u8],
    public_inputs: &[Fr],
    k: u32,
) -> Result<String, String> {
    let proof_hex = format!("0x{}", hex_encode(proof_bytes));
    let public: Vec<String> = public_inputs.iter().map(fr_to_decimal).collect();
    let obj = serde_json::json!({
        "protocol": "plonk",
        "curve": "bn128",
        "proof": proof_hex,
        "public_inputs": public,
        "k": k
    });
    serde_json::to_string_pretty(&obj).map_err(|e| format!("proof JSON serialization failed: {e}"))
}

pub(super) fn serialize_public_json(inputs: &[Fr]) -> Result<String, String> {
    let arr: Vec<String> = inputs.iter().map(fr_to_decimal).collect();
    serde_json::to_string_pretty(&arr).map_err(|e| format!("public JSON serialization failed: {e}"))
}

pub(super) fn serialize_vkey_json(vk: &VerifyingKey<G1Affine>, k: u32) -> Result<String, String> {
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytes)
        .map_err(|e| format!("vkey serialization failed: {e}"))?;
    let vk_hex = format!("0x{}", hex_encode(&vk_bytes));
    let obj = serde_json::json!({
        "protocol": "plonk",
        "curve": "bn128",
        "k": k,
        "vkey": vk_hex
    });
    serde_json::to_string_pretty(&obj).map_err(|e| format!("vkey JSON serialization failed: {e}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
