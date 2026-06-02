use constraints::r1cs::Variable;
use memory::{FieldBackend, FieldElement};

use super::WitnessError;

// ============================================================================
// Artik dispatch
// ============================================================================

/// Pick the `FieldFamily` that matches the compile-time backend
/// `F`. BN254-family primes share `BnLike256` — Goldilocks would need
/// a separate family and no circom lift targets it today.
fn artik_family<F: FieldBackend>() -> Option<memory::FieldFamily> {
    use memory::PrimeId;
    match F::PRIME_ID {
        PrimeId::Bn254 | PrimeId::Bls12_381 => Some(memory::FieldFamily::BnLike256),
        _ => None,
    }
}

/// Decode + execute an Artik program, reading `inputs` from the
/// witness vector and writing one field element per `outputs` slot.
pub(crate) fn dispatch_artik_call<F: FieldBackend>(
    outputs: &[Variable],
    inputs: &[Variable],
    program_bytes: &[u8],
    witness: &mut [FieldElement<F>],
) -> Result<(), WitnessError> {
    let primary = outputs.first().map(|v| v.index()).unwrap_or(0);

    let family = artik_family::<F>().ok_or_else(|| WitnessError::ArtikCallFailed {
        primary_output: primary,
        reason: "no Artik field-family binding for this backend".to_string(),
    })?;

    let signal_vec: Vec<FieldElement<F>> = inputs.iter().map(|v| witness[v.index()]).collect();

    let program = artik::bytecode::decode(program_bytes, Some(family)).map_err(|e| {
        WitnessError::ArtikCallFailed {
            primary_output: primary,
            reason: format!("decode failed: {e:?}"),
        }
    })?;

    let mut slot_vec: Vec<FieldElement<F>> = vec![FieldElement::<F>::zero(); outputs.len()];
    let mut ctx = artik::ArtikContext::<F>::new(&signal_vec, &mut slot_vec);
    artik::execute(&program, &mut ctx).map_err(|e| WitnessError::ArtikCallFailed {
        primary_output: primary,
        reason: format!("execute failed: {e:?}"),
    })?;

    for (v, val) in outputs.iter().zip(slot_vec.iter()) {
        witness[v.index()] = *val;
    }
    Ok(())
}
