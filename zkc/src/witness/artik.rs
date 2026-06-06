use constraints::r1cs::Variable;
use memory::{FieldBackend, FieldElement};

use super::WitnessError;

// ============================================================================
// Artik dispatch
// ============================================================================

/// Decode + execute an Artik program, reading `inputs` from the
/// witness vector and writing one field element per `outputs` slot.
///
/// When `memo` is provided, an identical `(program, inputs)` already seen
/// in the same proof — e.g. by the off-circuit hint walk that runs before
/// the R1CS witness fill — is served from the cache instead of being
/// re-executed. The written values are identical either way: a cache hit
/// only occurs on a bit-identical `(program, inputs)`, so the cached
/// outputs match a fresh execution.
pub(crate) fn dispatch_artik_call<F: FieldBackend>(
    outputs: &[Variable],
    inputs: &[Variable],
    program_bytes: &[u8],
    witness: &mut [FieldElement<F>],
    memo: Option<&mut artik::ArtikMemo<F>>,
) -> Result<(), WitnessError> {
    let primary = outputs.first().map(|v| v.index()).unwrap_or(0);

    let signal_vec: Vec<FieldElement<F>> = inputs.iter().map(|v| witness[v.index()]).collect();
    let mut slot_vec: Vec<FieldElement<F>> = vec![FieldElement::<F>::zero(); outputs.len()];

    match memo {
        Some(m) => m.run(program_bytes, &signal_vec, &mut slot_vec),
        None => artik::execute_into(program_bytes, &signal_vec, &mut slot_vec),
    }
    .map_err(|e| WitnessError::ArtikCallFailed {
        primary_output: primary,
        reason: format!("{e:?}"),
    })?;

    for (v, val) in outputs.iter().zip(slot_vec.iter()) {
        witness[v.index()] = *val;
    }
    Ok(())
}
