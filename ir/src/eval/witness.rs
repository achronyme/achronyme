use std::collections::HashMap;

use memory::{FieldBackend, FieldElement};

use crate::types::SsaVar;

use super::EvalError;

/// Dispatch an Artik `WitnessCall` instruction. Reads current values
/// of `inputs` from `values`, runs the Artik program, and writes one
/// field element per `outputs` slot back into `values`. Returns an
/// `EvalError::WitnessCallFailed` wrapping the underlying Artik error
/// on any decode / validate / execute failure.
///
/// Callers must not have already populated `outputs`; the Artik run
/// is the source of truth for those slots.
pub(super) fn dispatch_witness_call<F: FieldBackend>(
    inputs: &[SsaVar],
    outputs: &[SsaVar],
    program_bytes: &[u8],
    values: &mut HashMap<SsaVar, FieldElement<F>>,
) -> Result<(), Box<EvalError<F>>> {
    let primary = outputs.first().copied().unwrap_or(SsaVar(0));

    // Resolve input signals from the current values map.
    let mut signal_vec: Vec<FieldElement<F>> = Vec::with_capacity(inputs.len());
    for v in inputs {
        let val = values
            .get(v)
            .copied()
            .ok_or_else(|| Box::new(EvalError::UndefinedVar(*v)))?;
        signal_vec.push(val);
    }

    // Family guard — the Artik decoder cross-checks the bytecode header
    // against the expected family, which is determined by the backend
    // the evaluator was instantiated with.
    let family = witness_family::<F>().ok_or_else(|| {
        Box::new(EvalError::WitnessCallFailed {
            primary_output: primary,
            reason: "no Artik field-family binding for this backend".to_string(),
        })
    })?;

    let program = artik::bytecode::decode(program_bytes, Some(family)).map_err(|e| {
        Box::new(EvalError::WitnessCallFailed {
            primary_output: primary,
            reason: format!("decode failed: {e:?}"),
        })
    })?;

    let mut slot_vec: Vec<FieldElement<F>> = vec![FieldElement::<F>::zero(); outputs.len()];
    let mut ctx = artik::ArtikContext::<F>::new(&signal_vec, &mut slot_vec);
    artik::execute(&program, &mut ctx).map_err(|e| {
        Box::new(EvalError::WitnessCallFailed {
            primary_output: primary,
            reason: format!("execute failed: {e:?}"),
        })
    })?;

    for (v, val) in outputs.iter().zip(slot_vec.iter()) {
        values.insert(*v, *val);
    }
    Ok(())
}

/// Map the eval's `FieldBackend` to the `FieldFamily` the Artik
/// bytecode header declares. The lift emits `BnLike256` for BN254
/// and BLS12-381 (both are 256-bit BN-like primes sharing the Artik
/// encoding); Goldilocks would need its own family and no circom
/// lift targets it today.
fn witness_family<F: FieldBackend>() -> Option<memory::FieldFamily> {
    use memory::PrimeId;
    match F::PRIME_ID {
        PrimeId::Bn254 | PrimeId::Bls12_381 => Some(memory::FieldFamily::BnLike256),
        _ => None,
    }
}
