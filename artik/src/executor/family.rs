use super::*;

/// Reject a mismatch between the bytecode's declared field family and
/// the prime the backend implements. The mapping is: every 254/255/256
/// -bit prime shares `BnLike256`, Goldilocks has its own family, and
/// M31 is reserved for v2.
pub(super) fn check_family_compat<F: FieldBackend>(
    declared: FieldFamily,
) -> Result<(), ArtikError> {
    let expected = match F::PRIME_ID {
        PrimeId::Bn254
        | PrimeId::Bls12_381
        | PrimeId::Grumpkin
        | PrimeId::Pallas
        | PrimeId::Vesta
        | PrimeId::Secp256r1
        | PrimeId::Bls12_377 => FieldFamily::BnLike256,
        PrimeId::Goldilocks => FieldFamily::Goldilocks64,
    };
    if declared == expected {
        Ok(())
    } else {
        Err(ArtikError::FieldFamilyMismatch {
            declared: declared as u8,
            expected: expected as u8,
        })
    }
}
