use memory::{Bls12_381Fr, FieldBackend, FieldElement, GoldilocksFr};

use super::constants::{fe_from_hex, CIRCOMLIB_MDS, CIRCOMLIB_RC};
use super::lfsr::GrainLfsr;

/// Poseidon parameters, generic over the prime field.
///
/// Default backend is `Bn254Fr`, so bare `PoseidonParams` means BN254.
#[derive(Clone)]
pub struct PoseidonParams<F: FieldBackend = memory::Bn254Fr> {
    /// State width (number of field elements in sponge state)
    pub t: usize,
    /// Number of full rounds (split evenly: half at start, half at end)
    pub r_f: usize,
    /// Number of partial rounds (in the middle)
    pub r_p: usize,
    /// S-box exponent (5 for BN254/BLS12-381, 7 for Goldilocks)
    pub alpha: u32,
    /// Round constants: (r_f + r_p) * t field elements
    pub round_constants: Vec<FieldElement<F>>,
    /// MDS matrix: t x t, stored row-major
    pub mds: Vec<Vec<FieldElement<F>>>,
}

impl<F: FieldBackend> PoseidonParams<F> {
    /// Construct PoseidonParams from explicit components.
    pub fn new(
        t: usize,
        r_f: usize,
        r_p: usize,
        alpha: u32,
        round_constants: Vec<FieldElement<F>>,
        mds: Vec<Vec<FieldElement<F>>>,
    ) -> Self {
        assert_eq!(
            round_constants.len(),
            (r_f + r_p) * t,
            "expected {} round constants, got {}",
            (r_f + r_p) * t,
            round_constants.len()
        );
        assert_eq!(mds.len(), t, "MDS must be {t}x{t}");
        for row in &mds {
            assert_eq!(row.len(), t, "MDS row must have {t} elements");
        }
        Self {
            t,
            r_f,
            r_p,
            alpha,
            round_constants,
            mds,
        }
    }

    /// Generate Poseidon parameters via Grain LFSR + Cauchy MDS.
    ///
    /// Paper-compliant (ePrint 2019/458, Appendix E). Constants depend on
    /// the field size, NOT on which specific prime — the LFSR is deterministic
    /// given (field_size, t, r_f, r_p).
    #[allow(clippy::needless_range_loop)]
    pub fn from_lfsr(t: usize, r_f: usize, r_p: usize, alpha: u32, field_size: u16) -> Self {
        let total_rounds = r_f + r_p;

        // Cauchy MDS: M[i][j] = 1 / (x_i + y_j) where x_i = i+t, y_j = j
        let mut mds = vec![vec![FieldElement::<F>::zero(); t]; t];
        for i in 0..t {
            for j in 0..t {
                let sum = (i + j + t) as u64;
                let denom = FieldElement::<F>::from_u64(sum);
                mds[i][j] = denom.inv().unwrap();
            }
        }

        // Grain LFSR round constants
        let mut grain = GrainLfsr::new(field_size, t as u16, r_f as u16, r_p as u16);
        let mut round_constants = Vec::with_capacity(total_rounds * t);
        for _ in 0..(total_rounds * t) {
            round_constants.push(grain.next_field_element::<F>(field_size as usize));
        }

        Self::new(t, r_f, r_p, alpha, round_constants, mds)
    }
}

// ============================================================================
// BN254-specific constructors
// ============================================================================

impl PoseidonParams<memory::Bn254Fr> {
    /// Standard BN254 parameters: t=3, R_f=8, R_p=57, α=5
    ///
    /// Uses circomlibjs v0.1.7 constants (C[1], M[1]) for ecosystem
    /// interoperability with snarkjs, circom, and iden3 tooling.
    pub fn bn254_t3() -> Self {
        let round_constants: Vec<FieldElement> =
            CIRCOMLIB_RC.iter().map(|h| fe_from_hex(h)).collect();

        let mds: Vec<Vec<FieldElement>> = CIRCOMLIB_MDS
            .iter()
            .map(|row| row.iter().map(|h| fe_from_hex(h)).collect())
            .collect();

        Self::new(3, 8, 57, 5, round_constants, mds)
    }

    /// Paper-compliant BN254 parameters: t=3, R_f=8, R_p=57, α=5
    ///
    /// Round constants generated via Grain LFSR. MDS via Cauchy construction.
    ///
    /// **WARNING**: These constants do NOT match circomlibjs. Use
    /// [`Self::bn254_t3`] for production circuits.
    pub fn bn254_t3_lfsr() -> Self {
        Self::from_lfsr(3, 8, 57, 5, 254)
    }
}

// ============================================================================
// BLS12-381-specific constructors
// ============================================================================

impl PoseidonParams<Bls12_381Fr> {
    /// BLS12-381 parameters: t=3, R_f=8, R_p=57, α=5
    ///
    /// LFSR-generated (paper-compliant). For ecosystem interoperability with
    /// filecoin/neptune, use hardcoded constants from that library instead.
    pub fn bls12_381_t3() -> Self {
        Self::from_lfsr(3, 8, 57, 5, 255)
    }
}

// ============================================================================
// Goldilocks-specific constructors
// ============================================================================

impl PoseidonParams<GoldilocksFr> {
    /// Goldilocks parameters: t=3, R_f=8, R_p=22, α=7
    ///
    /// α=7 because gcd(5, p-1) ≠ 1 for the Goldilocks prime (5 divides p-1),
    /// making x^5 non-invertible. α=7 is invertible since gcd(7, p-1) = 1.
    ///
    /// LFSR-generated (paper-compliant). r_p=22 follows Plonky2 convention.
    pub fn goldilocks_t3() -> Self {
        Self::from_lfsr(3, 8, 22, 7, 64)
    }
}
