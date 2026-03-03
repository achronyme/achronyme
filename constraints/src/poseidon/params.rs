use memory::FieldElement;

use super::constants::{fe_from_hex, CIRCOMLIB_MDS, CIRCOMLIB_RC};
use super::lfsr::GrainLfsr;

/// Poseidon parameters for BN254, t=3
#[derive(Clone)]
pub struct PoseidonParams {
    /// State width (number of field elements in sponge state)
    pub t: usize,
    /// Number of full rounds (split evenly: half at start, half at end)
    pub r_f: usize,
    /// Number of partial rounds (in the middle)
    pub r_p: usize,
    /// Round constants: (r_f + r_p) * t field elements
    pub round_constants: Vec<FieldElement>,
    /// MDS matrix: t x t, stored row-major
    pub mds: Vec<Vec<FieldElement>>,
}

impl PoseidonParams {
    /// Construct PoseidonParams from explicit components.
    ///
    /// Use this for custom parameterizations (e.g., t=5, t=9) or
    /// when supplying externally-sourced constants.
    pub fn new(
        t: usize,
        r_f: usize,
        r_p: usize,
        round_constants: Vec<FieldElement>,
        mds: Vec<Vec<FieldElement>>,
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
            round_constants,
            mds,
        }
    }

    /// Standard BN254 parameters: t=3, R_f=8, R_p=57
    ///
    /// Uses circomlibjs v0.1.7 constants (C[1], M[1]) for ecosystem
    /// interoperability with snarkjs, circom, and iden3 tooling.
    ///
    /// See module-level docs for provenance and divergence notes.
    pub fn bn254_t3() -> Self {
        let round_constants: Vec<FieldElement> =
            CIRCOMLIB_RC.iter().map(|h| fe_from_hex(h)).collect();

        let mds: Vec<Vec<FieldElement>> = CIRCOMLIB_MDS
            .iter()
            .map(|row| row.iter().map(|h| fe_from_hex(h)).collect())
            .collect();

        Self::new(3, 8, 57, round_constants, mds)
    }

    /// Paper-compliant BN254 parameters: t=3, R_f=8, R_p=57
    ///
    /// Round constants generated via Grain LFSR (Poseidon paper, ePrint
    /// 2019/458, Appendix E). MDS via Cauchy construction M[i][j] = 1/(x_i + y_j).
    ///
    /// **WARNING**: These constants do NOT match circomlibjs. Proofs generated
    /// with this parameterization are incompatible with snarkjs/circom.
    /// Use [`Self::bn254_t3`] for production circuits.
    #[allow(clippy::needless_range_loop)]
    pub fn bn254_t3_lfsr() -> Self {
        let t = 3;
        let r_f = 8;
        let r_p = 57;
        let total_rounds = r_f + r_p;
        let field_size = 254u16;

        // --- MDS Matrix (Cauchy construction) ---
        let mut mds = vec![vec![FieldElement::ZERO; t]; t];
        for i in 0..t {
            for j in 0..t {
                let sum = (i + j + t) as u64;
                let denom = FieldElement::from_u64(sum);
                mds[i][j] = denom.inv().unwrap();
            }
        }

        // --- Round Constants (Grain LFSR) ---
        let mut grain = GrainLfsr::new(field_size, t as u16, r_f as u16, r_p as u16);
        let mut round_constants = Vec::with_capacity(total_rounds * t);
        for _ in 0..(total_rounds * t) {
            round_constants.push(grain.next_field_element(field_size as usize));
        }

        Self::new(t, r_f, r_p, round_constants, mds)
    }
}
