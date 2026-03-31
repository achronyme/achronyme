/// Identifies which prime field is in use for a given session.
///
/// Each variant corresponds to a scalar field (Fr) of a specific elliptic curve
/// or a standalone STARK-friendly prime. The `PrimeId` is stored in bytecode
/// headers, R1CS/WTNS files, and project configuration to ensure artifacts
/// are never mixed across incompatible fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PrimeId {
    /// BN254 scalar field (aka alt_bn128, bn128)
    /// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    /// 254 bits, 4 limbs. Default for Ethereum/Circom/snarkjs.
    Bn254,

    /// BLS12-381 scalar field
    /// p = 73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    /// 255 bits, 4 limbs. Used by Zcash, Filecoin, Ethereum 2.0.
    Bls12_381,

    /// Goldilocks prime
    /// p = 2^64 - 2^32 + 1 = 18446744069414584321
    /// 64 bits, 1 limb. Used by Plonky2/Plonky3 (STARK-friendly).
    Goldilocks,

    /// Grumpkin scalar field (cycle pair with BN254)
    /// 254 bits, 4 limbs. Used for recursive proofs.
    Grumpkin,

    /// Pallas scalar field (cycle pair with Vesta, used by Halo2 IPA)
    /// 255 bits, 4 limbs.
    Pallas,

    /// Vesta scalar field (cycle pair with Pallas)
    /// 255 bits, 4 limbs.
    Vesta,

    /// secp256r1 (NIST P-256) scalar field
    /// 256 bits, 4 limbs. Used for WebAuthn.
    Secp256r1,

    /// BLS12-377 scalar field (used by Aleo)
    /// 253 bits, 4 limbs.
    Bls12_377,
}

impl PrimeId {
    /// Human-readable name matching CLI flag and config values.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bn254 => "bn254",
            Self::Bls12_381 => "bls12-381",
            Self::Goldilocks => "goldilocks",
            Self::Grumpkin => "grumpkin",
            Self::Pallas => "pallas",
            Self::Vesta => "vesta",
            Self::Secp256r1 => "secp256r1",
            Self::Bls12_377 => "bls12-377",
        }
    }

    /// Parse from a CLI/config string (case-insensitive, allows common aliases).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "bn254" | "bn128" | "alt_bn128" | "altbn128" => Some(Self::Bn254),
            "bls12-381" | "bls12381" | "bls12_381" => Some(Self::Bls12_381),
            "goldilocks" | "gl" => Some(Self::Goldilocks),
            "grumpkin" => Some(Self::Grumpkin),
            "pallas" => Some(Self::Pallas),
            "vesta" => Some(Self::Vesta),
            "secp256r1" | "p256" => Some(Self::Secp256r1),
            "bls12-377" | "bls12377" | "bls12_377" => Some(Self::Bls12_377),
            _ => None,
        }
    }

    /// Bit size of the prime modulus.
    pub const fn modulus_bit_size(self) -> u32 {
        match self {
            Self::Bn254 => 254,
            Self::Bls12_381 => 255,
            Self::Goldilocks => 64,
            Self::Grumpkin => 254,
            Self::Pallas => 255,
            Self::Vesta => 255,
            Self::Secp256r1 => 256,
            Self::Bls12_377 => 253,
        }
    }

    /// Byte size needed to represent a single field element in canonical form.
    pub const fn byte_size(self) -> usize {
        match self {
            Self::Goldilocks => 8,
            _ => 32,
        }
    }
}

impl std::fmt::Display for PrimeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_roundtrip() {
        let primes = [
            PrimeId::Bn254,
            PrimeId::Bls12_381,
            PrimeId::Goldilocks,
            PrimeId::Grumpkin,
            PrimeId::Pallas,
            PrimeId::Vesta,
            PrimeId::Secp256r1,
            PrimeId::Bls12_377,
        ];
        for p in primes {
            assert_eq!(PrimeId::from_name(p.name()), Some(p));
        }
    }

    #[test]
    fn test_aliases() {
        assert_eq!(PrimeId::from_name("bn128"), Some(PrimeId::Bn254));
        assert_eq!(PrimeId::from_name("alt_bn128"), Some(PrimeId::Bn254));
        assert_eq!(PrimeId::from_name("BN254"), Some(PrimeId::Bn254));
        assert_eq!(PrimeId::from_name("BLS12-381"), Some(PrimeId::Bls12_381));
        assert_eq!(PrimeId::from_name("gl"), Some(PrimeId::Goldilocks));
        assert_eq!(PrimeId::from_name("p256"), Some(PrimeId::Secp256r1));
        assert_eq!(PrimeId::from_name("unknown"), None);
    }

    #[test]
    fn test_byte_size() {
        assert_eq!(PrimeId::Bn254.byte_size(), 32);
        assert_eq!(PrimeId::Bls12_381.byte_size(), 32);
        assert_eq!(PrimeId::Goldilocks.byte_size(), 8);
    }
}
