use std::marker::PhantomData;

use super::{arithmetic, Bn254Fr, FieldBackend, PrimeId};

/// A prime field element parameterized by a `FieldBackend`.
///
/// Default backend is `Bn254Fr`. In type positions, bare `FieldElement`
/// means `FieldElement<Bn254Fr>`. In expression positions (constructors),
/// use the BN254-specific methods on `impl FieldElement<Bn254Fr>` or
/// specify the backend explicitly: `FieldElement::<F>::from_repr(...)`.
#[derive(Clone, Copy)]
pub struct FieldElement<F: FieldBackend = Bn254Fr> {
    repr: F::Repr,
    _phantom: PhantomData<F>,
}

// Manual trait impls — PhantomData is always Eq/Hash/PartialEq regardless of F.
impl<F: FieldBackend> PartialEq for FieldElement<F> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.repr == other.repr
    }
}
impl<F: FieldBackend> Eq for FieldElement<F> {}
impl<F: FieldBackend> std::hash::Hash for FieldElement<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.repr.hash(state);
    }
}

// ============================================================================
// Generic API (works for ANY backend)
// ============================================================================

impl<F: FieldBackend> FieldElement<F> {
    /// Wrap a raw backend representation.
    #[inline]
    pub fn from_repr(repr: F::Repr) -> Self {
        Self {
            repr,
            _phantom: PhantomData,
        }
    }

    /// Access the raw backend representation.
    #[inline]
    pub fn into_repr(self) -> F::Repr {
        self.repr
    }

    /// Which prime field this element belongs to.
    pub const fn prime_id() -> PrimeId {
        F::PRIME_ID
    }

    /// Bit size of the modulus.
    pub const fn modulus_bit_size() -> u32 {
        F::MODULUS_BIT_SIZE
    }

    /// Byte size of a canonical element.
    pub const fn byte_size() -> usize {
        F::BYTE_SIZE
    }

    /// The zero element (additive identity).
    #[inline]
    pub fn zero() -> Self {
        Self::from_repr(F::zero())
    }

    /// The one element (multiplicative identity).
    #[inline]
    pub fn one() -> Self {
        Self::from_repr(F::one())
    }

    /// Create from a small u64 value.
    pub fn from_u64(val: u64) -> Self {
        Self::from_repr(F::from_u64(val))
    }

    /// Create from a signed i64 value.
    pub fn from_i64(val: i64) -> Self {
        Self::from_repr(F::from_i64(val))
    }

    /// Create from canonical form `[u64; 4]` (already reduced mod p).
    pub fn from_canonical(limbs: [u64; 4]) -> Self {
        Self::from_repr(F::from_canonical_limbs(&limbs))
    }

    /// Convert back to canonical form (from internal representation).
    pub fn to_canonical(&self) -> [u64; 4] {
        F::to_canonical_limbs(&self.repr)
    }

    /// Check if zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        F::is_zero(&self.repr)
    }

    /// Modular addition: (self + other) mod p.
    pub fn add(&self, other: &Self) -> Self {
        Self::from_repr(F::add(&self.repr, &other.repr))
    }

    /// Modular subtraction: (self - other) mod p.
    pub fn sub(&self, other: &Self) -> Self {
        Self::from_repr(F::sub(&self.repr, &other.repr))
    }

    /// Modular multiplication: (self * other) mod p.
    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        Self::from_repr(F::mul(&self.repr, &other.repr))
    }

    /// Modular negation: (-self) mod p.
    pub fn neg(&self) -> Self {
        Self::from_repr(F::neg(&self.repr))
    }

    /// Modular inverse: self⁻¹ mod p. Returns `None` if zero.
    pub fn inv(&self) -> Option<Self> {
        super::profile::record_inv();
        F::inv(&self.repr).map(Self::from_repr)
    }

    /// Modular division: self / other mod p. Returns `None` if other is zero.
    pub fn div(&self, other: &Self) -> Option<Self> {
        Some(self.mul(&other.inv()?))
    }

    /// Modular exponentiation: self^exp mod p (constant-time).
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        Self::from_repr(F::pow(&self.repr, exp))
    }

    /// Serialize to canonical little-endian bytes (32 bytes).
    pub fn to_le_bytes(&self) -> [u8; 32] {
        F::to_le_bytes(&self.repr)
    }

    /// Deserialize from canonical little-endian bytes.
    /// Returns `None` if the value is >= the prime modulus.
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Option<Self> {
        F::from_le_bytes(bytes).map(Self::from_repr)
    }

    /// Display as canonical decimal string.
    pub fn to_decimal_string(&self) -> String {
        F::to_decimal_string(&self.repr)
    }

    /// Parse from decimal string.
    pub fn from_decimal_str(s: &str) -> Option<Self> {
        F::from_decimal_str(s).map(Self::from_repr)
    }

    /// Parse from hex string (with or without "0x" prefix).
    pub fn from_hex_str(s: &str) -> Option<Self> {
        F::from_hex_str(s).map(Self::from_repr)
    }

    /// Parse from binary string ('0'/'1' chars only).
    pub fn from_binary_str(s: &str) -> Option<Self> {
        F::from_binary_str(s).map(Self::from_repr)
    }

    /// The prime modulus as little-endian bytes.
    pub fn modulus_le_bytes() -> [u8; 32] {
        F::modulus_le_bytes()
    }
}

// ============================================================================
// BN254-specific constants (backward compat: FieldElement::ZERO, ::ONE, etc.)
// These exist on the CONCRETE type, like HashMap::new() on HashMap<K,V,RandomState>.
// ============================================================================

impl FieldElement<Bn254Fr> {
    /// Number of 64-bit limbs in the internal representation.
    pub const NUM_LIMBS: usize = 4;

    /// The zero element (0 in Montgomery form = 0).
    pub const ZERO: Self = Self {
        repr: [0; 4],
        _phantom: PhantomData,
    };

    /// The one element (1 in Montgomery form = R mod p).
    pub const ONE: Self = Self {
        repr: arithmetic::R,
        _phantom: PhantomData,
    };
}

// ============================================================================
// Serde (delegates to backend)
// ============================================================================

impl<F: FieldBackend> serde::Serialize for FieldElement<F> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        F::serde_serialize(&self.repr, serializer)
    }
}

impl<'de, F: FieldBackend> serde::Deserialize<'de> for FieldElement<F> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        F::serde_deserialize(deserializer).map(Self::from_repr)
    }
}

// ============================================================================
// Display / Debug
// ============================================================================

impl<F: FieldBackend> std::fmt::Debug for FieldElement<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Field({})", self.to_decimal_string())
    }
}

impl<F: FieldBackend> std::fmt::Display for FieldElement<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_decimal_string())
    }
}
