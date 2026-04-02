use super::PrimeId;

/// Trait defining a prime field arithmetic backend.
///
/// Each backend is a **zero-sized marker type** (e.g., `Bn254Fr`, `Bls12_381Fr`)
/// that carries all field-specific logic as associated functions. The actual data
/// lives in `Self::Repr`, the internal representation type (e.g., `[u64; 4]` in
/// Montgomery form for 254/255-bit primes, `u64` for Goldilocks).
///
/// `FieldElement<F>` wraps `F::Repr` and delegates all operations to `F`.
///
/// # Design
///
/// One `match` at the CLI/session boundary selects the backend; generics carry it
/// everywhere else. No enum per value, no trait objects, no global mutable state.
pub trait FieldBackend: Copy + Clone + Eq + std::hash::Hash + std::fmt::Debug + Sized + 'static {
    /// Internal representation of a field element.
    ///
    /// For Montgomery4 backends (BN254, BLS12-381, etc.): `[u64; 4]`
    /// For Goldilocks: `u64`
    type Repr: Copy + Clone + Eq + std::hash::Hash + Send + Sync + std::fmt::Debug + 'static;

    /// Which prime this backend implements.
    const PRIME_ID: PrimeId;

    /// Bit size of the prime modulus.
    const MODULUS_BIT_SIZE: u32;

    /// Byte size of a canonical field element (32 for 254/255/256-bit, 8 for 64-bit).
    const BYTE_SIZE: usize;

    // ========================================================================
    // Constants
    // ========================================================================

    /// The additive identity (0).
    fn zero() -> Self::Repr;

    /// The multiplicative identity (1).
    fn one() -> Self::Repr;

    // ========================================================================
    // Construction
    // ========================================================================

    /// Create from a small unsigned value.
    fn from_u64(val: u64) -> Self::Repr;

    /// Create from a signed value (negative values map to p - |val|).
    fn from_i64(val: i64) -> Self::Repr;

    /// Create from canonical little-endian limbs.
    ///
    /// For 4-limb backends, `limbs` must have at least 4 elements.
    /// For Goldilocks, only `limbs[0]` is used.
    /// Values are reduced mod p automatically.
    fn from_canonical_limbs(limbs: &[u64]) -> Self::Repr;

    /// Extract canonical little-endian limbs.
    ///
    /// Returns 4 limbs for Montgomery4 backends, 1 limb (zero-padded to 4) for Goldilocks.
    fn to_canonical_limbs(a: &Self::Repr) -> [u64; 4];

    // ========================================================================
    // Arithmetic
    // ========================================================================

    /// Modular addition: (a + b) mod p.
    fn add(a: &Self::Repr, b: &Self::Repr) -> Self::Repr;

    /// Modular subtraction: (a - b) mod p.
    fn sub(a: &Self::Repr, b: &Self::Repr) -> Self::Repr;

    /// Modular multiplication: (a * b) mod p.
    fn mul(a: &Self::Repr, b: &Self::Repr) -> Self::Repr;

    /// Modular negation: (-a) mod p.
    fn neg(a: &Self::Repr) -> Self::Repr;

    /// Modular inverse: a⁻¹ mod p. Returns `None` if a == 0.
    fn inv(a: &Self::Repr) -> Option<Self::Repr>;

    /// Check if value is zero.
    fn is_zero(a: &Self::Repr) -> bool;

    /// Modular exponentiation: base^exp mod p.
    /// Exponent is given as 4 little-endian u64 limbs.
    fn pow(base: &Self::Repr, exp: &[u64; 4]) -> Self::Repr;

    /// Constant-time conditional select: returns `a` if flag==0, `b` if flag==1.
    fn ct_select(a: &Self::Repr, b: &Self::Repr, flag: u64) -> Self::Repr;

    // ========================================================================
    // Byte serialization (canonical form, little-endian)
    // ========================================================================

    /// Serialize to canonical little-endian bytes (32 bytes for most, 8 for Goldilocks).
    fn to_le_bytes(a: &Self::Repr) -> [u8; 32];

    /// Deserialize from canonical little-endian bytes.
    /// Returns `None` if the value is >= the prime modulus.
    fn from_le_bytes(bytes: &[u8]) -> Option<Self::Repr>;

    // ========================================================================
    // String I/O
    // ========================================================================

    /// Display as canonical decimal string.
    fn to_decimal_string(a: &Self::Repr) -> String;

    /// Parse from decimal string. Returns `None` on invalid input.
    fn from_decimal_str(s: &str) -> Option<Self::Repr>;

    /// Parse from hex string (with or without "0x" prefix).
    fn from_hex_str(s: &str) -> Option<Self::Repr>;

    /// Parse from binary string ('0'/'1' chars only).
    fn from_binary_str(s: &str) -> Option<Self::Repr>;

    // ========================================================================
    // Modulus access (for serialization headers)
    // ========================================================================

    /// The prime modulus as little-endian bytes (32 bytes, zero-padded for smaller primes).
    fn modulus_le_bytes() -> [u8; 32];

    // ========================================================================
    // Serde support
    // ========================================================================

    /// Serialize the internal representation for Rust-to-Rust serde (e.g., bincode, JSON).
    /// This uses the raw internal form (Montgomery limbs) for deterministic round-trips.
    fn serde_serialize<S: serde::Serializer>(
        a: &Self::Repr,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    /// Deserialize and validate the internal representation.
    fn serde_deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::Repr, D::Error>;
}
