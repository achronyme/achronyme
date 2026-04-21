//! Deterministic structural hashing for [`crate::intern::NodeInterner`].
//!
//! Uses SipHash-2-4 with a **fixed 16-byte key** (RFC §5.4). The fixed
//! key is what makes two independent runs of Lysis produce identical
//! hashes for identical input — `std::collections::hash_map::RandomState`
//! is seeded per-process and would make the `NodeMeta.hash` field
//! differ between runs even on structurally identical DAGs, which
//! breaks the determinism test that Phase 2 gates on.
//!
//! The key is not a secret. It's a salt that binds this particular
//! interner to a stable hash space. Changing it would invalidate any
//! persisted hash state (none today), so don't change it lightly.

use std::hash::BuildHasher;

use siphasher::sip::SipHasher24;

/// 16-byte fixed key for the Lysis interner. ASCII so it's
/// recognizable in hex dumps of hash state if we ever need to
/// debug a cross-process mismatch.
const LYSIS_INTERN_KEY: [u8; 16] = *b"lysisvm-1.0-intr";

/// `BuildHasher` producing `SipHasher24` instances seeded with the
/// fixed key above. Used by [`crate::intern::NodeInterner`]'s
/// [`indexmap::IndexMap`] so node lookups are deterministic across
/// process runs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicBuildHasher;

impl BuildHasher for DeterministicBuildHasher {
    type Hasher = SipHasher24;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        let (k0_bytes, k1_bytes) = LYSIS_INTERN_KEY.split_at(8);
        let k0 = u64::from_le_bytes(k0_bytes.try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(k1_bytes.try_into().expect("8 bytes"));
        SipHasher24::new_with_keys(k0, k1)
    }
}

/// Hash an arbitrary `Hash` value with the deterministic key. Useful
/// when hashing a standalone structural key outside of an `IndexMap`
/// context (e.g., when computing `NodeMeta.hash` at insertion time).
pub fn deterministic_hash<T: std::hash::Hash>(value: &T) -> u64 {
    let builder = DeterministicBuildHasher;
    builder.hash_one(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_input_same_hash_across_builders() {
        let a = DeterministicBuildHasher.hash_one(42u64);
        let b = DeterministicBuildHasher.hash_one(42u64);
        assert_eq!(a, b);
    }

    #[test]
    fn same_input_same_hash_via_helper() {
        assert_eq!(deterministic_hash(&"hello"), deterministic_hash(&"hello"));
    }

    #[test]
    fn different_input_different_hash() {
        assert_ne!(deterministic_hash(&7u64), deterministic_hash(&8u64));
    }

    #[test]
    fn tuple_hashing_is_stable() {
        let a = deterministic_hash(&(1u32, 2u32, 3u32));
        let b = deterministic_hash(&(1u32, 2u32, 3u32));
        assert_eq!(a, b);
        assert_ne!(a, deterministic_hash(&(3u32, 2u32, 1u32)));
    }

    #[test]
    fn fixed_key_is_16_ascii_bytes() {
        // Guard: we rely on the key being stable. If someone changes
        // it, this test calls it out.
        assert_eq!(LYSIS_INTERN_KEY.len(), 16);
        assert_eq!(&LYSIS_INTERN_KEY[..], b"lysisvm-1.0-intr");
    }
}
