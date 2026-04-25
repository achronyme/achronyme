//! Lysis bytecode header — the 16 bytes that precede every Lysis program.
//!
//! Mirror of Artik's header in spirit but with its own magic and a
//! different payload: Lysis has **no** `frame_size` in the header
//! because frame sizes are per-template and encoded in `DefineTemplate`
//! opcodes inside the body (see RFC §4.3.4). In exchange, the Lysis
//! header reserves one flag bit for `has_witness_calls`, which tells
//! the runtime whether the const pool contains Artik bytecode blobs
//! (const pool tag `0x02`) and whether the executor must be initialized
//! with an Artik dispatcher.
//!
//! See RFC `§4.2 — Header layout` for the normative specification.

use memory::FieldFamily;

use crate::error::LysisError;

/// The 4-byte magic identifier for Lysis bytecode: ASCII `LYSI`.
pub const MAGIC: [u8; 4] = *b"LYSI";

/// Current Lysis bytecode version. Phase 4 added v2 to carry
/// `heap_size_hint`; the v1 layout (16 bytes, no heap field) is still
/// accepted by the decoder but `encode()` always emits v2.
pub const VERSION: u16 = 2;

/// Legacy version tag. Streams written before Phase 4 are still
/// readable; the decoder treats their absent `heap_size_hint` as 0.
pub const VERSION_V1: u16 = 1;

/// Header size for the current version (v2: 18 bytes).
pub const HEADER_SIZE: usize = HEADER_SIZE_V2;

/// Header size for v1 — preserved for backward-compatible reads.
pub const HEADER_SIZE_V1: usize = 16;

/// Header size for v2: 18 bytes (v1 16 + 2 byte `heap_size_hint`).
pub const HEADER_SIZE_V2: usize = 18;

/// Bit 0 of `flags`: the program uses `EmitWitnessCall` (opcode 0x49)
/// and therefore the const pool carries at least one Artik bytecode
/// blob (tag `0x02`). The executor must be wired with an Artik
/// dispatcher before running such a program.
pub const FLAG_HAS_WITNESS_CALLS: u8 = 1 << 0;

/// Mask of the currently defined flag bits. Any bit outside this mask
/// is a reserved bit; the decoder rejects programs that set reserved
/// bits so we can extend the header semantics without introducing a
/// version bump.
pub const FLAGS_DEFINED_MASK: u8 = FLAG_HAS_WITNESS_CALLS;

/// Decoded bytecode header.
///
/// Layout v2 (18 bytes, little-endian — current default):
///
/// ```text
/// 0..4    magic                    "LYSI"
/// 4..6    version                  u16 LE  (2)
/// 6       family                   FieldFamily as u8
/// 7       flags                    u8 (bit 0: has_witness_calls)
/// 8..12   const_pool_len           u32 LE (number of entries)
/// 12..16  body_len                 u32 LE (bytes after const pool)
/// 16..18  heap_size_hint           u16 LE (Phase 4 spill heap entries)
/// ```
///
/// Layout v1 (16 bytes) is identical to v2 minus `heap_size_hint`; a
/// v1 stream decodes with `heap_size_hint = 0`. The decoder dispatches
/// on the version field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LysisHeader {
    pub version: u16,
    pub family: FieldFamily,
    pub flags: u8,
    /// Number of entries (not bytes) in the const pool.
    pub const_pool_len: u32,
    /// Length in bytes of the opcode stream that follows the const pool.
    pub body_len: u32,
    /// Number of slots the executor must pre-allocate in the
    /// program-global heap (Phase 4 §6.2). For v1 streams the field is
    /// absent and decodes as 0; for v2 streams that don't use heap
    /// opcodes the writer also leaves this 0.
    pub heap_size_hint: u16,
}

impl LysisHeader {
    /// Construct a fresh header with the current magic + version.
    /// `heap_size_hint` defaults to 0; chain `.with_heap_size_hint(n)`
    /// to set it. The default matches existing call sites that
    /// predate Phase 4.
    pub fn new(family: FieldFamily, flags: u8, const_pool_len: u32, body_len: u32) -> Self {
        Self {
            version: VERSION,
            family,
            flags,
            const_pool_len,
            body_len,
            heap_size_hint: 0,
        }
    }

    /// Builder-style setter for `heap_size_hint`. Returning `Self`
    /// keeps the call site as a one-liner with all other fields still
    /// supplied via `new()`.
    pub fn with_heap_size_hint(mut self, hint: u16) -> Self {
        self.heap_size_hint = hint;
        self
    }

    /// Bytes this header occupies on the wire — depends on version.
    /// Always 18 for freshly-constructed headers (`new()` always sets
    /// `version = VERSION = 2`); 16 only for headers that were
    /// `decode()`d from a v1 stream and never re-stamped.
    pub fn size_in_bytes(&self) -> usize {
        match self.version {
            VERSION_V1 => HEADER_SIZE_V1,
            _ => HEADER_SIZE_V2,
        }
    }

    /// Serialize this header to canonical bytes. Always emits v2
    /// (18 bytes); v1 emission is intentionally not exposed because
    /// the canonical writer always tags new programs with the latest
    /// version. To re-emit a decoded v1 header in v1 form, callers
    /// would need a v1-specific encoder; none exists today (zero
    /// in-tree v1 streams per research report §6.7).
    pub fn encode(&self) -> [u8; HEADER_SIZE_V2] {
        let mut out = [0u8; HEADER_SIZE_V2];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6] = self.family as u8;
        out[7] = self.flags;
        out[8..12].copy_from_slice(&self.const_pool_len.to_le_bytes());
        out[12..16].copy_from_slice(&self.body_len.to_le_bytes());
        out[16..18].copy_from_slice(&self.heap_size_hint.to_le_bytes());
        out
    }

    /// Decode the header prefix. Accepts both v1 (16 bytes) and v2
    /// (18 bytes); a v1 stream produces `heap_size_hint = 0`.
    ///
    /// Rejects: truncated input, wrong magic, unsupported version
    /// (anything outside `{1, 2}`), unknown field family discriminant,
    /// reserved flag bits set.
    pub fn decode(bytes: &[u8]) -> Result<Self, LysisError> {
        // First 6 bytes (magic + version) are layout-invariant; check
        // them before deciding the dispatch size.
        if bytes.len() < 6 {
            return Err(LysisError::UnexpectedEof {
                needed: HEADER_SIZE_V1,
                remaining: bytes.len(),
            });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().expect("slice len 4 by bounds check");
        if magic != MAGIC {
            return Err(LysisError::BadMagic { found: magic });
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let needed = match version {
            VERSION_V1 => HEADER_SIZE_V1,
            VERSION => HEADER_SIZE_V2,
            _ => {
                return Err(LysisError::UnsupportedVersion {
                    found: version,
                    expected: VERSION,
                })
            }
        };
        if bytes.len() < needed {
            return Err(LysisError::UnexpectedEof {
                needed,
                remaining: bytes.len(),
            });
        }

        let family = FieldFamily::from_u8(bytes[6])
            .ok_or(LysisError::UnknownFieldFamily { tag: bytes[6] })?;
        let flags = bytes[7];
        if flags & !FLAGS_DEFINED_MASK != 0 {
            return Err(LysisError::ReservedFlagSet { flags });
        }
        let const_pool_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let body_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let heap_size_hint = if version == VERSION_V1 {
            0
        } else {
            u16::from_le_bytes([bytes[16], bytes[17]])
        };
        Ok(Self {
            version,
            family,
            flags,
            const_pool_len,
            body_len,
            heap_size_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_lysi_ascii() {
        assert_eq!(&MAGIC, b"LYSI");
    }

    #[test]
    fn header_size_is_eighteen_bytes_v2() {
        assert_eq!(HEADER_SIZE, 18);
        assert_eq!(HEADER_SIZE_V2, 18);
        assert_eq!(HEADER_SIZE_V1, 16);
        assert_eq!(
            LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0)
                .encode()
                .len(),
            18
        );
    }

    #[test]
    fn header_roundtrips_bn254() {
        let h = LysisHeader::new(FieldFamily::BnLike256, 0, 42, 1024);
        let bytes = h.encode();
        let decoded = LysisHeader::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_roundtrips_goldilocks() {
        let h = LysisHeader::new(FieldFamily::Goldilocks64, FLAG_HAS_WITNESS_CALLS, 7, 512);
        let bytes = h.encode();
        let decoded = LysisHeader::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_rejects_pre_magic_truncation() {
        // Fewer than 6 bytes: can't even parse magic + version.
        let bytes = [0u8; 5];
        assert!(matches!(
            LysisHeader::decode(&bytes),
            Err(LysisError::UnexpectedEof {
                needed: HEADER_SIZE_V1,
                remaining: 5,
            })
        ));
    }

    #[test]
    fn header_rejects_v2_truncated_below_eighteen() {
        // Magic + version=2 but only 17 bytes total — one short of v2.
        let bytes = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).encode();
        let truncated = &bytes[..17];
        assert!(matches!(
            LysisHeader::decode(truncated),
            Err(LysisError::UnexpectedEof {
                needed: HEADER_SIZE_V2,
                remaining: 17,
            })
        ));
    }

    #[test]
    fn header_rejects_bad_magic() {
        let bytes = [0u8; 16];
        let err = LysisHeader::decode(&bytes).unwrap_err();
        assert!(matches!(err, LysisError::BadMagic { .. }));
    }

    #[test]
    fn header_rejects_wrong_magic_but_right_size() {
        let mut bytes = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).encode();
        bytes[0] = b'A'; // Corrupt the first magic byte.
        assert!(matches!(
            LysisHeader::decode(&bytes),
            Err(LysisError::BadMagic { .. })
        ));
    }

    #[test]
    fn header_rejects_unsupported_version() {
        let mut bytes = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).encode();
        // 99 is neither v1 (1) nor v2 (2).
        bytes[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert!(matches!(
            LysisHeader::decode(&bytes),
            Err(LysisError::UnsupportedVersion {
                found: 99,
                expected: VERSION,
            })
        ));
    }

    #[test]
    fn v1_stream_decodes_with_zero_heap_hint() {
        // Hand-construct a 16-byte v1 stream and confirm the v2
        // decoder reads it with heap_size_hint = 0 (backward-compat
        // contract from research report §6.7).
        let mut bytes = [0u8; HEADER_SIZE_V1];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION_V1.to_le_bytes());
        bytes[6] = FieldFamily::BnLike256 as u8;
        bytes[7] = 0;
        bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&64u32.to_le_bytes());
        let decoded = LysisHeader::decode(&bytes).unwrap();
        assert_eq!(decoded.version, VERSION_V1);
        assert_eq!(decoded.family, FieldFamily::BnLike256);
        assert_eq!(decoded.const_pool_len, 7);
        assert_eq!(decoded.body_len, 64);
        assert_eq!(decoded.heap_size_hint, 0);
        assert_eq!(decoded.size_in_bytes(), HEADER_SIZE_V1);
    }

    #[test]
    fn v2_roundtrips_heap_hint() {
        let h = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).with_heap_size_hint(2_500);
        assert_eq!(h.heap_size_hint, 2_500);
        let bytes = h.encode();
        assert_eq!(bytes.len(), HEADER_SIZE_V2);
        let decoded = LysisHeader::decode(&bytes).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.heap_size_hint, 2_500);
    }

    #[test]
    fn v2_max_heap_hint_roundtrips() {
        // Boundary: u16::MAX is the documented maximum (research
        // report §6.2). Make sure encode/decode preserves it.
        let h = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).with_heap_size_hint(u16::MAX);
        let decoded = LysisHeader::decode(&h.encode()).unwrap();
        assert_eq!(decoded.heap_size_hint, u16::MAX);
    }

    #[test]
    fn header_rejects_unknown_family() {
        let mut bytes = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).encode();
        bytes[6] = 0xFF;
        assert!(matches!(
            LysisHeader::decode(&bytes),
            Err(LysisError::UnknownFieldFamily { tag: 0xFF })
        ));
    }

    #[test]
    fn header_rejects_reserved_flag_bits() {
        let mut bytes = LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0).encode();
        bytes[7] = 0b1000_0000;
        assert!(matches!(
            LysisHeader::decode(&bytes),
            Err(LysisError::ReservedFlagSet { flags: 0b1000_0000 })
        ));
    }

    #[test]
    fn header_accepts_defined_flag_bits() {
        let bytes = LysisHeader::new(FieldFamily::BnLike256, FLAG_HAS_WITNESS_CALLS, 0, 0).encode();
        let decoded = LysisHeader::decode(&bytes).unwrap();
        assert_eq!(decoded.flags, FLAG_HAS_WITNESS_CALLS);
    }

    #[test]
    fn encoded_layout_matches_v2_spec() {
        let h = LysisHeader {
            version: VERSION,
            family: FieldFamily::BnLike256,
            flags: FLAG_HAS_WITNESS_CALLS,
            const_pool_len: 0x0A_0B_0C_0D,
            body_len: 0x11_22_33_44,
            heap_size_hint: 0xCAFE,
        };
        let bytes = h.encode();
        assert_eq!(&bytes[0..4], b"LYSI");
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), VERSION);
        assert_eq!(bytes[6], FieldFamily::BnLike256 as u8);
        assert_eq!(bytes[7], FLAG_HAS_WITNESS_CALLS);
        assert_eq!(
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            0x0A_0B_0C_0D,
        );
        assert_eq!(
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            0x11_22_33_44,
        );
        assert_eq!(u16::from_le_bytes([bytes[16], bytes[17]]), 0xCAFE);
    }
}
