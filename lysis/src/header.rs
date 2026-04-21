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

use artik::FieldFamily;

use crate::error::LysisError;

/// The 4-byte magic identifier for Lysis bytecode: ASCII `LYSI`.
pub const MAGIC: [u8; 4] = *b"LYSI";

/// Current Lysis bytecode version.
pub const VERSION: u16 = 1;

/// Total header size in bytes.
pub const HEADER_SIZE: usize = 16;

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
/// Layout (16 bytes, little-endian):
///
/// ```text
/// 0..4    magic                    "LYSI"
/// 4..6    version                  u16 LE
/// 6       family                   FieldFamily as u8
/// 7       flags                    u8 (bit 0: has_witness_calls)
/// 8..12   const_pool_len           u32 LE (number of entries)
/// 12..16  body_len                 u32 LE (bytes after const pool)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LysisHeader {
    pub version: u16,
    pub family: FieldFamily,
    pub flags: u8,
    /// Number of entries (not bytes) in the const pool.
    pub const_pool_len: u32,
    /// Length in bytes of the opcode stream that follows the const pool.
    pub body_len: u32,
}

impl LysisHeader {
    /// Construct a fresh header with the current magic + version.
    pub fn new(family: FieldFamily, flags: u8, const_pool_len: u32, body_len: u32) -> Self {
        Self {
            version: VERSION,
            family,
            flags,
            const_pool_len,
            body_len,
        }
    }

    /// Serialize this header to its canonical 16-byte representation.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6] = self.family as u8;
        out[7] = self.flags;
        out[8..12].copy_from_slice(&self.const_pool_len.to_le_bytes());
        out[12..16].copy_from_slice(&self.body_len.to_le_bytes());
        out
    }

    /// Decode the 16-byte header prefix.
    ///
    /// Rejects: truncated input, wrong magic, unsupported version,
    /// unknown field family discriminant, reserved flag bits set.
    pub fn decode(bytes: &[u8]) -> Result<Self, LysisError> {
        if bytes.len() < HEADER_SIZE {
            return Err(LysisError::UnexpectedEof {
                needed: HEADER_SIZE,
                remaining: bytes.len(),
            });
        }
        let magic: [u8; 4] = bytes[0..4].try_into().expect("slice len 4 by bounds check");
        if magic != MAGIC {
            return Err(LysisError::BadMagic { found: magic });
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(LysisError::UnsupportedVersion {
                found: version,
                expected: VERSION,
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
        Ok(Self {
            version,
            family,
            flags,
            const_pool_len,
            body_len,
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
    fn header_size_is_sixteen_bytes() {
        assert_eq!(HEADER_SIZE, 16);
        assert_eq!(
            LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0)
                .encode()
                .len(),
            16
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
    fn header_rejects_truncated() {
        let bytes = [0u8; 8];
        assert!(matches!(
            LysisHeader::decode(&bytes),
            Err(LysisError::UnexpectedEof {
                needed: HEADER_SIZE,
                remaining: 8,
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
    fn encoded_layout_matches_spec() {
        let h = LysisHeader {
            version: VERSION,
            family: FieldFamily::BnLike256,
            flags: FLAG_HAS_WITNESS_CALLS,
            const_pool_len: 0x0A_0B_0C_0D,
            body_len: 0x11_22_33_44,
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
    }
}
