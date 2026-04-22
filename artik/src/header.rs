//! Artik bytecode header — the 16 bytes that precede every program.

use crate::error::ArtikError;
pub use memory::FieldFamily;

/// The 4-byte magic identifier for Artik bytecode: ASCII `ARTK`.
pub const MAGIC: [u8; 4] = *b"ARTK";

/// Current Artik bytecode version.
pub const VERSION: u16 = 1;

/// Total header size in bytes.
pub const HEADER_SIZE: usize = 16;

/// Decoded bytecode header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtikHeader {
    pub version: u16,
    pub family: FieldFamily,
    pub flags: u8,
    pub const_pool_len: u32,
    pub body_len: u32,
    pub frame_size: u32,
}

impl ArtikHeader {
    /// Encode to its 16 canonical header bytes.
    ///
    /// Layout:
    /// ```text
    /// 0..4   magic "ARTK"
    /// 4..6   version (u16 LE)
    /// 6      field family
    /// 7      flags
    /// 8..12  const_pool_len (u32 LE)
    /// 12..16 body_len (u32 LE)
    /// ```
    ///
    /// `frame_size` is not part of the 16-byte header; it is encoded as
    /// the first 4 bytes of the body so we keep the header fixed-size
    /// while still making the frame size validator-checkable before any
    /// register is read.
    pub fn encode_prefix(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6] = self.family as u8;
        out[7] = self.flags;
        out[8..12].copy_from_slice(&self.const_pool_len.to_le_bytes());
        out[12..16].copy_from_slice(&self.body_len.to_le_bytes());
        out
    }

    /// Decode the 16-byte prefix. `frame_size` is read separately from
    /// the body by the decoder.
    pub fn decode_prefix(bytes: &[u8]) -> Result<Self, ArtikError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ArtikError::UnexpectedEof {
                needed: HEADER_SIZE,
                remaining: bytes.len(),
            });
        }
        if bytes[0..4] != MAGIC {
            return Err(ArtikError::BadHeader("magic != ARTK"));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(ArtikError::BadHeader("unsupported version"));
        }
        let family =
            FieldFamily::from_u8(bytes[6]).ok_or(ArtikError::UnknownFieldFamily(bytes[6]))?;
        let flags = bytes[7];
        let const_pool_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let body_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        Ok(Self {
            version,
            family,
            flags,
            const_pool_len,
            body_len,
            frame_size: 0, // filled in by decoder from body prelude
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = ArtikHeader {
            version: VERSION,
            family: FieldFamily::BnLike256,
            flags: 0,
            const_pool_len: 128,
            body_len: 512,
            frame_size: 0,
        };
        let bytes = h.encode_prefix();
        let decoded = ArtikHeader::decode_prefix(&bytes).unwrap();
        assert_eq!(decoded.version, h.version);
        assert_eq!(decoded.family, h.family);
        assert_eq!(decoded.flags, h.flags);
        assert_eq!(decoded.const_pool_len, h.const_pool_len);
        assert_eq!(decoded.body_len, h.body_len);
    }

    #[test]
    fn header_bad_magic() {
        let bytes = [0u8; 16];
        assert!(matches!(
            ArtikHeader::decode_prefix(&bytes),
            Err(ArtikError::BadHeader(_))
        ));
    }

    #[test]
    fn header_truncated() {
        let bytes = [0u8; 8];
        assert!(matches!(
            ArtikHeader::decode_prefix(&bytes),
            Err(ArtikError::UnexpectedEof { .. })
        ));
    }
}
