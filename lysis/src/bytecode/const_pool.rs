//! Const-pool encoding per RFC §4.4.
//!
//! The pool is an ordered list of tagged entries that precedes the
//! body in a serialized Lysis program. It carries:
//!
//! - `0x00 Field` — a field constant in canonical little-endian bytes
//!   (32 for `BnLike256`, 8 for `Goldilocks64`, per the family).
//! - `0x01 String` — a length-prefixed UTF-8 string (input names,
//!   span hints).
//! - `0x02 ArtikBytecode` — a length-prefixed Artik bytecode blob
//!   used by `EmitWitnessCall`.
//! - `0x03 Span` — three `u32`s: `file_id`, `start`, `end`.
//!
//! Duplicate entries are *not* required to be merged at encode time;
//! the pool acts like an append-only list, and `LoadConst idx` or
//! `EmitConst` refers to the entry by index. Phase 2 may grow a
//! dedup pass that collapses equal field constants before serializing
//! (see RFC §4.4, final paragraph: "duplicate field constants map to
//! the same index").

use artik::FieldFamily;
use memory::field::{Bn254Fr, FieldBackend, FieldElement};

use crate::error::LysisError;

/// Tag byte for const pool entries (RFC §4.4).
pub mod tag {
    pub const FIELD: u8 = 0x00;
    pub const STRING: u8 = 0x01;
    pub const ARTIK_BYTECODE: u8 = 0x02;
    pub const SPAN: u8 = 0x03;
}

/// One decoded const pool entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstPoolEntry<F: FieldBackend = Bn254Fr> {
    /// Field-element constant. `bytes.len()` matches
    /// `family.max_const_bytes()`.
    Field(FieldElement<F>),
    /// Length-prefixed UTF-8 string.
    String(String),
    /// Length-prefixed Artik bytecode blob, verbatim.
    ArtikBytecode(Vec<u8>),
    /// Source span: `(file_id, start, end)`.
    Span { file_id: u32, start: u32, end: u32 },
}

impl<F: FieldBackend> ConstPoolEntry<F> {
    /// Raw tag byte from RFC §4.4.
    pub fn tag(&self) -> u8 {
        match self {
            Self::Field(_) => tag::FIELD,
            Self::String(_) => tag::STRING,
            Self::ArtikBytecode(_) => tag::ARTIK_BYTECODE,
            Self::Span { .. } => tag::SPAN,
        }
    }
}

/// The const pool for one program.
///
/// Entries are kept in insertion order; `LoadConst idx` and
/// `EmitConst`/`EmitWitnessCall` resolve by index into this vec.
#[derive(Debug, Clone)]
pub struct ConstPool<F: FieldBackend = Bn254Fr> {
    family: FieldFamily,
    entries: Vec<ConstPoolEntry<F>>,
}

impl<F: FieldBackend> ConstPool<F> {
    /// Construct an empty pool for the given family.
    pub fn new(family: FieldFamily) -> Self {
        Self {
            family,
            entries: Vec::new(),
        }
    }

    /// Declared family (drives field-element serialization width).
    pub fn family(&self) -> FieldFamily {
        self.family
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in insertion order.
    pub fn entries(&self) -> &[ConstPoolEntry<F>] {
        &self.entries
    }

    /// Look up an entry by index.
    pub fn get(&self, idx: usize) -> Option<&ConstPoolEntry<F>> {
        self.entries.get(idx)
    }

    /// Append an entry and return its index.
    pub fn push(&mut self, entry: ConstPoolEntry<F>) -> u32 {
        let idx = self.entries.len();
        self.entries.push(entry);
        idx as u32
    }

    /// Serialize the pool to its canonical byte representation.
    ///
    /// The count of entries is *not* included — it lives in the
    /// [`crate::header::LysisHeader`] (`const_pool_len` field). This
    /// keeps the pool layout a pure data stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let width = self.family.max_const_bytes();
        for entry in &self.entries {
            out.push(entry.tag());
            match entry {
                ConstPoolEntry::Field(fe) => {
                    let bytes = fe.to_le_bytes();
                    out.extend_from_slice(&bytes[..width]);
                }
                ConstPoolEntry::String(s) => {
                    let len = u16::try_from(s.len()).expect("string too long for u16");
                    out.extend_from_slice(&len.to_le_bytes());
                    out.extend_from_slice(s.as_bytes());
                }
                ConstPoolEntry::ArtikBytecode(blob) => {
                    let len = u32::try_from(blob.len()).expect("blob too long for u32");
                    out.extend_from_slice(&len.to_le_bytes());
                    out.extend_from_slice(blob);
                }
                ConstPoolEntry::Span {
                    file_id,
                    start,
                    end,
                } => {
                    out.extend_from_slice(&file_id.to_le_bytes());
                    out.extend_from_slice(&start.to_le_bytes());
                    out.extend_from_slice(&end.to_le_bytes());
                }
            }
        }
        out
    }

    /// Decode `count` entries from `bytes`. Returns the pool plus the
    /// number of bytes consumed. Used by [`crate::bytecode::decode`]
    /// to advance past the pool to the body.
    pub fn decode(
        bytes: &[u8],
        count: u32,
        family: FieldFamily,
    ) -> Result<(Self, usize), LysisError> {
        let mut pool = Self::new(family);
        let width = family.max_const_bytes();
        let mut pos = 0usize;
        for i in 0..count {
            if pos >= bytes.len() {
                return Err(LysisError::UnexpectedEof {
                    needed: 1,
                    remaining: 0,
                });
            }
            let tag = bytes[pos];
            pos += 1;
            let entry = match tag {
                tag::FIELD => decode_field_entry::<F>(bytes, &mut pos, width, i)?,
                tag::STRING => decode_string_entry(bytes, &mut pos)?,
                tag::ARTIK_BYTECODE => decode_artik_entry(bytes, &mut pos)?,
                tag::SPAN => decode_span_entry(bytes, &mut pos)?,
                other => {
                    return Err(LysisError::UnknownConstPoolTag {
                        tag: other,
                        at_entry: i,
                    })
                }
            };
            pool.entries.push(entry);
        }
        Ok((pool, pos))
    }
}

fn take_n<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], LysisError> {
    if *pos + n > bytes.len() {
        return Err(LysisError::UnexpectedEof {
            needed: n,
            remaining: bytes.len().saturating_sub(*pos),
        });
    }
    let out = &bytes[*pos..*pos + n];
    *pos += n;
    Ok(out)
}

fn decode_field_entry<F: FieldBackend>(
    bytes: &[u8],
    pos: &mut usize,
    width: usize,
    entry_idx: u32,
) -> Result<ConstPoolEntry<F>, LysisError> {
    let raw = take_n(bytes, pos, width)?;
    // Zero-pad up to 32 bytes so `FieldElement::from_le_bytes` works
    // for both 8-byte (Goldilocks) and 32-byte (BN-like) families.
    let mut canonical = [0u8; 32];
    canonical[..width].copy_from_slice(raw);
    let fe = FieldElement::<F>::from_le_bytes(&canonical).ok_or({
        LysisError::ConstTooLarge {
            at_entry: entry_idx,
            got: width,
            max: width,
        }
    })?;
    Ok(ConstPoolEntry::Field(fe))
}

fn decode_string_entry<F: FieldBackend>(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ConstPoolEntry<F>, LysisError> {
    let len_bytes = take_n(bytes, pos, 2)?;
    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    let body = take_n(bytes, pos, len)?;
    let s = String::from_utf8(body.to_vec()).map_err(|_| LysisError::ValidationFailed {
        rule: 0,
        location: *pos as u32,
        detail: "string entry is not valid UTF-8",
    })?;
    Ok(ConstPoolEntry::String(s))
}

fn decode_artik_entry<F: FieldBackend>(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ConstPoolEntry<F>, LysisError> {
    let len_bytes = take_n(bytes, pos, 4)?;
    let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let body = take_n(bytes, pos, len)?;
    Ok(ConstPoolEntry::ArtikBytecode(body.to_vec()))
}

fn decode_span_entry<F: FieldBackend>(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ConstPoolEntry<F>, LysisError> {
    let fid_b = take_n(bytes, pos, 4)?;
    let start_b = take_n(bytes, pos, 4)?;
    let end_b = take_n(bytes, pos, 4)?;
    Ok(ConstPoolEntry::Span {
        file_id: u32::from_le_bytes([fid_b[0], fid_b[1], fid_b[2], fid_b[3]]),
        start: u32::from_le_bytes([start_b[0], start_b[1], start_b[2], start_b[3]]),
        end: u32::from_le_bytes([end_b[0], end_b[1], end_b[2], end_b[3]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one() -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0])
    }

    #[test]
    fn empty_pool_roundtrips() {
        let pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        let bytes = pool.encode();
        assert_eq!(bytes, Vec::<u8>::new());
        let (decoded, used) =
            ConstPool::<Bn254Fr>::decode(&bytes, 0, FieldFamily::BnLike256).unwrap();
        assert_eq!(used, 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn field_entry_roundtrips_bn254() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        let idx = pool.push(ConstPoolEntry::Field(one()));
        assert_eq!(idx, 0);
        let bytes = pool.encode();
        // 1 tag + 32 value = 33 bytes.
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], tag::FIELD);
        let (decoded, used) =
            ConstPool::<Bn254Fr>::decode(&bytes, 1, FieldFamily::BnLike256).unwrap();
        assert_eq!(used, 33);
        assert_eq!(decoded.len(), 1);
        match &decoded.entries()[0] {
            ConstPoolEntry::Field(v) => assert_eq!(*v, one()),
            _ => panic!("expected Field entry"),
        }
    }

    #[test]
    fn string_entry_roundtrips() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        pool.push(ConstPoolEntry::String("hello".to_owned()));
        let bytes = pool.encode();
        // 1 tag + 2 len + 5 body.
        assert_eq!(bytes.len(), 8);
        let (decoded, _) = ConstPool::<Bn254Fr>::decode(&bytes, 1, FieldFamily::BnLike256).unwrap();
        match &decoded.entries()[0] {
            ConstPoolEntry::String(s) => assert_eq!(s, "hello"),
            _ => panic!(),
        }
    }

    #[test]
    fn artik_blob_roundtrips() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        let blob = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        pool.push(ConstPoolEntry::ArtikBytecode(blob.clone()));
        let bytes = pool.encode();
        let (decoded, _) = ConstPool::<Bn254Fr>::decode(&bytes, 1, FieldFamily::BnLike256).unwrap();
        match &decoded.entries()[0] {
            ConstPoolEntry::ArtikBytecode(b) => assert_eq!(b, &blob),
            _ => panic!(),
        }
    }

    #[test]
    fn span_entry_roundtrips() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        pool.push(ConstPoolEntry::Span {
            file_id: 3,
            start: 100,
            end: 200,
        });
        let bytes = pool.encode();
        // 1 tag + 12 payload.
        assert_eq!(bytes.len(), 13);
        let (decoded, _) = ConstPool::<Bn254Fr>::decode(&bytes, 1, FieldFamily::BnLike256).unwrap();
        match &decoded.entries()[0] {
            ConstPoolEntry::Span {
                file_id,
                start,
                end,
            } => {
                assert_eq!(*file_id, 3);
                assert_eq!(*start, 100);
                assert_eq!(*end, 200);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn mixed_pool_roundtrips() {
        let mut pool = ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256);
        pool.push(ConstPoolEntry::Field(one()));
        pool.push(ConstPoolEntry::String("x".to_owned()));
        pool.push(ConstPoolEntry::ArtikBytecode(vec![0x01, 0x02]));
        pool.push(ConstPoolEntry::Span {
            file_id: 0,
            start: 0,
            end: 1,
        });
        let bytes = pool.encode();
        let (decoded, used) =
            ConstPool::<Bn254Fr>::decode(&bytes, 4, FieldFamily::BnLike256).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded.len(), 4);
    }

    #[test]
    fn unknown_tag_fails() {
        let bad = [0xEE, 0x00, 0x00];
        let err = ConstPool::<Bn254Fr>::decode(&bad, 1, FieldFamily::BnLike256).unwrap_err();
        assert!(matches!(
            err,
            LysisError::UnknownConstPoolTag { tag: 0xEE, .. }
        ));
    }

    #[test]
    fn truncated_entry_fails() {
        let bad = [tag::FIELD, 0x01, 0x02];
        let err = ConstPool::<Bn254Fr>::decode(&bad, 1, FieldFamily::BnLike256).unwrap_err();
        assert!(matches!(err, LysisError::UnexpectedEof { .. }));
    }
}
