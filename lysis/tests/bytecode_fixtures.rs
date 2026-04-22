//! Phase 0 hand-written bytecode fixtures for Lysis.
//!
//! Three fixtures — `Num2Bits(8)`, a Poseidon round, and a SHA-256
//! round — are built as raw `Vec<u8>` so the Phase 1 decoder + Phase 2
//! validator have something credible to exercise from day one. The
//! bodies are not executable yet (there is no interpreter yet), but
//! they follow the opcode layout of RFC §4.3 so Phase 1 can decode
//! them without rewriting the fixtures.
//!
//! What Phase 0 actually verifies here (per RFC §10 "Exit criteria:
//! fixtures parse"):
//!
//! 1. Each fixture's 16-byte header decodes via `LysisHeader::decode`.
//! 2. The declared `const_pool_len` matches the number of entries
//!    actually present (per the tag-dispatched reader below).
//! 3. The declared `body_len` matches the remaining byte count.
//!
//! Full opcode-by-opcode validation is Phase 2 work.

use lysis::{LysisHeader, HEADER_SIZE};
use memory::FieldFamily;

// ---------------------------------------------------------------------
// Opcode + tag constants (mirrors of RFC §4.3 + §4.4).
//
// These are duplicated here, not imported from `lysis`, because the
// public `Opcode` enum lands in Phase 1. Keeping them as plain `u8`
// constants here is intentional: it documents the byte layout of each
// fixture and flags drift between this file and the eventual enum
// (a compile-time consistency check will be added in Phase 1).
// ---------------------------------------------------------------------

// §4.3.1 Capture / environment
const OP_LOAD_CAPTURE: u8 = 0x01;
const OP_LOAD_CONST: u8 = 0x02;
const OP_LOAD_INPUT: u8 = 0x03;

// §4.3.2 Control flow
const OP_HALT: u8 = 0x13;

// §4.3.5 IR emission
const OP_EMIT_ADD: u8 = 0x41;
const OP_EMIT_MUL: u8 = 0x43;
const OP_EMIT_DECOMPOSE: u8 = 0x46;
const OP_EMIT_RANGE_CHECK: u8 = 0x48;

// §4.4 Const pool tags
const TAG_FIELD_CONST: u8 = 0x00;
const TAG_STRING: u8 = 0x01;
// const TAG_ARTIK_BYTECODE: u8 = 0x02;  // unused in Phase 0 fixtures.
// const TAG_SPAN: u8 = 0x03;

// Input visibility bits for OP_LOAD_INPUT (§4.3.1).
const VIS_PUBLIC: u8 = 0;
const VIS_WITNESS: u8 = 1;

// ---------------------------------------------------------------------
// Const pool encoders
// ---------------------------------------------------------------------

/// Encode a BnLike256 field constant entry: `[tag=0x00][32 bytes LE]`.
fn push_field_const_bn254(pool: &mut Vec<u8>, limbs: [u64; 4]) {
    pool.push(TAG_FIELD_CONST);
    for limb in limbs {
        pool.extend_from_slice(&limb.to_le_bytes());
    }
}

/// Encode a string entry: `[tag=0x01][len: u16 LE][bytes]`.
fn push_string(pool: &mut Vec<u8>, s: &str) {
    pool.push(TAG_STRING);
    pool.extend_from_slice(&(s.len() as u16).to_le_bytes());
    pool.extend_from_slice(s.as_bytes());
}

/// Stitch a header + const pool + body into the final byte vector.
fn assemble(
    family: FieldFamily,
    flags: u8,
    pool: Vec<u8>,
    body: Vec<u8>,
    pool_entries: u32,
) -> Vec<u8> {
    let header = LysisHeader::new(family, flags, pool_entries, body.len() as u32);
    let mut out = Vec::with_capacity(HEADER_SIZE + pool.len() + body.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&pool);
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------------
// Fixture 1: Num2Bits(8)
// ---------------------------------------------------------------------
//
// Circom reference:
//
//   template Num2Bits(n) {
//       signal input in;
//       signal output out[n];
//       var lc1 = 0;
//       for (var i = 0; i < n; i++) {
//           out[i] <-- (in >> i) & 1;
//           out[i] * (out[i] - 1) === 0;
//           lc1 += out[i] * 2**i;
//       }
//       lc1 === in;
//   }
//
// Lysis lowered sketch (n is a capture; fixture freezes n = 8):
//
//   LoadCapture  r0, captures[0]            ; r0 = n = 8 (sanity only)
//   LoadInput    r1, "in", witness          ; r1 = in (public input)
//   EmitDecompose r2, r1, 8                 ; r2 = base of out[0..8]
//   EmitRangeCheck r2,  1                   ; each out[i] ∈ {0,1}
//   EmitRangeCheck r3,  1
//   EmitRangeCheck r4,  1
//   EmitRangeCheck r5,  1
//   EmitRangeCheck r6,  1
//   EmitRangeCheck r7,  1
//   EmitRangeCheck r8,  1
//   EmitRangeCheck r9,  1
//   Halt
//
// The 8 output SSA vars produced by `EmitDecompose` are the 8
// consecutive registers starting at `dst_arr` (r2..r9). Phase 1 may
// refine this convention (e.g., explicit register allocation per
// output); for Phase 0 it only needs to decode.
#[rustfmt::skip]
fn num2bits_8() -> Vec<u8> {
    let mut pool = Vec::new();
    push_string(&mut pool, "in");

    let body = vec![
        OP_LOAD_CAPTURE, /* dst */ 0, /* idx LE */ 0, 0,
        OP_LOAD_INPUT, /* dst */ 1, /* name_idx LE */ 0, 0, VIS_WITNESS,
        OP_EMIT_DECOMPOSE, /* dst_arr */ 2, /* src */ 1, /* n_bits */ 8,
        OP_EMIT_RANGE_CHECK, 2, 1,
        OP_EMIT_RANGE_CHECK, 3, 1,
        OP_EMIT_RANGE_CHECK, 4, 1,
        OP_EMIT_RANGE_CHECK, 5, 1,
        OP_EMIT_RANGE_CHECK, 6, 1,
        OP_EMIT_RANGE_CHECK, 7, 1,
        OP_EMIT_RANGE_CHECK, 8, 1,
        OP_EMIT_RANGE_CHECK, 9, 1,
        OP_HALT,
    ];
    assemble(FieldFamily::BnLike256, 0, pool, body, /* entries */ 1)
}

// ---------------------------------------------------------------------
// Fixture 2: Poseidon round (t=3, α=5)
// ---------------------------------------------------------------------
//
// One full round of Poseidon permutation:
//   1. Add round constants:    s_i += C_i      (i = 0..t)
//   2. S-box (α=5):            s_i = s_i^5
//   3. MDS mix:                skipped — requires t*t matrix
//                              multiplications; omitted from this
//                              fixture so the body stays readable.
//                              The real Poseidon ends each round with
//                              a linear mix; Phase 3 will emit that.
//
// Registers:
//   r0,r1,r2       — current state slots s0,s1,s2
//   r3,r4,r5       — round constants C0,C1,C2
//   r6..r8         — s_i + C_i
//   r9..r11        — (s+C)^2
//   r12..r14       — (s+C)^4
//   r15..r17       — (s+C)^5 (post-S-box state, pre-MDS)
//
// Const pool: 3 field constants (C0, C1, C2) + 3 strings ("s0","s1","s2").
#[rustfmt::skip]
fn poseidon_round() -> Vec<u8> {
    let mut pool = Vec::new();
    // Entries 0..3: round constants (dummy values; real Poseidon uses
    // the published MDS-compatible constants).
    push_field_const_bn254(&mut pool, [1, 0, 0, 0]);
    push_field_const_bn254(&mut pool, [2, 0, 0, 0]);
    push_field_const_bn254(&mut pool, [3, 0, 0, 0]);
    // Entries 3..6: input names.
    push_string(&mut pool, "s0");
    push_string(&mut pool, "s1");
    push_string(&mut pool, "s2");

    let body = vec![
        // Load inputs.
        OP_LOAD_INPUT, 0, 3, 0, VIS_WITNESS,
        OP_LOAD_INPUT, 1, 4, 0, VIS_WITNESS,
        OP_LOAD_INPUT, 2, 5, 0, VIS_WITNESS,
        // Load round constants.
        OP_LOAD_CONST, 3, 0, 0,
        OP_LOAD_CONST, 4, 1, 0,
        OP_LOAD_CONST, 5, 2, 0,
        // Add round constants.
        OP_EMIT_ADD, 6, 0, 3,
        OP_EMIT_ADD, 7, 1, 4,
        OP_EMIT_ADD, 8, 2, 5,
        // S-box α=5: (x^2) * (x^2) * x = x^5.
        OP_EMIT_MUL, 9, 6, 6,
        OP_EMIT_MUL, 10, 7, 7,
        OP_EMIT_MUL, 11, 8, 8,
        OP_EMIT_MUL, 12, 9, 9,
        OP_EMIT_MUL, 13, 10, 10,
        OP_EMIT_MUL, 14, 11, 11,
        OP_EMIT_MUL, 15, 12, 6,
        OP_EMIT_MUL, 16, 13, 7,
        OP_EMIT_MUL, 17, 14, 8,
        OP_HALT,
    ];
    assemble(FieldFamily::BnLike256, 0, pool, body, /* entries */ 6)
}

// ---------------------------------------------------------------------
// Fixture 3: SHA-256 round (single iteration of the main loop)
// ---------------------------------------------------------------------
//
// Sketch of one of the 64 main-loop iterations:
//
//     T1 = h + Σ1(e) + Ch(e,f,g) + K_t + W_t
//     T2 = Σ0(a) + Maj(a,b,c)
//     h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2
//
// The full round needs rotations, bit decomposition, and bitwise logic
// which have dedicated opcodes (Phase 1 will flesh those out). For
// Phase 0 we encode a compressed stand-in: field-add chain over the 8
// state words + K_t + W_t, enough to exercise register allocation +
// const pool indexing without defining bit-level opcodes yet.
//
// Registers:
//   r0..r7   — current state (a..h)
//   r8       — W_t (message schedule entry)
//   r9       — K_t (round constant)
//   r10..r13 — partial sums
#[rustfmt::skip]
fn sha256_round() -> Vec<u8> {
    let mut pool = Vec::new();
    // K_t round constant (dummy).
    push_field_const_bn254(&mut pool, [0x428a_2f98, 0, 0, 0]);
    // 8 state input names + W_t.
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "w"] {
        push_string(&mut pool, name);
    }

    let body = vec![
        // Load 8 state words (public — they're the result of the previous round).
        OP_LOAD_INPUT, 0, 1, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 1, 2, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 2, 3, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 3, 4, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 4, 5, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 5, 6, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 6, 7, 0, VIS_PUBLIC,
        OP_LOAD_INPUT, 7, 8, 0, VIS_PUBLIC,
        // Load W_t (witness).
        OP_LOAD_INPUT, 8, 9, 0, VIS_WITNESS,
        // Load K_t round constant.
        OP_LOAD_CONST, 9, 0, 0,
        // Compressed round: sum = h + K_t + W_t (+ others omitted).
        OP_EMIT_ADD, 10, 7, 9,
        OP_EMIT_ADD, 11, 10, 8,
        OP_EMIT_ADD, 12, 11, 4, // + e (Σ1 compressed)
        OP_EMIT_ADD, 13, 12, 0, // + a (Σ0 + Maj compressed)
        OP_HALT,
    ];
    assemble(FieldFamily::BnLike256, 0, pool, body, /* entries */ 10)
}

// ---------------------------------------------------------------------
// Const-pool scanner (Phase 0 — replaced by `ConstPool::decode` in Phase 1)
// ---------------------------------------------------------------------

/// Walk the const pool by tag, returning the offset just past the last
/// entry. Used only to sanity-check that each fixture's declared
/// `const_pool_len` matches what the bytes actually contain.
fn const_pool_span(bytes: &[u8], n_entries: u32, family: FieldFamily) -> Result<usize, String> {
    let mut pos = 0usize;
    for i in 0..n_entries {
        if pos >= bytes.len() {
            return Err(format!(
                "entry {i} out of range at pos={pos} len={}",
                bytes.len()
            ));
        }
        let tag = bytes[pos];
        pos += 1;
        match tag {
            TAG_FIELD_CONST => {
                let width = family.max_const_bytes();
                if pos + width > bytes.len() {
                    return Err(format!(
                        "field const entry {i} truncated at pos={pos}, width={width}"
                    ));
                }
                pos += width;
            }
            TAG_STRING => {
                if pos + 2 > bytes.len() {
                    return Err(format!("string entry {i} truncated at pos={pos}"));
                }
                let len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
                pos += 2 + len;
                if pos > bytes.len() {
                    return Err(format!("string body of entry {i} overruns buffer"));
                }
            }
            other => return Err(format!("unknown tag {other:#04x} at entry {i}")),
        }
    }
    Ok(pos)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

fn check_fixture_parses(name: &str, fixture: &[u8]) {
    // Header decodes.
    let header = LysisHeader::decode(fixture)
        .unwrap_or_else(|e| panic!("fixture {name}: header decode failed: {e}"));

    // Const pool spans the declared number of entries and matches the body offset.
    let pool_start = HEADER_SIZE;
    let pool_bytes = &fixture[pool_start..];
    let pool_len = const_pool_span(pool_bytes, header.const_pool_len, header.family)
        .unwrap_or_else(|e| panic!("fixture {name}: const pool walk failed: {e}"));

    let body_start = pool_start + pool_len;
    let remaining = fixture.len() - body_start;
    assert_eq!(
        remaining, header.body_len as usize,
        "fixture {name}: body_len ({}) != actual remaining bytes ({})",
        header.body_len, remaining
    );

    // Body has at least a `Halt`.
    assert!(
        header.body_len > 0,
        "fixture {name}: body must not be empty"
    );
}

#[test]
fn num2bits_8_header_and_pool_parse() {
    check_fixture_parses("num2bits_8", &num2bits_8());
}

#[test]
fn poseidon_round_header_and_pool_parse() {
    check_fixture_parses("poseidon_round", &poseidon_round());
}

#[test]
fn sha256_round_header_and_pool_parse() {
    check_fixture_parses("sha256_round", &sha256_round());
}

#[test]
fn all_fixtures_declare_bn_like_256_family() {
    for (name, f) in [
        ("num2bits_8", num2bits_8()),
        ("poseidon_round", poseidon_round()),
        ("sha256_round", sha256_round()),
    ] {
        let header = LysisHeader::decode(&f).unwrap();
        assert_eq!(
            header.family,
            FieldFamily::BnLike256,
            "fixture {name} has non-bn254 family"
        );
    }
}

#[test]
fn fixtures_have_distinct_bytes() {
    // A trivial smoke test: the three fixtures must not accidentally
    // be byte-identical (easy bug when copy-pasting).
    let n = num2bits_8();
    let p = poseidon_round();
    let s = sha256_round();
    assert_ne!(n, p, "num2bits == poseidon bytes");
    assert_ne!(p, s, "poseidon == sha256 bytes");
    assert_ne!(n, s, "num2bits == sha256 bytes");
}

#[test]
fn fixture_body_contains_halt_at_end() {
    for (name, bytes) in [
        ("num2bits_8", num2bits_8()),
        ("poseidon_round", poseidon_round()),
        ("sha256_round", sha256_round()),
    ] {
        assert_eq!(
            *bytes.last().unwrap(),
            OP_HALT,
            "fixture {name} must end in OP_HALT"
        );
    }
}
