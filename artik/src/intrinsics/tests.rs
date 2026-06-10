use super::limbs::*;
use super::*;
use crate::ir::Instr;
use crate::program::{Program, Subprogram};
use memory::FieldFamily;

// ── Reference oracles ───────────────────────────────────────────
//
// Literal ports of the circom-ecdsa `bigint_func` reference
// algorithms, digit by digit, used to fuzz the native limb math.
// They intentionally mirror the source structure (SplitFn carries,
// schoolbook long division with the scaled short_div estimate)
// rather than calling any code under test.

fn ref_split3(x: u128, n: u32) -> [u64; 3] {
    let mask = (1u128 << n) - 1;
    [
        (x & mask) as u64,
        ((x >> n) & mask) as u64,
        ((x >> (2 * n)) & mask) as u64,
    ]
}

fn ref_prod(n: u32, k: usize, a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut prod_val = vec![0u128; 2 * k - 1];
    for (i, slot) in prod_val.iter_mut().enumerate() {
        if i < k {
            for ai in 0..=i {
                *slot += a[ai] as u128 * b[i - ai] as u128;
            }
        } else {
            for ai in (i - k + 1)..k {
                *slot += a[ai] as u128 * b[i - ai] as u128;
            }
        }
    }
    let split: Vec<[u64; 3]> = prod_val.iter().map(|&v| ref_split3(v, n)).collect();
    let mask = (1u128 << n) - 1;
    let mut out = vec![0u64; 2 * k];
    let mut carry = vec![0u64; 2 * k];
    out[0] = split[0][0];
    if 2 * k - 1 > 1 {
        let sum = split[0][1] as u128 + split[1][0] as u128;
        out[1] = (sum & mask) as u64;
        carry[1] = (sum >> n) as u64;
    }
    if 2 * k - 1 > 2 {
        for i in 2..2 * k - 1 {
            let sum = split[i][0] as u128
                + split[i - 1][1] as u128
                + split[i - 2][2] as u128
                + carry[i - 1] as u128;
            out[i] = (sum & mask) as u64;
            carry[i] = (sum >> n) as u64;
        }
        out[2 * k - 1] = split[2 * k - 2][1] + split[2 * k - 3][2] + carry[2 * k - 2];
    }
    out
}

fn ref_long_gt(k: usize, a: &[u64], b: &[u64]) -> bool {
    for i in (0..k).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false
}

fn ref_long_sub(n: u32, k: usize, a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut diff = vec![0u64; k];
    let mut borrow = vec![0u64; k];
    for i in 0..k {
        let prev = if i == 0 { 0 } else { borrow[i - 1] };
        if a[i] as u128 >= b[i] as u128 + prev as u128 {
            diff[i] = a[i] - b[i] - prev;
        } else {
            diff[i] = ((1u128 << n) + a[i] as u128 - b[i] as u128 - prev as u128) as u64;
            borrow[i] = 1;
        }
    }
    diff
}

fn ref_long_scalar_mult(n: u32, k: usize, a: u64, b: &[u64]) -> Vec<u64> {
    let mask = (1u128 << n) - 1;
    let mut out = vec![0u64; k + 2];
    for i in 0..k {
        let temp = out[i] as u128 + a as u128 * b[i] as u128;
        out[i] = (temp & mask) as u64;
        out[i + 1] += (temp >> n) as u64;
    }
    out
}

fn ref_short_div_norm(n: u32, k: usize, a: &[u64], b: &[u64]) -> u64 {
    let max_digit = (1u128 << n) - 1;
    let mut qhat = ((a[k] as u128) * (1u128 << n) + a[k - 1] as u128) / b[k - 1] as u128;
    if qhat > max_digit {
        qhat = max_digit;
    }
    let mut mult = ref_long_scalar_mult(n, k, qhat as u64, b);
    if ref_long_gt(k + 1, &mult, a) {
        mult = ref_long_sub(n, k + 1, &mult, b);
        if ref_long_gt(k + 1, &mult, a) {
            qhat as u64 - 2
        } else {
            qhat as u64 - 1
        }
    } else {
        qhat as u64
    }
}

fn ref_short_div(n: u32, k: usize, a: &[u64], b: &[u64]) -> u64 {
    let scale = (1u64 << n) / (1 + b[k - 1]);
    let norm_a = ref_long_scalar_mult(n, k + 1, scale, a);
    let norm_b = ref_long_scalar_mult(n, k, scale, b);
    if norm_b[k] != 0 {
        ref_short_div_norm(n, k + 1, &norm_a, &norm_b)
    } else {
        ref_short_div_norm(n, k, &norm_a, &norm_b)
    }
}

/// Reference long_div: quotient (m + 1 digits) and remainder (k digits).
fn ref_long_div(n: u32, k: usize, m: usize, a: &[u64], b: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let mut remainder = vec![0u64; m + k + 2];
    remainder[..m + k].copy_from_slice(&a[..m + k]);
    let mut quotient = vec![0u64; m + 1];
    for i in (0..=m).rev() {
        let mut dividend = vec![0u64; k + 2];
        if i == m {
            dividend[..k].copy_from_slice(&remainder[m..m + k]);
        } else {
            for j in (0..=k).rev() {
                dividend[j] = remainder[j + i];
            }
        }
        quotient[i] = ref_short_div(n, k, &dividend, b);
        let mult_shift = ref_long_scalar_mult(n, k, quotient[i], b);
        let mut subtrahend = vec![0u64; m + k + 2];
        for j in 0..=k {
            if i + j < m + k {
                subtrahend[i + j] = mult_shift[j];
            }
        }
        remainder = ref_long_sub(n, m + k, &remainder, &subtrahend);
        remainder.resize(m + k + 2, 0);
    }
    (quotient, remainder[..k].to_vec())
}

/// Reference mod_exp loop on digit vectors.
fn ref_mod_exp(n: u32, k: usize, a: &[u64], p: &[u64], e: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; k];
    out[0] = 1;
    for i in (0..n as u64 * k as u64).rev() {
        let bit = (e[(i / n as u64) as usize] >> (i % n as u64)) & 1;
        if bit == 1 {
            let mut temp = ref_prod(n, k, &out, a);
            temp.resize(2 * k, 0);
            let (_, r) = ref_long_div(n, k, k, &temp, p);
            out = r;
        }
        if i > 0 {
            let mut temp = ref_prod(n, k, &out, &out);
            temp.resize(2 * k, 0);
            let (_, r) = ref_long_div(n, k, k, &temp, p);
            out = r;
        }
    }
    out
}

/// Deterministic xorshift64* for fuzz vectors — no host entropy.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn digit(&mut self, n: u32) -> u64 {
        if n == 64 {
            self.next()
        } else {
            self.next() & ((1 << n) - 1)
        }
    }
}

// ── Limb math vs the reference oracles ──────────────────────────

#[test]
fn prod_matches_reference_across_widths() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for &n in &[4u32, 8, 16, 32, 63] {
        for k in 2usize..=4 {
            for _ in 0..50 {
                let a: Vec<u64> = (0..k).map(|_| rng.digit(n)).collect();
                let b: Vec<u64> = (0..k).map(|_| rng.digit(n)).collect();
                let native = prod_digits(n, k as u32, &a, &b).expect("in-range");
                let reference = ref_prod(n, k, &a, &b);
                assert_eq!(native, reference, "prod n={n} k={k} a={a:?} b={b:?}");
            }
        }
    }
}

#[test]
fn longdiv_matches_reference_across_widths() {
    let mut rng = Rng(0xDEADBEEFCAFEF00D);
    for &n in &[4u32, 8, 16, 32, 63] {
        for k in 1usize..=4 {
            for m in k..=k + 2 {
                for _ in 0..40 {
                    let a: Vec<u64> = (0..m + k).map(|_| rng.digit(n)).collect();
                    let mut b: Vec<u64> = (0..k).map(|_| rng.digit(n)).collect();
                    if b[k - 1] == 0 {
                        b[k - 1] = 1;
                    }
                    let (nq, nr) = longdiv_digits(n, k as u32, m as u32, &a, &b).expect("in-range");
                    let (rq, rr) = ref_long_div(n, k, m, &a, &b);
                    assert_eq!(nq, rq, "quotient n={n} k={k} m={m} a={a:?} b={b:?}");
                    assert_eq!(nr, rr, "remainder n={n} k={k} m={m} a={a:?} b={b:?}");
                }
            }
        }
    }
}

#[test]
fn modexp_matches_reference_across_widths() {
    let mut rng = Rng(0x1234567890ABCDEF);
    for &n in &[4u32, 8, 16] {
        for k in 2usize..=3 {
            for _ in 0..8 {
                let a: Vec<u64> = (0..k).map(|_| rng.digit(n)).collect();
                let e: Vec<u64> = (0..k).map(|_| rng.digit(n)).collect();
                let mut p: Vec<u64> = (0..k).map(|_| rng.digit(n)).collect();
                if p[k - 1] == 0 {
                    p[k - 1] = 1;
                }
                let native = modexp_digits(n, k as u32, &a, &p, &e).expect("in-range");
                let reference = ref_mod_exp(n, k, &a, &p, &e);
                assert_eq!(
                    native, reference,
                    "modexp n={n} k={k} a={a:?} p={p:?} e={e:?}"
                );
            }
        }
    }
}

#[test]
fn modinv_secp256k1_vector_verifies() {
    // n = 64, k = 4 — the production shape. p = secp256k1 field prime.
    let p: [u64; 4] = [
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];
    let a: [u64; 4] = [
        0x59F2815B16F81798,
        0x029BFCDB2DCE28D9,
        0x55A06295CE870B07,
        0x79BE667EF9DCBBAC,
    ]; // secp256k1 generator x — known invertible
    let inv = modinv_digits(64, 4, &a, &p).expect("in-range invertible");
    // Verify a * inv mod p == 1 with the same limb machinery.
    let mut wide = prod_digits(64, 4, &a, &inv).expect("in-range");
    wide.resize(8, 0);
    let (_, r) = longdiv_digits(64, 4, 4, &wide, &p).expect("in-range");
    assert_eq!(r, vec![1, 0, 0, 0]);
}

#[test]
fn modinv_zero_and_p_multiple_collapse_to_zero() {
    let p: [u64; 4] = [
        0xFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];
    // Literal zero digits: the reference's isZero early exit.
    assert_eq!(
        modinv_digits(64, 4, &[0, 0, 0, 0], &p).expect("in-range"),
        vec![0, 0, 0, 0]
    );
    // a == p (nonzero digits, zero residue): the reference's Fermat
    // loop collapses to zero after the first reduction.
    assert_eq!(
        modinv_digits(64, 4, &p, &p).expect("in-range"),
        vec![0, 0, 0, 0]
    );
}

#[test]
fn guards_decline_out_of_contract_inputs() {
    // Digit out of range for n = 4.
    assert!(prod_digits(4, 2, &[16, 0], &[1, 0]).is_none());
    // Divisor leading digit zero.
    assert!(longdiv_digits(8, 2, 2, &[1, 2, 3, 4], &[5, 0]).is_none());
    // Modulus below 2 declines the inverse.
    assert!(modinv_digits(8, 2, &[3, 0], &[1, 0]).is_none());
    // Too few digits supplied.
    assert!(prod_digits(8, 4, &[1, 2], &[3, 4]).is_none());
    // Single-register shapes decline: the reference product truncates
    // its top digit at k = 1 and only the interpreted body reproduces
    // that.
    assert!(prod_digits(8, 1, &[10], &[7]).is_none());
    assert!(modexp_digits(8, 1, &[3], &[7], &[5]).is_none());
    assert!(modinv_digits(8, 1, &[3], &[7]).is_none());
}

// ── Annotation wire format + validation ─────────────────────────

fn annotated_two_sub_program(intrinsic: Intrinsic) -> Program {
    // Entry calls subprogram 1; subprogram 1 has the ModInv-shaped
    // signature (two scalars, two field arrays, one field-array
    // return).
    use crate::ir::{ElemT, RegType};
    let entry = Subprogram {
        frame_size: 8,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![Instr::Return { srcs: Vec::new() }],
    };
    let callee = Subprogram {
        frame_size: 8,
        params: vec![
            RegType::Field,
            RegType::Field,
            RegType::Array(ElemT::Field),
            RegType::Array(ElemT::Field),
        ],
        returns: vec![RegType::Array(ElemT::Field)],
        body: vec![
            Instr::AllocArray {
                dst: 4,
                len: 4,
                elem: ElemT::Field,
            },
            Instr::Return { srcs: vec![4] },
        ],
    };
    let mut prog =
        Program::from_subprograms(FieldFamily::BnLike256, Vec::new(), vec![entry, callee]);
    prog.intrinsics.push(IntrinsicAnnotation {
        func_id: 1,
        intrinsic,
    });
    prog
}

#[test]
fn annotation_round_trips_through_bytecode() {
    let intrinsic = Intrinsic::ModInv {
        n: 4,
        k: 2,
        ret_len: 4,
    };
    let prog = annotated_two_sub_program(intrinsic);
    let bytes = crate::bytecode::encode(&prog);
    let decoded = crate::bytecode::decode(&bytes, Some(FieldFamily::BnLike256)).expect("decode");
    assert_eq!(decoded.intrinsics.len(), 1);
    assert_eq!(decoded.intrinsics[0].func_id, 1);
    assert_eq!(decoded.intrinsics[0].intrinsic, intrinsic);
    assert_ne!(decoded.header.flags & FLAG_INTRINSICS, 0);
}

#[test]
fn unannotated_program_has_no_flag_and_decodes_clean() {
    let mut prog = annotated_two_sub_program(Intrinsic::Prod {
        n: 4,
        k: 2,
        ret_len: 4,
    });
    prog.intrinsics.clear();
    let bytes = crate::bytecode::encode(&prog);
    let decoded = crate::bytecode::decode(&bytes, Some(FieldFamily::BnLike256)).expect("decode");
    assert!(decoded.intrinsics.is_empty());
    assert_eq!(decoded.header.flags & FLAG_INTRINSICS, 0);
}

#[test]
fn annotation_on_entry_is_rejected() {
    let mut prog = annotated_two_sub_program(Intrinsic::ModInv {
        n: 4,
        k: 2,
        ret_len: 4,
    });
    prog.intrinsics[0].func_id = 0;
    let bytes = crate::bytecode::encode(&prog);
    let err = crate::bytecode::decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert_eq!(err, ArtikError::BadIntrinsicAnnotation { func_id: 0 });
}

#[test]
fn annotation_with_bad_bounds_is_rejected() {
    let prog = annotated_two_sub_program(Intrinsic::ModInv {
        n: 99,
        k: 2,
        ret_len: 4,
    });
    let bytes = crate::bytecode::encode(&prog);
    let err = crate::bytecode::decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert_eq!(err, ArtikError::BadIntrinsicAnnotation { func_id: 1 });
}

#[test]
fn annotation_with_mismatched_signature_is_rejected() {
    // LongDiv expects 3 scalars + 2 arrays; the callee has 2 + 2.
    let prog = annotated_two_sub_program(Intrinsic::LongDiv {
        n: 4,
        k: 2,
        m: 2,
        ret_len: 8,
    });
    let bytes = crate::bytecode::encode(&prog);
    let err = crate::bytecode::decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert_eq!(err, ArtikError::BadIntrinsicAnnotation { func_id: 1 });
}

#[test]
fn unknown_intrinsic_tag_is_rejected() {
    let prog = annotated_two_sub_program(Intrinsic::ModInv {
        n: 4,
        k: 2,
        ret_len: 4,
    });
    let mut bytes = crate::bytecode::encode(&prog);
    // The tag byte sits right after the section count and func_id.
    let section_start = bytes.len() - (4 + 4 + 1 + 12);
    bytes[section_start + 8] = 0xEE;
    let err = crate::bytecode::decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert_eq!(err, ArtikError::UnknownIntrinsicTag(0xEE));
}
