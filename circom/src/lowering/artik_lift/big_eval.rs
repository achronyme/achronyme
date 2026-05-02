//! Compile-time big-integer evaluator for the Artik lift.
//!
//! Circom's `var` arithmetic operates on 256-bit values. Loop counts
//! and small accumulators stay in `i64` ([`super::ConstInt`] /
//! [`super::helpers::eval_const_expr`]), but expressions like
//! `(-1) >> 1` (the Legendre exponent for BN254 Fr) or 78-decimal-digit
//! literals overflow that path. [`try_eval_big`] folds those at lift
//! time so the caller can use the result either as a constant exponent
//! for [`super::LiftState::lift_pow`] or as a register-pushed bigint
//! literal.
//!
//! ## Negation semantics
//!
//! Circom evaluates `-x` modulo the field prime. The lift currently
//! emits Artik bytecode tagged [`memory::FieldFamily::BnLike256`], so
//! the active prime is BN254-Fr's. [`bn254_fr_modulus`] returns it as
//! a `BigUint` for the `UnaryOp::Neg` case — the result of `p - x` is
//! still in `[0, p)` and round-trips correctly through 32-byte LE
//! encoding.

use std::collections::HashMap;

use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

use crate::ast::{BinOp, Expr, UnaryOp};

use super::ConstInt;

/// BN254 scalar field modulus
/// (`21888242871839275222246405745257275088548364400416034343698204186575808495617`).
/// Hardcoded for the BnLike256 family — the only family the lift emits
/// today. If the lift later targets BLS12-381 or another BnLike256
/// prime, this needs to dispatch on `FieldFamily`.
pub(super) fn bn254_fr_modulus() -> BigUint {
    let bytes = <memory::Bn254Fr as memory::FieldBackend>::modulus_le_bytes();
    BigUint::from_bytes_le(&bytes)
}

/// Fold `expr` to a non-negative big-integer using the lift's
/// compile-time scopes. Returns `None` for anything that isn't
/// evaluable at lift time (signal references, runtime locals,
/// unsupported ops).
///
/// `i64_locals` lets identifiers tracked as small-integer compile-time
/// vars (loop counters) participate in big-int folds without forcing
/// the caller to mirror them into a `BigUint` map.
pub(super) fn try_eval_big(
    expr: &Expr,
    big_locals: &HashMap<String, BigUint>,
    i64_locals: &HashMap<String, ConstInt>,
) -> Option<BigUint> {
    match expr {
        Expr::Number { value, .. } => value.parse::<BigUint>().ok(),
        Expr::HexNumber { value, .. } => {
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            BigUint::parse_bytes(trimmed.as_bytes(), 16)
        }
        Expr::Ident { name, .. } => {
            if let Some(v) = big_locals.get(name) {
                return Some(v.clone());
            }
            i64_locals.get(name).copied().map(|n| {
                if n < 0 {
                    let p = bn254_fr_modulus();
                    &p - BigUint::from(n.unsigned_abs())
                } else {
                    BigUint::from(n as u64)
                }
            })
        }
        Expr::UnaryOp {
            op: UnaryOp::Neg,
            operand,
            ..
        } => {
            let v = try_eval_big(operand, big_locals, i64_locals)?;
            let p = bn254_fr_modulus();
            if v.is_zero() {
                Some(BigUint::zero())
            } else {
                Some(&p - (v % &p))
            }
        }
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = try_eval_big(lhs, big_locals, i64_locals)?;
            let b = try_eval_big(rhs, big_locals, i64_locals)?;
            let p = bn254_fr_modulus();
            match op {
                BinOp::Add => Some((a + b) % &p),
                BinOp::Sub => Some(field_sub(&a, &b, &p)),
                BinOp::Mul => Some((a * b) % &p),
                // `<<` / `>>` in circom var arithmetic are bit-level on
                // the canonical 256-bit unsigned view. The shift amount
                // must fit in u32 for `BigUint`'s shift impl; anything
                // larger would have shifted the operand out of the
                // 256-bit window anyway.
                BinOp::ShiftL => {
                    let shift = b.to_u32()?;
                    Some((a << shift) % &p)
                }
                BinOp::ShiftR => {
                    let shift = b.to_u32()?;
                    Some(a >> shift)
                }
                BinOp::BitAnd => Some(a & b),
                BinOp::BitOr => Some(a | b),
                BinOp::BitXor => Some(a ^ b),
                BinOp::IntDiv => {
                    if b.is_zero() {
                        return None;
                    }
                    Some(a / b)
                }
                BinOp::Mod => {
                    if b.is_zero() {
                        return None;
                    }
                    Some(a % b)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// `(a - b) mod p`, treating `a` and `b` as canonical residues in
/// `[0, p)`. `BigUint` subtraction would underflow when `a < b`, so
/// rebase by `p` first.
fn field_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    let a_canon = a % p;
    let b_canon = b % p;
    if a_canon >= b_canon {
        a_canon - b_canon
    } else {
        (p + a_canon) - b_canon
    }
}

/// Encode a `BigUint` as up to 32 little-endian bytes for
/// [`artik::ProgramBuilder::intern_const`]. Trailing zeros are
/// trimmed so the constant pool stays compact, but a single leading
/// zero remains for the value `0`.
pub(super) fn big_to_le_bytes_trimmed(v: &BigUint) -> Option<Vec<u8>> {
    let mut bytes = v.to_bytes_le();
    if bytes.len() > 32 {
        return None;
    }
    while bytes.last() == Some(&0) && bytes.len() > 1 {
        bytes.pop();
    }
    Some(bytes)
}
