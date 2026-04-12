//! BN254 field-aware constant folding for `CircuitExpr`.
//!
//! Evaluates a `CircuitExpr` tree to a single `FieldConst` when every
//! leaf is `Const`.  Arithmetic uses exact BN254 modular operations
//! (via `memory::FieldElement<Bn254Fr>`), so the result matches what
//! the R1CS backend produces at instantiation time.
//!
//! This is the compile-time analogue of the witness evaluator: if all
//! inputs to a sub-circuit are known constants, the entire sub-circuit
//! collapses to a constant — zero constraints.

use ir::prove_ir::types::{CircuitBinOp, CircuitExpr, CircuitUnaryOp, FieldConst};
use memory::{Bn254Fr, FieldElement};

/// Try to fold a `CircuitExpr` to a `FieldConst`.
///
/// Returns `Some(fc)` when every leaf in the expression tree is `Const`
/// and every operation is field-evaluable (Add, Sub, Mul, Div, Neg, Pow).
/// Returns `None` if any leaf is a `Var`, `Input`, `Capture`, or if the
/// expression contains a non-evaluable operation (comparisons, bitwise, etc.).
pub fn try_fold_const(expr: &CircuitExpr) -> Option<FieldConst> {
    match expr {
        CircuitExpr::Const(fc) => Some(*fc),

        CircuitExpr::BinOp { op, lhs, rhs } => {
            let l = to_fe(try_fold_const(lhs)?)?;
            let r = to_fe(try_fold_const(rhs)?)?;
            let result = match op {
                CircuitBinOp::Add => l.add(&r),
                CircuitBinOp::Sub => l.sub(&r),
                CircuitBinOp::Mul => l.mul(&r),
                CircuitBinOp::Div => l.div(&r)?,
            };
            Some(FieldConst::from_field(result))
        }

        CircuitExpr::UnaryOp { op, operand } => {
            let val = to_fe(try_fold_const(operand)?)?;
            match op {
                CircuitUnaryOp::Neg => Some(FieldConst::from_field(val.neg())),
                CircuitUnaryOp::Not => {
                    // Boolean NOT: 1 - val
                    let one = FieldElement::<Bn254Fr>::one();
                    Some(FieldConst::from_field(one.sub(&val)))
                }
            }
        }

        CircuitExpr::Pow { base, exp } => {
            let b = to_fe(try_fold_const(base)?)?;
            // Build [u64; 4] exponent
            let e = [*exp, 0, 0, 0];
            Some(FieldConst::from_field(b.pow(&e)))
        }

        // Left shift by a compile-time constant: `x << s` → `x * 2^s`
        // in the field. Uses `pow` so the shift amount can exceed 63
        // without overflowing — `1 << 64` correctly produces `2^64` as
        // a BN254 field element (well within the 254-bit field).
        //
        // Missing this fold silently broke `LessThan(n)` for any
        // n >= 64: circomlib's `n2b.in <== in[0] + (1 << n) - in[1]`
        // expression got lowered to a runtime `CircuitExpr::ShiftL`,
        // whose IR evaluation used u64 arithmetic and wrapped `1 << 64`
        // to 0 — turning the range-check input into `in[0] - in[1]`
        // (i.e. `-58 mod p` instead of `2^64 - 58`) and causing the
        // Num2Bits sum constraint to fail.
        CircuitExpr::ShiftL { operand, shift, .. } => {
            let base = to_fe(try_fold_const(operand)?)?;
            let shift_amt = try_fold_const(shift)?.to_u64()?;
            let two = FieldElement::<Bn254Fr>::from_u64(2);
            let e = [shift_amt, 0, 0, 0];
            let two_to_s = two.pow(&e);
            Some(FieldConst::from_field(base.mul(&two_to_s)))
        }

        // Right shift by a compile-time constant. For field elements
        // this isn't a direct division — we need the integer
        // representation. We only fold when the operand fits in u64
        // (which covers every realistic compile-time case) and fall
        // back to the runtime shift otherwise.
        CircuitExpr::ShiftR { operand, shift, .. } => {
            let base_u64 = try_fold_const(operand)?.to_u64()?;
            let shift_amt = try_fold_const(shift)?.to_u64()?;
            let shifted = if shift_amt >= 64 {
                0
            } else {
                base_u64 >> shift_amt
            };
            Some(FieldConst::from_u64(shifted))
        }

        // IntDiv / IntMod are integer operations, not field operations.
        // We can evaluate them when the values fit in u64.
        CircuitExpr::IntDiv { lhs, rhs, .. } => {
            let l = try_fold_const(lhs)?.to_u64()?;
            let r = try_fold_const(rhs)?.to_u64()?;
            if r == 0 {
                return None;
            }
            Some(FieldConst::from_u64(l / r))
        }
        CircuitExpr::IntMod { lhs, rhs, .. } => {
            let l = try_fold_const(lhs)?.to_u64()?;
            let r = try_fold_const(rhs)?.to_u64()?;
            if r == 0 {
                return None;
            }
            Some(FieldConst::from_u64(l % r))
        }

        // Mux with constant condition → select branch
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            let c = try_fold_const(cond)?;
            if !c.is_zero() {
                try_fold_const(if_true)
            } else {
                try_fold_const(if_false)
            }
        }

        // Anything else (Var, Input, Capture, ArrayIndex, etc.) → not constant
        _ => None,
    }
}

/// Convert a `FieldConst` to a BN254 `FieldElement`.
///
/// Returns `None` if the stored bytes are not valid in BN254 (>= prime).
fn to_fe(fc: FieldConst) -> Option<FieldElement<Bn254Fr>> {
    fc.to_field::<Bn254Fr>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: u64) -> CircuitExpr {
        CircuitExpr::Const(FieldConst::from_u64(v))
    }

    fn fc(v: u64) -> FieldConst {
        FieldConst::from_u64(v)
    }

    #[test]
    fn fold_const_leaf() {
        assert_eq!(try_fold_const(&c(42)), Some(fc(42)));
    }

    #[test]
    fn fold_add() {
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(c(10)),
            rhs: Box::new(c(20)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(30)));
    }

    #[test]
    fn fold_sub() {
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: Box::new(c(50)),
            rhs: Box::new(c(30)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(20)));
    }

    #[test]
    fn fold_mul() {
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(c(7)),
            rhs: Box::new(c(6)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(42)));
    }

    #[test]
    fn fold_div() {
        // 42 / 6 = 7 in the field
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: Box::new(c(42)),
            rhs: Box::new(c(6)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(7)));
    }

    #[test]
    fn fold_div_by_zero_is_none() {
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: Box::new(c(42)),
            rhs: Box::new(c(0)),
        };
        assert_eq!(try_fold_const(&expr), None);
    }

    #[test]
    fn fold_neg() {
        // -1 in BN254 = p - 1
        let expr = CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Neg,
            operand: Box::new(c(1)),
        };
        let result = try_fold_const(&expr).unwrap();
        assert!(!result.is_zero());
        // Verify: neg(1) + 1 = 0
        let fe = to_fe(result).unwrap();
        let one = FieldElement::<Bn254Fr>::one();
        assert!(fe.add(&one).is_zero());
    }

    #[test]
    fn fold_pow() {
        // 2^10 = 1024
        let expr = CircuitExpr::Pow {
            base: Box::new(c(2)),
            exp: 10,
        };
        assert_eq!(try_fold_const(&expr), Some(fc(1024)));
    }

    #[test]
    fn fold_nested() {
        // (10 + 20) * 3 = 90
        let add = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(c(10)),
            rhs: Box::new(c(20)),
        };
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(add),
            rhs: Box::new(c(3)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(90)));
    }

    #[test]
    fn fold_fails_with_var() {
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(c(10)),
            rhs: Box::new(CircuitExpr::Var("x".to_string())),
        };
        assert_eq!(try_fold_const(&expr), None);
    }

    #[test]
    fn fold_mux_const_true() {
        let expr = CircuitExpr::Mux {
            cond: Box::new(c(1)),
            if_true: Box::new(c(42)),
            if_false: Box::new(c(99)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(42)));
    }

    #[test]
    fn fold_mux_const_false() {
        let expr = CircuitExpr::Mux {
            cond: Box::new(c(0)),
            if_true: Box::new(c(42)),
            if_false: Box::new(c(99)),
        };
        assert_eq!(try_fold_const(&expr), Some(fc(99)));
    }

    #[test]
    fn fold_field_div_roundtrip() {
        // a / b * b should = a (in BN254 field)
        let a = FieldElement::<Bn254Fr>::from_u64(12345);
        let b = FieldElement::<Bn254Fr>::from_u64(67890);
        let fc_a = FieldConst::from_field(a);
        let fc_b = FieldConst::from_field(b);

        // a / b
        let div_expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: Box::new(CircuitExpr::Const(fc_a)),
            rhs: Box::new(CircuitExpr::Const(fc_b)),
        };
        let quot = try_fold_const(&div_expr).unwrap();

        // (a / b) * b
        let mul_expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Const(quot)),
            rhs: Box::new(CircuitExpr::Const(fc_b)),
        };
        assert_eq!(try_fold_const(&mul_expr), Some(fc_a));
    }

    #[test]
    fn fold_sub_wraps_in_field() {
        // 3 - 5 = p - 2 in BN254 (not negative, wraps around)
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: Box::new(c(3)),
            rhs: Box::new(c(5)),
        };
        let result = try_fold_const(&expr).unwrap();
        assert!(!result.is_zero());
        // Verify: (3 - 5) + 5 = 3
        let fe = to_fe(result).unwrap();
        let five = FieldElement::<Bn254Fr>::from_u64(5);
        let three = FieldElement::<Bn254Fr>::from_u64(3);
        assert_eq!(fe.add(&five), three);
    }

    #[test]
    fn fold_large_mul_in_field() {
        // Multiply two large values — result must be mod p, not overflow
        let big = FieldConst::from_decimal_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap();
        let expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Const(big)),
            rhs: Box::new(c(2)),
        };
        let result = try_fold_const(&expr).unwrap();
        // p-1 * 2 = 2p - 2 ≡ -2 mod p, and -2 + 2 = 0
        let fe = to_fe(result).unwrap();
        let two = FieldElement::<Bn254Fr>::from_u64(2);
        assert!(fe.add(&two).is_zero());
    }
}
