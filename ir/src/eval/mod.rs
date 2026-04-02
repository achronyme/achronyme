use std::collections::HashMap;
use std::fmt;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use constraints::PoseidonParamsProvider;
use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar};

/// Errors that can occur during IR evaluation.
#[derive(Debug)]
pub enum EvalError<F: FieldBackend = memory::Bn254Fr> {
    MissingInput(String),
    DivisionByZero {
        var: SsaVar,
        dividend_name: Option<String>,
        divisor_name: Option<String>,
    },
    AssertionFailed {
        var: SsaVar,
        name: Option<String>,
        value: Option<FieldElement<F>>,
        message: Option<String>,
    },
    AssertEqFailed {
        lhs: SsaVar,
        rhs: SsaVar,
        lhs_name: Option<String>,
        rhs_name: Option<String>,
        lhs_value: Option<FieldElement<F>>,
        rhs_value: Option<FieldElement<F>>,
        message: Option<String>,
    },
    RangeCheckFailed {
        var: SsaVar,
        bits: u32,
        name: Option<String>,
        value: Option<FieldElement<F>>,
    },
    NonBooleanMuxCondition {
        var: SsaVar,
        name: Option<String>,
        value: Option<FieldElement<F>>,
    },
    UndefinedVar(SsaVar),
}

/// Look up the source-level name for an SSA variable.
fn resolve_name<F: FieldBackend>(program: &IrProgram<F>, var: SsaVar) -> Option<String> {
    program.get_name(var).map(|s| s.to_string())
}

impl<F: FieldBackend> fmt::Display for EvalError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::MissingInput(name) => write!(f, "missing input: `{name}`"),
            EvalError::DivisionByZero {
                dividend_name,
                divisor_name,
                ..
            } => match (dividend_name, divisor_name) {
                (Some(a), Some(b)) => {
                    write!(
                        f,
                        "division by zero when dividing '{a}' by '{b}' (which is 0)"
                    )
                }
                _ => write!(f, "division by zero"),
            },
            EvalError::AssertionFailed {
                name,
                value,
                message,
                ..
            } => {
                if let Some(msg) = message {
                    write!(f, "assertion failed: {msg}")
                } else {
                    match (name, value) {
                        (Some(n), Some(v)) => write!(
                            f,
                            "assertion failed at '{n}' (value is {}, expected non-zero)",
                            v.to_decimal_string()
                        ),
                        (Some(n), None) => {
                            write!(f, "assertion failed at '{n}' (expected non-zero)")
                        }
                        _ => write!(f, "assertion failed (expected non-zero)"),
                    }
                }
            }
            EvalError::AssertEqFailed {
                lhs_name,
                rhs_name,
                lhs_value,
                rhs_value,
                message,
                ..
            } => {
                if let Some(msg) = message {
                    write!(f, "assert_eq failed: {msg}")
                } else {
                    match (lhs_name, rhs_name, lhs_value, rhs_value) {
                        (Some(a), Some(b), Some(av), Some(bv)) => write!(
                            f,
                            "assert_eq failed: '{a}' (value {}) != '{b}' (value {})",
                            av.to_decimal_string(),
                            bv.to_decimal_string()
                        ),
                        _ => write!(f, "assert_eq failed: values are not equal"),
                    }
                }
            }
            EvalError::RangeCheckFailed {
                bits, name, value, ..
            } => match (name, value) {
                (Some(n), Some(v)) => {
                    let max_str = if *bits < 64 {
                        format!("{}", (1u64 << bits) - 1)
                    } else {
                        format!("2^{bits}-1")
                    };
                    write!(
                        f,
                        "range check failed: '{n}' (value {}) does not fit in {bits} bits (max {max_str})",
                        v.to_decimal_string()
                    )
                }
                _ => write!(f, "range check failed: value does not fit in {bits} bits"),
            },
            EvalError::NonBooleanMuxCondition { name, value, .. } => match (name, value) {
                (Some(n), Some(v)) => write!(
                    f,
                    "if/else condition must be boolean: '{n}' has value {} (expected 0 or 1)",
                    v.to_decimal_string()
                ),
                _ => write!(f, "if/else condition must be boolean (expected 0 or 1)"),
            },
            EvalError::UndefinedVar(var) => write!(f, "undefined variable #{}", var.0),
        }
    }
}

impl<F: FieldBackend> std::error::Error for EvalError<F> {}

/// Evaluate an IR program with concrete inputs, returning all SSA variable values.
///
/// This is a pure evaluator: it computes every SSA variable's value by walking
/// the instruction list forward. Assertions (`AssertEq`, `Assert`, `RangeCheck`)
/// are checked eagerly and return errors immediately on failure.
///
/// ```
/// use std::collections::HashMap;
/// use ir::IrLowering;
/// use ir::eval::evaluate;
/// use memory::FieldElement;
///
/// let prog = IrLowering::lower_circuit("assert_eq(x, y)", &["x"], &["y"]).unwrap();
/// let mut inputs = HashMap::new();
/// inputs.insert("x".to_string(), FieldElement::from_u64(42));
/// inputs.insert("y".to_string(), FieldElement::from_u64(42));
/// assert!(evaluate(&prog, &inputs).is_ok());
/// ```
pub fn evaluate<F: FieldBackend + PoseidonParamsProvider>(
    program: &IrProgram<F>,
    inputs: &HashMap<String, FieldElement<F>>,
) -> Result<HashMap<SsaVar, FieldElement<F>>, Box<EvalError<F>>> {
    let mut values: HashMap<SsaVar, FieldElement<F>> = HashMap::new();
    let mut poseidon_params: Option<PoseidonParams<F>> = None;

    let get = |values: &HashMap<SsaVar, FieldElement<F>>,
               var: &SsaVar|
     -> Result<FieldElement<F>, Box<EvalError<F>>> {
        values
            .get(var)
            .copied()
            .ok_or_else(|| Box::new(EvalError::UndefinedVar(*var)))
    };

    for inst in &program.instructions {
        match inst {
            Instruction::Const { result, value } => {
                values.insert(*result, *value);
            }
            Instruction::Input { result, name, .. } => {
                let val = inputs
                    .get(name)
                    .copied()
                    .ok_or_else(|| Box::new(EvalError::MissingInput(name.clone())))?;
                values.insert(*result, val);
            }
            Instruction::Add { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.add(&b));
            }
            Instruction::Sub { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.sub(&b));
            }
            Instruction::Mul { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.mul(&b));
            }
            Instruction::Div { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let inv = b.inv().ok_or_else(|| {
                    Box::new(EvalError::DivisionByZero {
                        var: *result,
                        dividend_name: resolve_name(program, *lhs),
                        divisor_name: resolve_name(program, *rhs),
                    })
                })?;
                values.insert(*result, a.mul(&inv));
            }
            Instruction::Neg { result, operand } => {
                let v = get(&values, operand)?;
                values.insert(*result, v.neg());
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let c = get(&values, cond)?;
                let t = get(&values, if_true)?;
                let f = get(&values, if_false)?;
                if c != FieldElement::<F>::zero() && c != FieldElement::<F>::one() {
                    return Err(Box::new(EvalError::NonBooleanMuxCondition {
                        var: *cond,
                        name: resolve_name(program, *cond),
                        value: Some(c),
                    }));
                }
                let val = if !c.is_zero() { t } else { f };
                values.insert(*result, val);
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let l = get(&values, left)?;
                let r = get(&values, right)?;
                let params = poseidon_params.get_or_insert_with(F::default_poseidon_t3);
                let hash = poseidon_hash(params, l, r);
                values.insert(*result, hash);
            }
            Instruction::AssertEq {
                result,
                lhs,
                rhs,
                message,
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                if a != b {
                    return Err(Box::new(EvalError::AssertEqFailed {
                        lhs: *lhs,
                        rhs: *rhs,
                        lhs_name: resolve_name(program, *lhs),
                        rhs_name: resolve_name(program, *rhs),
                        lhs_value: Some(a),
                        rhs_value: Some(b),
                        message: message.clone(),
                    }));
                }
                values.insert(*result, a);
            }
            Instruction::Assert {
                result,
                operand,
                message,
            } => {
                let v = get(&values, operand)?;
                if v != FieldElement::<F>::one() {
                    return Err(Box::new(EvalError::AssertionFailed {
                        var: *operand,
                        name: resolve_name(program, *operand),
                        value: Some(v),
                        message: message.clone(),
                    }));
                }
                values.insert(*result, v);
            }
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                let v = get(&values, operand)?;
                if !fits_in_bits(&v, *bits) {
                    return Err(Box::new(EvalError::RangeCheckFailed {
                        var: *operand,
                        bits: *bits,
                        name: resolve_name(program, *operand),
                        value: Some(v),
                    }));
                }
                values.insert(*result, v);
            }
            Instruction::Not { result, operand } => {
                let v = get(&values, operand)?;
                values.insert(*result, FieldElement::<F>::one().sub(&v));
            }
            Instruction::And { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.mul(&b));
            }
            Instruction::Or { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                // a + b - a*b
                values.insert(*result, a.add(&b).sub(&a.mul(&b)));
            }
            Instruction::IsEq { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let eq = if a == b {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                };
                values.insert(*result, eq);
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let neq = if a != b {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                };
                values.insert(*result, neq);
            }
            Instruction::IsLt { result, lhs, rhs }
            | Instruction::IsLtBounded {
                result, lhs, rhs, ..
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let la = a.to_canonical();
                let lb = b.to_canonical();
                let less = (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]);
                values.insert(
                    *result,
                    if less {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    },
                );
            }
            Instruction::IsLe { result, lhs, rhs }
            | Instruction::IsLeBounded {
                result, lhs, rhs, ..
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let la = a.to_canonical();
                let lb = b.to_canonical();
                let le = (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0]);
                values.insert(
                    *result,
                    if le {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    },
                );
            }
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let v = get(&values, operand)?;
                if !fits_in_bits(&v, *num_bits) {
                    return Err(Box::new(EvalError::RangeCheckFailed {
                        var: *operand,
                        bits: *num_bits,
                        name: resolve_name(program, *operand),
                        value: Some(v),
                    }));
                }
                let limbs = v.to_canonical();
                for (i, bit_var) in bit_results.iter().enumerate() {
                    let limb_idx = i / 64;
                    let bit_pos = i % 64;
                    let bit = if limb_idx < 4 {
                        (limbs[limb_idx] >> bit_pos) & 1
                    } else {
                        0
                    };
                    values.insert(*bit_var, FieldElement::<F>::from_u64(bit));
                }
                values.insert(*result, v);
            }
            Instruction::IntDiv {
                result, lhs, rhs, ..
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let (q, _) = int_divmod_field(&a, &b);
                values.insert(*result, q);
            }
            Instruction::IntMod {
                result, lhs, rhs, ..
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let (_, r) = int_divmod_field(&a, &b);
                values.insert(*result, r);
            }
        }
    }

    Ok(values)
}

/// Evaluate an IR program leniently: skip assertion failures instead of erroring.
///
/// Returns `(values, failures)` where `failures` lists the instruction indices
/// whose assertions failed. Used by the inspector to show wire values even when
/// constraints are unsatisfied.
pub fn evaluate_lenient<F: FieldBackend + PoseidonParamsProvider>(
    program: &IrProgram<F>,
    inputs: &HashMap<String, FieldElement<F>>,
) -> (HashMap<SsaVar, FieldElement<F>>, Vec<usize>) {
    let mut values: HashMap<SsaVar, FieldElement<F>> = HashMap::new();
    let mut poseidon_params: Option<PoseidonParams<F>> = None;
    let mut failures: Vec<usize> = Vec::new();

    let get = |values: &HashMap<SsaVar, FieldElement<F>>,
               var: &SsaVar|
     -> Option<FieldElement<F>> { values.get(var).copied() };

    for (idx, inst) in program.instructions.iter().enumerate() {
        match inst {
            Instruction::Const { result, value } => {
                values.insert(*result, *value);
            }
            Instruction::Input { result, name, .. } => {
                if let Some(val) = inputs.get(name) {
                    values.insert(*result, *val);
                }
            }
            Instruction::Add { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.add(&b));
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.sub(&b));
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.mul(&b));
                }
            }
            Instruction::Div { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    if let Some(inv) = b.inv() {
                        values.insert(*result, a.mul(&inv));
                    }
                }
            }
            Instruction::Neg { result, operand } => {
                if let Some(v) = get(&values, operand) {
                    values.insert(*result, v.neg());
                }
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                if let (Some(c), Some(t), Some(f)) = (
                    get(&values, cond),
                    get(&values, if_true),
                    get(&values, if_false),
                ) {
                    values.insert(*result, if !c.is_zero() { t } else { f });
                }
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                if let (Some(l), Some(r)) = (get(&values, left), get(&values, right)) {
                    let params = poseidon_params.get_or_insert_with(F::default_poseidon_t3);
                    values.insert(*result, poseidon_hash(params, l, r));
                }
            }
            Instruction::AssertEq {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    if a != b {
                        failures.push(idx);
                    }
                    values.insert(*result, a);
                }
            }
            Instruction::Assert {
                result, operand, ..
            } => {
                if let Some(v) = get(&values, operand) {
                    if v != FieldElement::<F>::one() {
                        failures.push(idx);
                    }
                    values.insert(*result, v);
                }
            }
            Instruction::RangeCheck {
                result, operand, ..
            } => {
                if let Some(v) = get(&values, operand) {
                    values.insert(*result, v);
                }
            }
            Instruction::Not { result, operand } => {
                if let Some(v) = get(&values, operand) {
                    values.insert(*result, FieldElement::<F>::one().sub(&v));
                }
            }
            Instruction::And { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.mul(&b));
                }
            }
            Instruction::Or { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.add(&b).sub(&a.mul(&b)));
                }
            }
            Instruction::IsEq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(
                        *result,
                        if a == b {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        },
                    );
                }
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(
                        *result,
                        if a != b {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        },
                    );
                }
            }
            Instruction::IsLt {
                result, lhs, rhs, ..
            }
            | Instruction::IsLtBounded {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    let la = a.to_canonical();
                    let lb = b.to_canonical();
                    let less = (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]);
                    values.insert(
                        *result,
                        if less {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        },
                    );
                }
            }
            Instruction::IsLe {
                result, lhs, rhs, ..
            }
            | Instruction::IsLeBounded {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    let la = a.to_canonical();
                    let lb = b.to_canonical();
                    let le = (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0]);
                    values.insert(
                        *result,
                        if le {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        },
                    );
                }
            }
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                ..
            } => {
                if let Some(v) = get(&values, operand) {
                    let limbs = v.to_canonical();
                    for (i, bit_var) in bit_results.iter().enumerate() {
                        let limb_idx = i / 64;
                        let bit_pos = i % 64;
                        let bit = if limb_idx < 4 {
                            (limbs[limb_idx] >> bit_pos) & 1
                        } else {
                            0
                        };
                        values.insert(*bit_var, FieldElement::<F>::from_u64(bit));
                    }
                    values.insert(*result, v);
                }
            }
            Instruction::IntDiv {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    let (q, _) = int_divmod_field(&a, &b);
                    values.insert(*result, q);
                }
            }
            Instruction::IntMod {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    let (_, r) = int_divmod_field(&a, &b);
                    values.insert(*result, r);
                }
            }
        }
    }

    (values, failures)
}

/// Check whether a field element fits in `bits` bits.
fn fits_in_bits<F: FieldBackend>(v: &FieldElement<F>, bits: u32) -> bool {
    if bits >= 256 {
        return true;
    }
    let limbs = v.to_canonical();
    // Check each 64-bit limb
    for (i, &limb) in limbs.iter().enumerate() {
        let limb_start = (i as u32) * 64;
        if limb_start >= bits {
            // This entire limb must be zero
            if limb != 0 {
                return false;
            }
        } else {
            let remaining_bits = bits - limb_start;
            if remaining_bits < 64 {
                // Only lower `remaining_bits` bits allowed
                if limb >= (1u64 << remaining_bits) {
                    return false;
                }
            }
            // If remaining_bits >= 64, the whole limb is fine
        }
    }
    true
}

/// Integer division and modulo on field elements (unsigned).
/// Returns `(q, r)` where `a = b * q + r` and `0 <= r < b`.
fn int_divmod_field<F: FieldBackend>(
    a: &FieldElement<F>,
    b: &FieldElement<F>,
) -> (FieldElement<F>, FieldElement<F>) {
    let a_limbs = a.to_canonical();
    let b_limbs = b.to_canonical();
    let a_small = a_limbs[1] == 0 && a_limbs[2] == 0 && a_limbs[3] == 0;
    let b_small = b_limbs[1] == 0 && b_limbs[2] == 0 && b_limbs[3] == 0;
    if b_small && b_limbs[0] == 0 {
        return (FieldElement::<F>::zero(), FieldElement::<F>::zero());
    }
    if a_small && b_small {
        let q = a_limbs[0] / b_limbs[0];
        let r = a_limbs[0] % b_limbs[0];
        return (
            FieldElement::<F>::from_u64(q),
            FieldElement::<F>::from_u64(r),
        );
    }
    // Multi-limb: use shift-and-subtract
    let (q, r) = divmod_u256(&a_limbs, &b_limbs);
    (u256_to_field::<F>(&q), u256_to_field::<F>(&r))
}

fn divmod_u256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    let a_bits = 256 - leading_zeros_u256(a);
    let b_bits = 256 - leading_zeros_u256(b);
    if b_bits == 0 || cmp_u256(a, b) == std::cmp::Ordering::Less {
        return ([0; 4], *a);
    }
    let shift = a_bits - b_bits;
    let mut rem = *a;
    let mut quot = [0u64; 4];
    let mut shifted = shl_u256(b, shift);
    for i in (0..=shift).rev() {
        if cmp_u256(&rem, &shifted) != std::cmp::Ordering::Less {
            rem = sub_u256(&rem, &shifted);
            quot[i / 64] |= 1u64 << (i % 64);
        }
        shifted = shr_u256(&shifted, 1);
    }
    (quot, rem)
}

fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

fn leading_zeros_u256(a: &[u64; 4]) -> usize {
    for i in (0..4).rev() {
        if a[i] != 0 {
            return (3 - i) * 64 + a[i].leading_zeros() as usize;
        }
    }
    256
}

fn shl_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let (ws, bs) = (shift / 64, shift % 64);
    let mut r = [0u64; 4];
    for i in ws..4 {
        r[i] = a[i - ws] << bs;
        if bs > 0 && i > ws {
            r[i] |= a[i - ws - 1] >> (64 - bs);
        }
    }
    r
}

fn shr_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let (ws, bs) = (shift / 64, shift % 64);
    let mut r = [0u64; 4];
    for i in 0..(4 - ws) {
        r[i] = a[i + ws] >> bs;
        if bs > 0 && i + ws + 1 < 4 {
            r[i] |= a[i + ws + 1] << (64 - bs);
        }
    }
    r
}

fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        r[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    r
}

fn u256_to_field<F: FieldBackend>(limbs: &[u64; 4]) -> FieldElement<F> {
    let mut result = FieldElement::<F>::from_u64(limbs[0]);
    let shift64 =
        FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
    if limbs[1] != 0 {
        result = result.add(&FieldElement::<F>::from_u64(limbs[1]).mul(&shift64));
    }
    if limbs[2] != 0 {
        let shift128 = shift64.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[2]).mul(&shift128));
    }
    if limbs[3] != 0 {
        let shift128 = shift64.mul(&shift64);
        let shift192 = shift128.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[3]).mul(&shift192));
    }
    result
}

#[cfg(test)]
mod tests;
