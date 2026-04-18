//! ProveIR instantiation: ProveIR template + capture values → IrProgram (flat IR SSA).
//!
//! This is Phase B of the ProveIR pipeline. Given a pre-compiled circuit template
//! and concrete values for all captured variables, it produces an `IrProgram`
//! compatible with the existing optimize → R1CS/Plonkish pipeline.
//!
//! Key operations:
//! - Resolve captures to constants or witness inputs
//! - Unroll for loops (bounds are now concrete)
//! - Expand array declarations (sizes are now concrete)
//! - Flatten the CircuitNode/CircuitExpr tree into a flat `Vec<Instruction>`

mod api;
mod utils;

use std::collections::HashMap;

use diagnostics::SpanRange;
use memory::{FieldBackend, FieldElement};

use super::error::ProveIrError;
use super::types::*;
use crate::types::{Instruction, IrProgram, IrType, SsaVar, Visibility};
use utils::{fe_to_u64, fe_to_usize};

/// Maximum iterations allowed during instantiation (loop unrolling).
/// This mirrors `MAX_UNROLL_ITERATIONS` in IrLowering but applies to capture-bound
/// loops that are only resolved at instantiation time.
pub(super) const MAX_INSTANTIATE_ITERATIONS: u64 = 1_000_000;

/// Bitwise binary operation type (used internally by emit_bitwise_binop).
pub(super) enum BitwiseOp {
    And,
    Or,
    Xor,
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// A resolved value in the instantiation environment.
#[derive(Clone, Debug)]
pub(super) enum InstEnvValue {
    /// A scalar SSA variable.
    Scalar(SsaVar),
    /// An array of SSA variables (one per element).
    Array(Vec<SsaVar>),
}

// ---------------------------------------------------------------------------
// Instantiator
// ---------------------------------------------------------------------------

/// Converts a ProveIR template into a flat IrProgram given concrete capture values.
pub(super) struct Instantiator<F: FieldBackend> {
    pub(super) program: IrProgram<F>,
    pub(super) env: HashMap<String, InstEnvValue>,
    /// Concrete capture values (provided by caller).
    pub(super) captures: HashMap<String, FieldElement<F>>,
    /// Current source span context — set when entering a CircuitNode,
    /// propagated to all IR instructions emitted within that node.
    pub(super) current_span: Option<SpanRange>,
    /// Maps output signal element names → their public wire SSA vars.
    /// Non-empty only when instantiating Circom circuits with `signal output`.
    /// Used to intercept body nodes (WitnessHint, Let) that would create
    /// duplicate wires for output signals.
    pub(super) output_pub_vars: HashMap<String, SsaVar>,
}


impl<F: FieldBackend> Instantiator<F> {
    // -------------------------------------------------------------------
    // Span-aware instruction emission
    // -------------------------------------------------------------------

    /// Push an instruction and tag its result with the current source span.
    fn push_inst(&mut self, inst: Instruction<F>) -> SsaVar {
        let var = self.program.push(inst);
        if let Some(span) = &self.current_span {
            self.program.set_span(var, span.clone());
        }
        var
    }

    // -------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------

    pub(super) fn validate_captures(&self, prove_ir: &ProveIR) -> Result<(), ProveIrError> {
        for cap in &prove_ir.captures {
            if !self.captures.contains_key(&cap.name) {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "missing capture value for `{}` — required by the circuit template",
                        cap.name
                    ),
                    span: None,
                });
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // Input declarations
    // -------------------------------------------------------------------

    pub(super) fn declare_input(
        &mut self,
        decl: &ProveInputDecl,
        visibility: Visibility,
    ) -> Result<(), ProveIrError> {
        let ir_type = decl.ir_type;

        match &decl.array_size {
            Some(array_size) => {
                let size = self.resolve_array_size(array_size)?;
                let mut elem_vars = Vec::with_capacity(size);
                for i in 0..size {
                    let elem_name = format!("{}_{i}", decl.name);
                    let v = self.emit_input(&elem_name, visibility, ir_type);
                    self.env.insert(elem_name, InstEnvValue::Scalar(v));
                    elem_vars.push(v);
                }
                self.env
                    .insert(decl.name.clone(), InstEnvValue::Array(elem_vars));
            }
            None => {
                let v = self.emit_input(&decl.name, visibility, ir_type);
                self.env.insert(decl.name.clone(), InstEnvValue::Scalar(v));
            }
        }
        Ok(())
    }

    /// Emit an Input instruction, enforce Bool type with RangeCheck if needed,
    /// and return the final SsaVar (the RangeCheck result if Bool, else the Input result).
    fn emit_input(&mut self, name: &str, visibility: Visibility, ir_type: IrType) -> SsaVar {
        let v = self.program.fresh_var();
        self.push_inst(Instruction::Input {
            result: v,
            name: name.to_string(),
            visibility,
        });
        self.program.set_name(v, name.to_string());
        self.program.set_type(v, ir_type);

        // Bool inputs must be constrained to {0, 1} via RangeCheck(1 bit).
        // Without this, a malicious prover could assign arbitrary field elements
        // to Bool inputs, breaking downstream boolean logic (And, Or, Not, Mux).
        if ir_type == IrType::Bool {
            let enforced = self.program.fresh_var();
            self.push_inst(Instruction::RangeCheck {
                result: enforced,
                operand: v,
                bits: 1,
            });
            self.program.set_type(enforced, IrType::Bool);
            enforced
        } else {
            v
        }
    }

    pub(super) fn declare_capture(&mut self, cap: &CaptureDef) -> Result<(), ProveIrError> {
        // Safe: validate_captures already verified all required captures exist.
        let value =
            *self
                .captures
                .get(&cap.name)
                .ok_or_else(|| ProveIrError::UnsupportedOperation {
                    description: format!("missing capture value for `{}`", cap.name),
                    span: None,
                })?;
        match cap.usage {
            CaptureUsage::CircuitInput | CaptureUsage::Both => {
                // Becomes a witness input — the concrete value is the witness
                // assignment provided by the prover.
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Input {
                    result: v,
                    name: cap.name.clone(),
                    visibility: Visibility::Witness,
                });
                self.program.set_name(v, cap.name.clone());
                self.program.set_type(v, IrType::Field);
                self.env.insert(cap.name.clone(), InstEnvValue::Scalar(v));

                // For `Both` captures: the value is used structurally (loop bounds,
                // array sizes) AND in constraints. We emit an AssertEq to enforce
                // that the witness value matches the structural constant. Without
                // this, a malicious prover could provide a different witness value
                // than the one used for structural decisions (e.g., loop count),
                // producing an unsound proof.
                if cap.usage == CaptureUsage::Both {
                    let const_var = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: const_var,
                        value,
                    });
                    let eq_var = self.program.fresh_var();
                    self.push_inst(Instruction::AssertEq {
                        result: eq_var,
                        lhs: v,
                        rhs: const_var,
                        message: None,
                    });
                }
            }
            CaptureUsage::StructureOnly => {
                // Inlined as a constant — not a circuit wire.
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Const { result: v, value });
                self.program.set_name(v, cap.name.clone());
                self.env.insert(cap.name.clone(), InstEnvValue::Scalar(v));
            }
        }
        Ok(())
    }

    /// Resolve an ArraySize to a concrete usize.
    pub(super) fn resolve_array_size(&self, size: &ArraySize) -> Result<usize, ProveIrError> {
        match size {
            ArraySize::Literal(n) => Ok(*n),
            ArraySize::Capture(name) => {
                let fe =
                    self.captures
                        .get(name)
                        .ok_or_else(|| ProveIrError::UnsupportedOperation {
                            description: format!("missing capture value for array size `{name}`"),
                            span: None,
                        })?;
                fe_to_usize(fe, name)
            }
        }
    }

    // -------------------------------------------------------------------
    // Node emission (CircuitNode → Instructions)
    // -------------------------------------------------------------------

    pub(super) fn emit_node(&mut self, node: &CircuitNode) -> Result<(), ProveIrError> {
        // Set span context: all instructions emitted while processing this node
        // inherit the node's source span for source mapping.
        let prev_span = self.current_span.take();
        if let Some(span) = node.span() {
            self.current_span = Some(span.clone());
        }

        self.emit_node_inner(node)?;

        self.current_span = prev_span;
        Ok(())
    }

    fn emit_node_inner(&mut self, node: &CircuitNode) -> Result<(), ProveIrError> {
        match node {
            CircuitNode::Let { name, value, .. } => {
                // Output signals: don't create a new SSA var. Instead, evaluate
                // the expression and constrain the public wire to equal it.
                if let Some(&pub_var) = self.output_pub_vars.get(name) {
                    let v = self.emit_expr(value)?;
                    let result = self.program.fresh_var();
                    self.push_inst(Instruction::AssertEq {
                        result,
                        lhs: pub_var,
                        rhs: v,
                        message: None,
                    });
                    // env keeps pointing to pub_var (not shadowed)
                } else {
                    let v = self.emit_expr(value)?;
                    self.program.set_name(v, name.clone());
                    self.env.insert(name.clone(), InstEnvValue::Scalar(v));
                }
            }
            CircuitNode::LetArray { name, elements, .. } => {
                let mut elem_vars = Vec::with_capacity(elements.len());
                for (i, elem) in elements.iter().enumerate() {
                    let v = self.emit_expr(elem)?;
                    let elem_name = format!("{name}_{i}");
                    self.program.set_name(v, elem_name.clone());
                    self.env.insert(elem_name, InstEnvValue::Scalar(v));
                    elem_vars.push(v);
                }
                self.env
                    .insert(name.clone(), InstEnvValue::Array(elem_vars));
            }
            CircuitNode::AssertEq {
                lhs, rhs, message, ..
            } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::AssertEq {
                    result: v,
                    lhs: l,
                    rhs: r,
                    message: message.clone(),
                });
            }
            CircuitNode::Assert { expr, message, .. } => {
                let operand = self.emit_expr(expr)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Assert {
                    result: v,
                    operand,
                    message: message.clone(),
                });
            }
            CircuitNode::For {
                var, range, body, ..
            } => {
                self.emit_for(var, range, body)?;
            }
            CircuitNode::If {
                cond: _,
                then_body,
                else_body,
                ..
            } => {
                // In arithmetic circuits, both branches are always emitted
                // (no conditional execution). The Mux selection is handled
                // at the expression level (CircuitExpr::Mux).
                for n in then_body {
                    self.emit_node(n)?;
                }
                for n in else_body {
                    self.emit_node(n)?;
                }
            }
            CircuitNode::Expr { expr, .. } => {
                self.emit_expr(expr)?;
            }
            CircuitNode::Decompose {
                name,
                value,
                num_bits,
                ..
            } => {
                let operand = self.emit_expr(value)?;
                let result = self.program.fresh_var();
                let mut bit_vars = Vec::with_capacity(*num_bits as usize);
                for i in 0..*num_bits {
                    let bit_v = self.program.fresh_var();
                    let elem_name = format!("{name}_{i}");
                    self.program.set_name(bit_v, elem_name.clone());
                    self.env.insert(elem_name, InstEnvValue::Scalar(bit_v));
                    bit_vars.push(bit_v);
                }
                self.push_inst(Instruction::Decompose {
                    result,
                    bit_results: bit_vars.clone(),
                    operand,
                    num_bits: *num_bits,
                });
                self.env.insert(name.clone(), InstEnvValue::Array(bit_vars));
            }
            CircuitNode::WitnessHint { name, .. } => {
                // Output signals: the public wire already exists; skip creating
                // a duplicate witness wire. The prover provides the value as a
                // public input.
                if self.output_pub_vars.contains_key(name) {
                    // env already has the public wire — nothing to do.
                } else {
                    // Witness hint: register as a witness input variable.
                    // The hint expression is NOT compiled to constraints.
                    // The actual value is provided externally by the prover
                    // (computed from the hint expression off-circuit).
                    let v = self.program.fresh_var();
                    self.program.set_name(v, name.clone());
                    self.push_inst(Instruction::Input {
                        result: v,
                        name: name.clone(),
                        visibility: Visibility::Witness,
                    });
                    self.env.insert(name.clone(), InstEnvValue::Scalar(v));
                }
            }
            CircuitNode::LetIndexed {
                array,
                index,
                value,
                ..
            } => {
                // Try evaluating the index as a constant expression first
                // (handles linearized multi-dim indices like i*2+j after loop unroll)
                let idx = if let Ok(fe) = self.eval_const_expr(index) {
                    fe_to_usize(&fe, array)?
                } else {
                    let idx_var = self.emit_expr(index)?;
                    self.extract_const_index(idx_var).ok_or_else(|| {
                        ProveIrError::UnsupportedOperation {
                            description: format!(
                                "indexed assignment into `{array}` requires a compile-time constant index"
                            ),
                            span: None,
                        }
                    })?
                };
                let elem_name = format!("{array}_{idx}");

                // Output signals: constrain the public wire to the expression
                if let Some(&pub_var) = self.output_pub_vars.get(&elem_name) {
                    let v = self.emit_expr(value)?;
                    let result = self.program.fresh_var();
                    self.push_inst(Instruction::AssertEq {
                        result,
                        lhs: pub_var,
                        rhs: v,
                        message: None,
                    });
                    // env keeps pointing to pub_var (not shadowed)
                } else {
                    let v = self.emit_expr(value)?;
                    self.program.set_name(v, elem_name.clone());
                    self.env.insert(elem_name, InstEnvValue::Scalar(v));
                    self.ensure_array_slot(array, idx, v);
                }
            }
            CircuitNode::WitnessHintIndexed { array, index, .. } => {
                let idx = if let Ok(fe) = self.eval_const_expr(index) {
                    fe_to_usize(&fe, array)?
                } else {
                    let idx_var = self.emit_expr(index)?;
                    self.extract_const_index(idx_var).ok_or_else(|| {
                        ProveIrError::UnsupportedOperation {
                            description: format!(
                                "indexed witness hint into `{array}` requires a compile-time constant index"
                            ),
                            span: None,
                        }
                    })?
                };
                let elem_name = format!("{array}_{idx}");

                // Output signals: the public wire already exists; skip duplicate
                if self.output_pub_vars.contains_key(&elem_name) {
                    // env already has the public wire — nothing to do.
                } else {
                    let v = self.program.fresh_var();
                    self.program.set_name(v, elem_name.clone());
                    self.push_inst(Instruction::Input {
                        result: v,
                        name: elem_name.clone(),
                        visibility: Visibility::Witness,
                    });
                    self.env.insert(elem_name, InstEnvValue::Scalar(v));
                    self.ensure_array_slot(array, idx, v);
                }
            }
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // For loop unrolling
    // -------------------------------------------------------------------

    fn emit_for(
        &mut self,
        var: &str,
        range: &ForRange,
        body: &[CircuitNode],
    ) -> Result<(), ProveIrError> {
        match range {
            ForRange::Literal { start, end } => self.emit_range_loop(var, *start, *end, body),
            ForRange::WithCapture { start, end_capture } => {
                let end_fe = self.captures.get(end_capture).ok_or_else(|| {
                    ProveIrError::UnsupportedOperation {
                        description: format!(
                            "missing capture value for loop bound `{end_capture}`"
                        ),
                        span: None,
                    }
                })?;
                let end = fe_to_u64(end_fe, end_capture)?;
                self.emit_range_loop(var, *start, end, body)
            }
            ForRange::WithExpr { start, end_expr } => {
                let end = self.eval_const_expr_u64(end_expr)?;
                self.emit_range_loop(var, *start, end, body)
            }
            ForRange::Array(arr_name) => {
                let elems = match self.env.get(arr_name) {
                    Some(InstEnvValue::Array(elems)) => elems.clone(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!("for loop iterable `{arr_name}` is not an array"),
                            span: None,
                        });
                    }
                };

                self.with_saved_var(var, |this| {
                    for elem_var in &elems {
                        this.env
                            .insert(var.to_string(), InstEnvValue::Scalar(*elem_var));
                        for node in body {
                            this.emit_node(node)?;
                        }
                    }
                    Ok(())
                })
            }
        }
    }

    /// Evaluate a circuit expression to a u64 using capture values.
    ///
    /// Used for `ForRange::WithExpr` where the loop bound is a computed
    /// expression over captures (e.g., `n + 1` from `Num2Bits(n+1)`).
    fn eval_const_expr_u64(&self, expr: &CircuitExpr) -> Result<u64, ProveIrError> {
        let fe = self.eval_const_expr(expr)?;
        fe_to_u64(&fe, "<expr>")
    }

    fn eval_const_expr(&self, expr: &CircuitExpr) -> Result<FieldElement<F>, ProveIrError> {
        match expr {
            CircuitExpr::Const(fc) => {
                fc.to_field::<F>()
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: "constant out of field range".into(),
                        span: None,
                    })
            }
            CircuitExpr::Capture(name) => {
                self.captures
                    .get(name)
                    .copied()
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "missing capture value `{name}` in loop bound expression"
                        ),
                        span: None,
                    })
            }
            CircuitExpr::BinOp { op, lhs, rhs } => {
                let l = self.eval_const_expr(lhs)?;
                let r = self.eval_const_expr(rhs)?;
                match op {
                    CircuitBinOp::Add => Ok(l.add(&r)),
                    CircuitBinOp::Sub => Ok(l.sub(&r)),
                    CircuitBinOp::Mul => Ok(l.mul(&r)),
                    CircuitBinOp::Div => {
                        l.div(&r).ok_or_else(|| ProveIrError::UnsupportedOperation {
                            description: "division by zero in loop bound expression".into(),
                            span: None,
                        })
                    }
                }
            }
            CircuitExpr::Var(name) | CircuitExpr::Input(name) => {
                // Look up the variable in the env — if it's a scalar SSA var
                // that was defined as a Const (e.g., loop variable after unroll),
                // extract its value.
                if let Some(InstEnvValue::Scalar(ssa)) = self.env.get(name) {
                    let ssa = *ssa;
                    for inst in self.program.instructions.iter().rev() {
                        if inst.result_var() == ssa {
                            if let Instruction::Const { value, .. } = inst {
                                return Ok(*value);
                            }
                            break;
                        }
                    }
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "variable `{name}` is not a compile-time constant in this context"
                    ),
                    span: None,
                })
            }
            CircuitExpr::ShiftL { operand, shift, .. } => {
                // `x << s` is `x * 2^s` in the field. Use `FieldElement::pow`
                // so shifts >= 64 (e.g. circomlib's `LessThan(64)` computing
                // `1 << 64`) don't collapse to 0 via `u64::checked_shl`.
                // BN254 is 254-bit so `2^s` for `s <= 253` is always a
                // valid field element; shifts larger than that overflow
                // the field and we bail out explicitly rather than
                // silently wrap.
                let op_val = self.eval_const_expr(operand)?;
                let shift_val = self.eval_const_expr_u64(shift)?;
                if shift_val >= 254 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "left shift amount {shift_val} exceeds BN254 field width (254 bits)"
                        ),
                        span: None,
                    });
                }
                let two = FieldElement::<F>::from_u64(2);
                let two_to_s = two.pow(&[shift_val, 0, 0, 0]);
                Ok(op_val.mul(&two_to_s))
            }
            CircuitExpr::ShiftR { operand, shift, .. } => {
                let op_val = self.eval_const_expr_u64(operand)?;
                let shift_val = self.eval_const_expr_u64(shift)?;
                let result = if shift_val >= 64 {
                    0
                } else {
                    op_val >> (shift_val as u32)
                };
                Ok(FieldElement::<F>::from_u64(result))
            }
            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("unsupported expression in const eval: {expr:?}"),
                span: None,
            }),
        }
    }

    /// Unroll a numeric range loop: for var in start..end { body }
    fn emit_range_loop(
        &mut self,
        var: &str,
        start: u64,
        end: u64,
        body: &[CircuitNode],
    ) -> Result<(), ProveIrError> {
        let iterations = end.saturating_sub(start);
        if iterations > MAX_INSTANTIATE_ITERATIONS {
            return Err(ProveIrError::RangeTooLarge {
                iterations,
                max: MAX_INSTANTIATE_ITERATIONS,
                span: None,
            });
        }
        self.with_saved_var(var, |this| {
            for i in start..end {
                let v = this.program.fresh_var();
                this.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::<F>::from_u64(i),
                });
                this.program.set_name(v, var.to_string());
                this.env.insert(var.to_string(), InstEnvValue::Scalar(v));

                for node in body {
                    this.emit_node(node)?;
                }
            }
            Ok(())
        })
    }

    /// Save a variable's env binding, run a closure, then restore it.
    fn with_saved_var<Func>(&mut self, var: &str, f: Func) -> Result<(), ProveIrError>
    where
        Func: FnOnce(&mut Self) -> Result<(), ProveIrError>,
    {
        let saved = self.env.get(var).cloned();
        let result = f(self);
        match saved {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }
        result
    }

    // -------------------------------------------------------------------
    // Expression emission (CircuitExpr → SsaVar)
    // -------------------------------------------------------------------

    fn emit_expr(&mut self, expr: &CircuitExpr) -> Result<SsaVar, ProveIrError> {
        match expr {
            CircuitExpr::Const(field_const) => {
                let fe = field_const.to_field::<F>().ok_or_else(|| {
                    ProveIrError::UnsupportedOperation {
                        description: format!(
                            "field constant {field_const:?} is not valid in the target field"
                        ),
                        span: None,
                    }
                })?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Const {
                    result: v,
                    value: fe,
                });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::Input(name) => self.resolve_scalar(name),
            CircuitExpr::Var(name) => self.resolve_scalar(name),
            CircuitExpr::Capture(name) => {
                // Captures should already be in env (declared in step 4).
                // If not, it means the capture classification missed it.
                self.resolve_scalar(name)
            }
            CircuitExpr::BinOp { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                let inst = match op {
                    CircuitBinOp::Add => Instruction::Add {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBinOp::Sub => Instruction::Sub {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBinOp::Mul => Instruction::Mul {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBinOp::Div => Instruction::Div {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                };
                self.push_inst(inst);
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::UnaryOp { op, operand } => {
                let inner = self.emit_expr(operand)?;
                let v = self.program.fresh_var();
                let inst = match op {
                    CircuitUnaryOp::Neg => Instruction::Neg {
                        result: v,
                        operand: inner,
                    },
                    CircuitUnaryOp::Not => Instruction::Not {
                        result: v,
                        operand: inner,
                    },
                };
                self.push_inst(inst);
                let ty = match op {
                    CircuitUnaryOp::Neg => IrType::Field,
                    CircuitUnaryOp::Not => IrType::Bool,
                };
                self.program.set_type(v, ty);
                Ok(v)
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                // Gt and Ge are desugared by swapping operands.
                let inst = match op {
                    CircuitCmpOp::Eq => Instruction::IsEq {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Neq => Instruction::IsNeq {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Lt => Instruction::IsLt {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Le => Instruction::IsLe {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Gt => Instruction::IsLt {
                        result: v,
                        lhs: r,
                        rhs: l,
                    },
                    CircuitCmpOp::Ge => Instruction::IsLe {
                        result: v,
                        lhs: r,
                        rhs: l,
                    },
                };
                self.push_inst(inst);
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                let inst = match op {
                    CircuitBoolOp::And => Instruction::And {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBoolOp::Or => Instruction::Or {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                };
                self.push_inst(inst);
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => {
                let c = self.emit_expr(cond)?;
                let t = self.emit_expr(if_true)?;
                let f = self.emit_expr(if_false)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Mux {
                    result: v,
                    cond: c,
                    if_true: t,
                    if_false: f,
                });
                // Propagate type if both branches agree
                if let (Some(tt), Some(ft)) = (self.program.get_type(t), self.program.get_type(f)) {
                    if tt == ft {
                        self.program.set_type(v, tt);
                    }
                }
                Ok(v)
            }
            CircuitExpr::PoseidonHash { left, right } => {
                let l = self.emit_expr(left)?;
                let r = self.emit_expr(right)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::PoseidonHash {
                    result: v,
                    left: l,
                    right: r,
                });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::PoseidonMany(args) => {
                if args.is_empty() {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "poseidon_many requires at least 2 arguments".into(),
                        span: None,
                    });
                }

                let compiled: Vec<SsaVar> = args
                    .iter()
                    .map(|a| self.emit_expr(a))
                    .collect::<Result<_, _>>()?;

                if compiled.len() == 1 {
                    // Match IrLowering semantics: single arg → poseidon(arg, ZERO)
                    let zero = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: zero,
                        value: FieldElement::<F>::zero(),
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left: compiled[0],
                        right: zero,
                    });
                    return Ok(v);
                }

                // Left-fold: poseidon(poseidon(a0, a1), a2), ...
                let mut iter = compiled.into_iter();
                let mut acc = iter.next().expect("checked non-empty above");
                for next in iter {
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left: acc,
                        right: next,
                    });
                    acc = v;
                }
                Ok(acc)
            }
            CircuitExpr::RangeCheck { value, bits } => {
                let operand = self.emit_expr(value)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::RangeCheck {
                    result: v,
                    operand,
                    bits: *bits,
                });
                Ok(v)
            }
            CircuitExpr::MerkleVerify {
                root,
                leaf,
                path,
                indices,
            } => {
                // Merkle verification: hash leaf up the tree using path and indices.
                // path and indices are arrays in env.
                let root_var = self.emit_expr(root)?;
                let leaf_var = self.emit_expr(leaf)?;

                let path_elems = match self.env.get(path) {
                    Some(InstEnvValue::Array(elems)) => elems.clone(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!("merkle_verify path `{path}` is not an array"),
                            span: None,
                        });
                    }
                };
                let idx_elems = match self.env.get(indices) {
                    Some(InstEnvValue::Array(elems)) => elems.clone(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "merkle_verify indices `{indices}` is not an array"
                            ),
                            span: None,
                        });
                    }
                };

                if path_elems.len() != idx_elems.len() {
                    return Err(ProveIrError::ArrayLengthMismatch {
                        expected: path_elems.len(),
                        got: idx_elems.len(),
                        span: None,
                    });
                }

                // Walk up the tree: conditional swap + single hash per level.
                // idx=0 → current is left child:  poseidon(current, sibling)
                // idx=1 → current is right child: poseidon(sibling, current)
                // Cost: 2 Mux + 1 Poseidon (365) instead of 2 Poseidon + 1 Mux (724).
                let mut current = leaf_var;
                for (sibling, idx) in path_elems.iter().zip(idx_elems.iter()) {
                    let left = self.program.fresh_var();
                    self.push_inst(Instruction::Mux {
                        result: left,
                        cond: *idx,
                        if_true: *sibling,
                        if_false: current,
                    });
                    let right = self.program.fresh_var();
                    self.push_inst(Instruction::Mux {
                        result: right,
                        cond: *idx,
                        if_true: current,
                        if_false: *sibling,
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left,
                        right,
                    });
                    current = v;
                }

                // Assert computed root == expected root
                let v = self.program.fresh_var();
                self.push_inst(Instruction::AssertEq {
                    result: v,
                    lhs: current,
                    rhs: root_var,
                    message: None,
                });
                Ok(v)
            }
            CircuitExpr::ArrayIndex { array, index } => {
                // The index must resolve to a constant. Try evaluating as a
                // constant expression first (handles captures like `n` that are
                // known at instantiation time), then fall back to emitting and
                // extracting from the instruction stream.
                let idx = self
                    .eval_const_expr(index)
                    .ok()
                    .and_then(|fe| {
                        let limbs = fe.to_canonical();
                        if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                            usize::try_from(limbs[0]).ok()
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        let idx_var = self.emit_expr(index).ok()?;
                        self.extract_const_index(idx_var)
                    })
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "array index into `{array}` must be a compile-time constant"
                        ),
                        span: None,
                    })?;

                match self.env.get(array) {
                    Some(InstEnvValue::Array(elems)) => {
                        if idx >= elems.len() {
                            return Err(ProveIrError::IndexOutOfBounds {
                                name: array.clone(),
                                index: idx,
                                length: elems.len(),
                                span: None,
                            });
                        }
                        Ok(elems[idx])
                    }
                    _ => Err(ProveIrError::UnsupportedOperation {
                        description: format!("`{array}` is not an array"),
                        span: None,
                    }),
                }
            }
            CircuitExpr::ArrayLen(name) => {
                let len = match self.env.get(name) {
                    Some(InstEnvValue::Array(elems)) => elems.len(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!("`{name}` is not an array"),
                            span: None,
                        });
                    }
                };
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Const {
                    result: v,
                    value: FieldElement::<F>::from_u64(len as u64),
                });
                Ok(v)
            }
            CircuitExpr::Pow { base, exp } => {
                let base_var = self.emit_expr(base)?;
                self.emit_pow(base_var, *exp)
            }
            CircuitExpr::IntDiv { lhs, rhs, max_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::IntDiv {
                    result: v,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits,
                });
                Ok(v)
            }
            CircuitExpr::IntMod { lhs, rhs, max_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::IntMod {
                    result: v,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits,
                });
                Ok(v)
            }

            // ── Bitwise operations (expanded via Decompose) ────────
            CircuitExpr::BitAnd { lhs, rhs, num_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, *num_bits, BitwiseOp::And)
            }
            CircuitExpr::BitOr { lhs, rhs, num_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, *num_bits, BitwiseOp::Or)
            }
            CircuitExpr::BitXor { lhs, rhs, num_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, *num_bits, BitwiseOp::Xor)
            }
            CircuitExpr::BitNot { operand, num_bits } => {
                let op = self.emit_expr(operand)?;
                self.emit_bitnot(op, *num_bits)
            }
            CircuitExpr::ShiftR {
                operand,
                shift,
                num_bits,
            } => {
                // If both operand and shift are compile-time constants, fold entirely
                if let Ok(fe) = self.eval_const_expr(expr) {
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: v,
                        value: fe,
                    });
                    return Ok(v);
                }
                let op = self.emit_expr(operand)?;
                let shift_val = self.resolve_const_u32(shift, "shift right amount")?;
                self.emit_shift_right(op, shift_val, *num_bits)
            }
            CircuitExpr::ShiftL {
                operand,
                shift,
                num_bits,
            } => {
                // If both operand and shift are compile-time constants, fold entirely
                if let Ok(fe) = self.eval_const_expr(expr) {
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: v,
                        value: fe,
                    });
                    return Ok(v);
                }
                let op = self.emit_expr(operand)?;
                let shift_val = self.resolve_const_u32(shift, "shift left amount")?;
                self.emit_shift_left(op, shift_val, *num_bits)
            }
        }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// Resolve a name to a scalar SsaVar from the environment.
    fn resolve_scalar(&self, name: &str) -> Result<SsaVar, ProveIrError> {
        match self.env.get(name) {
            Some(InstEnvValue::Scalar(v)) => Ok(*v),
            Some(InstEnvValue::Array(_)) => Err(ProveIrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: None,
            }),
            None => Err(ProveIrError::UndeclaredVariable {
                name: name.into(),
                span: None,
                suggestion: None,
            }),
        }
    }

    /// Emit a power chain: base^exp as repeated multiplication.
    fn emit_pow(&mut self, base: SsaVar, exp: u64) -> Result<SsaVar, ProveIrError> {
        if exp == 0 {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Const {
                result: v,
                value: FieldElement::<F>::one(),
            });
            return Ok(v);
        }

        // Square-and-multiply for efficiency
        let mut result = None;
        let mut current = base;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = Some(match result {
                    None => current,
                    Some(acc) => {
                        let v = self.program.fresh_var();
                        self.push_inst(Instruction::Mul {
                            result: v,
                            lhs: acc,
                            rhs: current,
                        });
                        v
                    }
                });
            }
            e >>= 1;
            if e > 0 {
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Mul {
                    result: v,
                    lhs: current,
                    rhs: current,
                });
                current = v;
            }
        }

        Ok(result.unwrap_or(base))
    }

    // -------------------------------------------------------------------
    // Bitwise operation expansion
    // -------------------------------------------------------------------

    /// Decompose a value into `num_bits` individual bit variables.
    /// Returns the vector of bit SsaVars (LSB first).
    fn emit_decompose_bits(
        &mut self,
        operand: SsaVar,
        num_bits: u32,
    ) -> Result<Vec<SsaVar>, ProveIrError> {
        let result = self.program.fresh_var();
        let mut bit_vars = Vec::with_capacity(num_bits as usize);
        for _ in 0..num_bits {
            bit_vars.push(self.program.fresh_var());
        }
        self.push_inst(Instruction::Decompose {
            result,
            bit_results: bit_vars.clone(),
            operand,
            num_bits,
        });
        Ok(bit_vars)
    }

    /// Recompose bits (LSB first) back into a single field element: Σ bit_i * 2^i
    fn emit_recompose(&mut self, bits: &[SsaVar]) -> Result<SsaVar, ProveIrError> {
        if bits.is_empty() {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Const {
                result: v,
                value: FieldElement::<F>::zero(),
            });
            return Ok(v);
        }

        let mut acc = bits[0]; // bit_0 * 2^0 = bit_0
        let mut power_of_two = FieldElement::<F>::from_u64(2);

        for &bit in &bits[1..] {
            // coeff = 2^i
            let coeff_var = self.program.fresh_var();
            self.push_inst(Instruction::Const {
                result: coeff_var,
                value: power_of_two,
            });
            // term = bit * 2^i
            let term = self.program.fresh_var();
            self.push_inst(Instruction::Mul {
                result: term,
                lhs: bit,
                rhs: coeff_var,
            });
            // acc = acc + term
            let new_acc = self.program.fresh_var();
            self.push_inst(Instruction::Add {
                result: new_acc,
                lhs: acc,
                rhs: term,
            });
            acc = new_acc;
            power_of_two = power_of_two.add(&power_of_two); // 2^(i+1)
        }

        Ok(acc)
    }

    /// Emit a bitwise binary operation (AND, OR, XOR).
    fn emit_bitwise_binop(
        &mut self,
        lhs: SsaVar,
        rhs: SsaVar,
        num_bits: u32,
        op: BitwiseOp,
    ) -> Result<SsaVar, ProveIrError> {
        let bits_l = self.emit_decompose_bits(lhs, num_bits)?;
        let bits_r = self.emit_decompose_bits(rhs, num_bits)?;

        let mut result_bits = Vec::with_capacity(num_bits as usize);
        for i in 0..num_bits as usize {
            let bit = match op {
                BitwiseOp::And => {
                    // AND: a * b
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: v,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    v
                }
                BitwiseOp::Or => {
                    // OR: a + b - a*b
                    let ab = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: ab,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let sum = self.program.fresh_var();
                    self.push_inst(Instruction::Add {
                        result: sum,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Sub {
                        result: v,
                        lhs: sum,
                        rhs: ab,
                    });
                    v
                }
                BitwiseOp::Xor => {
                    // XOR: a + b - 2*a*b
                    let ab = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: ab,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let two = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: two,
                        value: FieldElement::<F>::from_u64(2),
                    });
                    let two_ab = self.program.fresh_var();
                    self.push_inst(Instruction::Mul {
                        result: two_ab,
                        lhs: two,
                        rhs: ab,
                    });
                    let sum = self.program.fresh_var();
                    self.push_inst(Instruction::Add {
                        result: sum,
                        lhs: bits_l[i],
                        rhs: bits_r[i],
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Sub {
                        result: v,
                        lhs: sum,
                        rhs: two_ab,
                    });
                    v
                }
            };
            result_bits.push(bit);
        }

        self.emit_recompose(&result_bits)
    }

    /// Emit bitwise NOT: decompose, flip each bit (1 - bit), recompose.
    fn emit_bitnot(&mut self, operand: SsaVar, num_bits: u32) -> Result<SsaVar, ProveIrError> {
        let bits = self.emit_decompose_bits(operand, num_bits)?;
        let one = self.program.fresh_var();
        self.push_inst(Instruction::Const {
            result: one,
            value: FieldElement::<F>::one(),
        });

        let mut result_bits = Vec::with_capacity(num_bits as usize);
        for &bit in &bits {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Sub {
                result: v,
                lhs: one,
                rhs: bit,
            });
            result_bits.push(v);
        }

        self.emit_recompose(&result_bits)
    }

    /// Emit right shift: decompose, take bits[shift..], recompose.
    fn emit_shift_right(
        &mut self,
        operand: SsaVar,
        shift: u32,
        num_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        if shift >= num_bits {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Const {
                result: v,
                value: FieldElement::<F>::zero(),
            });
            return Ok(v);
        }
        let bits = self.emit_decompose_bits(operand, num_bits)?;
        // Right shift: drop the lowest `shift` bits
        let shifted_bits = &bits[shift as usize..];
        self.emit_recompose(shifted_bits)
    }

    /// Emit left shift: decompose, prepend `shift` zero bits, recompose.
    fn emit_shift_left(
        &mut self,
        operand: SsaVar,
        shift: u32,
        num_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        if shift >= num_bits {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Const {
                result: v,
                value: FieldElement::<F>::zero(),
            });
            return Ok(v);
        }
        let bits = self.emit_decompose_bits(operand, num_bits)?;
        // Left shift: prepend `shift` zeros, truncate to num_bits
        let zero = self.program.fresh_var();
        self.push_inst(Instruction::Const {
            result: zero,
            value: FieldElement::<F>::zero(),
        });
        let mut shifted_bits: Vec<SsaVar> = vec![zero; shift as usize];
        let remaining = (num_bits - shift) as usize;
        shifted_bits.extend_from_slice(&bits[..remaining.min(bits.len())]);
        self.emit_recompose(&shifted_bits)
    }

    /// Try to extract a constant usize from the last emitted instruction
    /// (the one that defined `var`).
    fn extract_const_index(&self, var: SsaVar) -> Option<usize> {
        // Walk backwards to find the instruction that defines this variable
        for inst in self.program.instructions.iter().rev() {
            if inst.result_var() == var {
                if let Instruction::Const { value, .. } = inst {
                    let limbs = value.to_canonical();
                    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                        return usize::try_from(limbs[0]).ok();
                    }
                }
                return None;
            }
        }
        None
    }

    /// Ensure an array exists in the env and has at least `idx + 1` slots.
    /// Creates the array lazily if it doesn't exist, and extends it with
    /// placeholder variables if needed.
    fn ensure_array_slot(&mut self, array: &str, idx: usize, var: SsaVar) {
        match self.env.get_mut(array) {
            Some(InstEnvValue::Array(arr)) => {
                // Extend if needed
                while arr.len() <= idx {
                    let placeholder = self.program.fresh_var();
                    arr.push(placeholder);
                }
                arr[idx] = var;
            }
            Some(InstEnvValue::Scalar(_)) => {
                // Name collision — don't overwrite scalar
            }
            None => {
                // Create array lazily
                let mut arr = Vec::with_capacity(idx + 1);
                for _ in 0..idx {
                    let placeholder = self.program.fresh_var();
                    arr.push(placeholder);
                }
                arr.push(var);
                self.env.insert(array.to_string(), InstEnvValue::Array(arr));
            }
        }
    }

    /// Extract a constant u32 from an emitted variable, with a descriptive error.
    fn extract_const_u32(&self, var: SsaVar, context: &str) -> Result<u32, ProveIrError> {
        self.extract_const_index(var)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| ProveIrError::UnsupportedOperation {
                description: format!("{context} must be a compile-time constant"),
                span: None,
            })
    }

    /// Resolve a circuit expression to a u32 constant, trying eval_const_expr
    /// first (for captures) then falling back to emit + extract.
    fn resolve_const_u32(
        &mut self,
        expr: &CircuitExpr,
        context: &str,
    ) -> Result<u32, ProveIrError> {
        // Try constant evaluation first (handles captures and arithmetic)
        if let Ok(fe) = self.eval_const_expr(expr) {
            let val = fe_to_u64(&fe, context)?;
            return u32::try_from(val).map_err(|_| ProveIrError::UnsupportedOperation {
                description: format!("{context} too large for u32"),
                span: None,
            });
        }
        // Fall back to emit + extract
        let var = self.emit_expr(expr)?;
        self.extract_const_u32(var, context)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
