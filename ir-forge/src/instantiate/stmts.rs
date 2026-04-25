//! Statement-level emission on [`Instantiator`].
//!
//! These walk a [`CircuitNode`] tree and emit the corresponding flat IR
//! [`Instruction`]s. The big surface here is `emit_node` (the dispatch),
//! `emit_for` (loop unrolling against concrete capture-bound ranges),
//! and the two compile-time evaluators that resolve loop bounds and
//! array sizes. `with_saved_var` is the per-iteration env helper used
//! by both for-range and for-array unrolling.
//!
//! Expression emission lives in [`super::exprs`]; bit-level helpers
//! live in [`super::bits`].

use memory::{FieldBackend, FieldElement};

use super::utils::{fe_to_u64, fe_to_usize};
use super::{InstEnvValue, Instantiator, LoopUnrollMode, MAX_INSTANTIATE_ITERATIONS};
use crate::error::ProveIrError;
use crate::extended::IndexedEffectKind;
use crate::types::*;
use ir_core::{Instruction, SsaVar, Visibility};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
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
                    let result = self.fresh_var();
                    self.push_inst(Instruction::AssertEq {
                        result,
                        lhs: pub_var,
                        rhs: v,
                        message: None,
                    });
                    // env keeps pointing to pub_var (not shadowed)
                } else {
                    let v = self.emit_expr(value)?;
                    self.set_name(v, name.clone());
                    self.env.insert(name.clone(), InstEnvValue::Scalar(v));
                }
            }
            CircuitNode::LetArray { name, elements, .. } => {
                let mut elem_vars = Vec::with_capacity(elements.len());
                for (i, elem) in elements.iter().enumerate() {
                    let v = self.emit_expr(elem)?;
                    let elem_name = format!("{name}_{i}");
                    self.set_name(v, elem_name.clone());
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
                let v = self.fresh_var();
                self.push_inst(Instruction::AssertEq {
                    result: v,
                    lhs: l,
                    rhs: r,
                    message: message.clone(),
                });
            }
            CircuitNode::Assert { expr, message, .. } => {
                let operand = self.emit_expr(expr)?;
                // Lower Assert(x) → AssertEq(x, 1). The Lysis lifter's
                // Walker performs the same desugaring at lift time;
                // emitting it here keeps the legacy and Lysis paths
                // byte-equivalent in R1CS multiset (Phase 3.C.6
                // Stage 1 finding).
                let one = self.emit_const(FieldElement::<F>::one());
                let v = self.fresh_var();
                self.push_inst(Instruction::AssertEq {
                    result: v,
                    lhs: operand,
                    rhs: one,
                    message: message.clone(),
                });
            }
            CircuitNode::For {
                var, range, body, ..
            } => {
                self.emit_for(var, range, body)?;
            }
            CircuitNode::If {
                cond,
                then_body,
                else_body,
                ..
            } => {
                // Compile-time-known conditions select exactly one branch.
                // Circomlib patterns like `ShR`'s `if (i+r >= n) { out <== 0 }
                // else { out <== in[i+r] }` rely on this — the untaken branch
                // would access out-of-bounds signal slots. When cond depends
                // on a runtime signal, fall back to emitting both branches
                // (downstream Mux handles selection at the value level).
                match self.eval_const_expr(cond) {
                    Ok(c) => {
                        let taken = if c.is_zero() { else_body } else { then_body };
                        for n in taken {
                            self.emit_node(n)?;
                        }
                    }
                    Err(_) => {
                        for n in then_body {
                            self.emit_node(n)?;
                        }
                        for n in else_body {
                            self.emit_node(n)?;
                        }
                    }
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
                let result = self.fresh_var();
                let mut bit_vars = Vec::with_capacity(*num_bits as usize);
                for i in 0..*num_bits {
                    let bit_v = self.fresh_var();
                    let elem_name = format!("{name}_{i}");
                    self.set_name(bit_v, elem_name.clone());
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
                    let v = self.fresh_var();
                    self.set_name(v, name.clone());
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
                // Const-index fast path: linearized indices like
                // `i*2+j` after loop unroll fold here, plus literal
                // `arr[3]`. Resolves before any IR emission so the
                // const-index handlers below stay byte-identical.
                if let Ok(fe) = self.eval_const_expr(index) {
                    let idx = fe_to_usize(&fe, array)?;
                    self.emit_let_indexed_const(array, idx, value)?;
                } else {
                    // Symbolic index. Two paths split by sink mode:
                    //   - Symbolic (ExtendedSink): emit a structured
                    //     SymbolicIndexedEffect carrying the resolved
                    //     `array_slots` snapshot for the walker to
                    //     materialise per iteration.
                    //   - PerIteration (LegacySink): preserve the
                    //     existing UnsupportedOperation error — the
                    //     legacy R1CS path can't carry symbolic
                    //     indices and circom-side
                    //     `IndexedAssignmentLoop` lowering already
                    //     unrolled them at lowering time.
                    let idx_var = self.emit_expr(index)?;
                    match self.sink.loop_unroll_mode() {
                        LoopUnrollMode::Symbolic => {
                            self.emit_let_indexed_symbolic(array, idx_var, value)?;
                        }
                        LoopUnrollMode::PerIteration => {
                            // LegacySink path: try the SsaVar
                            // const-fold once for back-compat with
                            // multi-dim linearised indices that don't
                            // fold via `eval_const_expr`. If still no
                            // const, surface the historical error.
                            if let Some(idx) = self.extract_const_index(idx_var) {
                                self.emit_let_indexed_const(array, idx, value)?;
                            } else {
                                return Err(ProveIrError::UnsupportedOperation {
                                    description: format!(
                                        "indexed assignment into `{array}` requires a compile-time constant index"
                                    ),
                                    span: None,
                                });
                            }
                        }
                    }
                }
            }
            CircuitNode::WitnessHintIndexed { array, index, .. } => {
                if let Ok(fe) = self.eval_const_expr(index) {
                    let idx = fe_to_usize(&fe, array)?;
                    self.emit_witness_hint_indexed_const(array, idx)?;
                } else {
                    let idx_var = self.emit_expr(index)?;
                    match self.sink.loop_unroll_mode() {
                        LoopUnrollMode::Symbolic => {
                            self.emit_witness_hint_indexed_symbolic(array, idx_var)?;
                        }
                        LoopUnrollMode::PerIteration => {
                            if let Some(idx) = self.extract_const_index(idx_var) {
                                self.emit_witness_hint_indexed_const(array, idx)?;
                            } else {
                                return Err(ProveIrError::UnsupportedOperation {
                                    description: format!(
                                        "indexed witness hint into `{array}` requires a compile-time constant index"
                                    ),
                                    span: None,
                                });
                            }
                        }
                    }
                }
            }
            CircuitNode::WitnessCall {
                output_bindings,
                input_signals,
                program_bytes,
                ..
            } => {
                // Artik witness-calculator call. Emit an
                // `Instruction::WitnessCall` carrying the bytecode +
                // input SsaVars + output SsaVars. The prover's
                // witness generator decodes + runs the Artik program
                // at witness-gen time, filling each output wire with
                // the value its slot writes.
                //
                // Output signals take precedence over the default
                // witness wire (same rule as `WitnessHint`): if a
                // binding name is already a public output wire, it
                // was pre-allocated in `self.output_pub_vars`. The
                // instruction writes directly into that wire so the
                // public-output channel receives the Artik result.
                let mut inputs: Vec<SsaVar> = Vec::with_capacity(input_signals.len());
                for expr in input_signals {
                    inputs.push(self.emit_expr(expr)?);
                }
                let mut outputs: Vec<SsaVar> = Vec::with_capacity(output_bindings.len());
                for name in output_bindings {
                    let v = if let Some(&existing) = self.output_pub_vars.get(name) {
                        existing
                    } else {
                        let fresh = self.fresh_var();
                        self.set_name(fresh, name.clone());
                        self.env.insert(name.clone(), InstEnvValue::Scalar(fresh));
                        fresh
                    };
                    outputs.push(v);
                }
                self.push_inst(Instruction::WitnessCall {
                    outputs,
                    inputs,
                    program_bytes: program_bytes.clone(),
                });
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
    pub(super) fn eval_const_expr_u64(&self, expr: &CircuitExpr) -> Result<u64, ProveIrError> {
        let fe = self.eval_const_expr(expr)?;
        fe_to_u64(&fe, "<expr>")
    }

    pub(super) fn eval_const_expr(
        &self,
        expr: &CircuitExpr,
    ) -> Result<FieldElement<F>, ProveIrError> {
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
                            "missing capture value `{name}` in constant expression"
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
                            description: "division by zero in constant expression".into(),
                            span: None,
                        })
                    }
                }
            }
            CircuitExpr::UnaryOp { op, operand } => {
                let v = self.eval_const_expr(operand)?;
                match op {
                    CircuitUnaryOp::Neg => Ok(v.neg()),
                    CircuitUnaryOp::Not => {
                        // Logical NOT on 0/1: 1 - v. For non-bool values
                        // circom treats this as (v == 0).
                        Ok(if v.is_zero() {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        })
                    }
                }
            }
            CircuitExpr::Var(name) | CircuitExpr::Input(name) => {
                // Look up the variable in the env — if it's a scalar SSA var
                // that was defined as a Const (e.g., loop variable after unroll),
                // extract its value via the const_values cache.
                if let Some(InstEnvValue::Scalar(ssa)) = self.env.get(name) {
                    if let Some(value) = self.const_value_of(*ssa) {
                        return Ok(value);
                    }
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "variable `{name}` is not a compile-time constant in this context"
                    ),
                    span: None,
                })
            }
            // Integer-semantic ops: evaluate as u64 arithmetic, return as
            // field element. Circomlib's rotation / shift templates
            // (e.g. `RotR(n, r)`, `ShR(n, r)`) produce `(i+r) % n` and
            // `i + r` on loop vars + captures — both must fold here so
            // the downstream signal-array index resolves to a literal.
            CircuitExpr::IntDiv { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                if r == 0 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "integer division by zero in constant expression".into(),
                        span: None,
                    });
                }
                Ok(FieldElement::<F>::from_u64(l / r))
            }
            CircuitExpr::IntMod { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                if r == 0 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "modulo by zero in constant expression".into(),
                        span: None,
                    });
                }
                Ok(FieldElement::<F>::from_u64(l % r))
            }
            CircuitExpr::BitAnd { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                Ok(FieldElement::<F>::from_u64(l & r))
            }
            CircuitExpr::BitOr { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                Ok(FieldElement::<F>::from_u64(l | r))
            }
            CircuitExpr::BitXor { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                Ok(FieldElement::<F>::from_u64(l ^ r))
            }
            CircuitExpr::BitNot { operand, num_bits } => {
                let v = self.eval_const_expr_u64(operand)?;
                let mask = if *num_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << num_bits) - 1
                };
                Ok(FieldElement::<F>::from_u64((!v) & mask))
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
            CircuitExpr::Pow { base, exp } => {
                let b = self.eval_const_expr(base)?;
                Ok(b.pow(&[*exp, 0, 0, 0]))
            }
            CircuitExpr::ArrayLen(name) => match self.env.get(name) {
                Some(InstEnvValue::Array(elems)) => {
                    Ok(FieldElement::<F>::from_u64(elems.len() as u64))
                }
                _ => Err(ProveIrError::UnsupportedOperation {
                    description: format!("`{name}` is not an array in const eval"),
                    span: None,
                }),
            },
            CircuitExpr::ArrayIndex { array, index } => {
                let idx = fe_to_usize(&self.eval_const_expr(index)?, array)?;
                match self.env.get(array) {
                    Some(InstEnvValue::Array(elems)) => {
                        let ssa = elems.get(idx).copied().ok_or_else(|| {
                            ProveIrError::IndexOutOfBounds {
                                name: array.clone(),
                                index: idx,
                                length: elems.len(),
                                span: None,
                            }
                        })?;
                        if let Some(value) = self.const_value_of(ssa) {
                            return Ok(value);
                        }
                        Err(ProveIrError::UnsupportedOperation {
                            description: format!("`{array}[{idx}]` is not a compile-time constant"),
                            span: None,
                        })
                    }
                    _ => Err(ProveIrError::UnsupportedOperation {
                        description: format!("`{array}` is not an array"),
                        span: None,
                    }),
                }
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                let l = self.eval_const_expr(lhs)?;
                let r = self.eval_const_expr(rhs)?;
                let (ok, descr): (bool, &str) = match op {
                    CircuitCmpOp::Eq => (l == r, "=="),
                    CircuitCmpOp::Neq => (l != r, "!="),
                    // Ordering on field elements is treated as u64-signed
                    // for small captures (loop bounds, array sizes). This
                    // matches the sign of values template authors actually
                    // use in const contexts.
                    CircuitCmpOp::Lt => (fe_to_u64(&l, "<")? < fe_to_u64(&r, "<")?, "<"),
                    CircuitCmpOp::Le => (fe_to_u64(&l, "<=")? <= fe_to_u64(&r, "<=")?, "<="),
                    CircuitCmpOp::Gt => (fe_to_u64(&l, ">")? > fe_to_u64(&r, ">")?, ">"),
                    CircuitCmpOp::Ge => (fe_to_u64(&l, ">=")? >= fe_to_u64(&r, ">=")?, ">="),
                };
                let _ = descr;
                Ok(if ok {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                })
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                let l = self.eval_const_expr(lhs)?;
                let r = self.eval_const_expr(rhs)?;
                let lb = !l.is_zero();
                let rb = !r.is_zero();
                let out = match op {
                    CircuitBoolOp::And => lb && rb,
                    CircuitBoolOp::Or => lb || rb,
                };
                Ok(if out {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                })
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => {
                let c = self.eval_const_expr(cond)?;
                if !c.is_zero() {
                    self.eval_const_expr(if_true)
                } else {
                    self.eval_const_expr(if_false)
                }
            }
            // Nodes below emit gadgets (hash, merkle, range) or cannot
            // appear in const position. Failing here tells the caller
            // to fall back to emit + extract_const_index, which is the
            // correct behaviour when the expression genuinely depends
            // on a runtime signal.
            CircuitExpr::PoseidonHash { .. }
            | CircuitExpr::PoseidonMany(_)
            | CircuitExpr::RangeCheck { .. }
            | CircuitExpr::MerkleVerify { .. } => Err(ProveIrError::UnsupportedOperation {
                description: "gadget expression not allowed in const eval".into(),
                span: None,
            }),
        }
    }

    /// Unroll a numeric range loop: `for var in start..end { body }`.
    ///
    /// Two emission strategies depending on
    /// [`InstrSink::loop_unroll_mode`]:
    ///
    /// - **PerIteration (LegacySink):** emit body once per `i in
    ///   start..end`, binding `var` to a fresh `Const(i)` SSA wire
    ///   each iteration. Byte-identical to the pre-Stage-2 pipeline.
    /// - **Symbolic (ExtendedSink):** allocate one fresh SSA slot for
    ///   `var`, switch the sink to a sub-buffer
    ///   ([`InstrSink::begin_symbolic_loop`]), emit body **once** with
    ///   `var` symbolically bound to that slot, then close with
    ///   [`InstrSink::finish_symbolic_loop`] which folds the
    ///   sub-buffer into a single
    ///   [`ExtendedInstruction::LoopUnroll { iter_var, start, end, body }`]
    ///   in the outer scope. The Lysis lifter's executor handles the
    ///   per-iteration value binding at run time. This is the Stage-2
    ///   inflection point where SHA-256(64) loop amplification is
    ///   eliminated (Phase 3.C.6 commit 2.5).
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
        match self.sink.loop_unroll_mode() {
            LoopUnrollMode::PerIteration => self.with_saved_var(var, |this| {
                for i in start..end {
                    let v = this.emit_const(FieldElement::<F>::from_u64(i));
                    this.set_name(v, var.to_string());
                    this.env.insert(var.to_string(), InstEnvValue::Scalar(v));

                    for node in body {
                        this.emit_node(node)?;
                    }
                }
                Ok(())
            }),
            LoopUnrollMode::Symbolic => {
                // Allocate iter_var BEFORE the body, in the outer
                // scope, so the LoopUnroll node refers to a slot
                // declared in the parent's namespace (the executor's
                // loop machinery binds it per iteration there).
                let iter_var = self.fresh_var();
                self.set_name(iter_var, var.to_string());
                self.sink.begin_symbolic_loop();
                let result = self.with_saved_var(var, |this| {
                    this.env
                        .insert(var.to_string(), InstEnvValue::Scalar(iter_var));
                    for node in body {
                        this.emit_node(node)?;
                    }
                    Ok(())
                });
                self.sink
                    .finish_symbolic_loop(iter_var, start as i64, end as i64);
                result
            }
        }
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

    // ----------------------------------------------------------------
    // Indexed-write helpers (Gap 1 Stage 2).
    //
    // The `LetIndexed` / `WitnessHintIndexed` handlers split into two
    // paths: const-index (existing semantics, byte-identical to the
    // pre-Gap 1 pipeline) and symbolic-index (new path, ExtendedSink
    // only). The helpers below are the const-index implementation
    // factored out so both paths share it.
    // ----------------------------------------------------------------

    /// Const-index `LetIndexed` handler. Mirrors the pre-Gap 1
    /// behaviour byte-for-byte: outputs go through AssertEq against
    /// the public wire; non-outputs lazily allocate the slot and
    /// shadow the env entry.
    fn emit_let_indexed_const(
        &mut self,
        array: &str,
        idx: usize,
        value: &CircuitExpr,
    ) -> Result<(), ProveIrError> {
        let elem_name = format!("{array}_{idx}");

        if let Some(&pub_var) = self.output_pub_vars.get(&elem_name) {
            let v = self.emit_expr(value)?;
            let result = self.fresh_var();
            self.push_inst(Instruction::AssertEq {
                result,
                lhs: pub_var,
                rhs: v,
                message: None,
            });
        } else {
            let v = self.emit_expr(value)?;
            self.set_name(v, elem_name.clone());
            self.env.insert(elem_name, InstEnvValue::Scalar(v));
            self.ensure_array_slot(array, idx, v);
        }
        Ok(())
    }

    /// Const-index `WitnessHintIndexed` handler.
    fn emit_witness_hint_indexed_const(
        &mut self,
        array: &str,
        idx: usize,
    ) -> Result<(), ProveIrError> {
        let elem_name = format!("{array}_{idx}");
        if self.output_pub_vars.contains_key(&elem_name) {
            // env already has the public wire — nothing to do.
        } else {
            let v = self.fresh_var();
            self.set_name(v, elem_name.clone());
            self.push_inst(Instruction::Input {
                result: v,
                name: elem_name.clone(),
                visibility: Visibility::Witness,
            });
            self.env.insert(elem_name, InstEnvValue::Scalar(v));
            self.ensure_array_slot(array, idx, v);
        }
        Ok(())
    }

    /// Symbolic-index `LetIndexed` — emits one
    /// [`ExtendedInstruction::SymbolicIndexedEffect`] carrying the
    /// resolved `array_slots` snapshot for the walker. Requires the
    /// surrounding `array` to be declared (so its slots are
    /// pre-allocated in env); errors if the array doesn't exist or
    /// is a scalar.
    fn emit_let_indexed_symbolic(
        &mut self,
        array: &str,
        index_var: SsaVar,
        value: &CircuitExpr,
    ) -> Result<(), ProveIrError> {
        let array_slots = self.snapshot_array_slots(array)?;
        let value_var = self.emit_expr(value)?;
        let span = self.current_span.clone();
        self.sink.push_symbolic_indexed_effect(
            IndexedEffectKind::Let,
            array_slots,
            index_var,
            Some(value_var),
            span,
        );
        Ok(())
    }

    /// Symbolic-index `WitnessHintIndexed`. Same shape as
    /// [`emit_let_indexed_symbolic`] but with no value side.
    fn emit_witness_hint_indexed_symbolic(
        &mut self,
        array: &str,
        index_var: SsaVar,
    ) -> Result<(), ProveIrError> {
        let array_slots = self.snapshot_array_slots(array)?;
        let span = self.current_span.clone();
        self.sink.push_symbolic_indexed_effect(
            IndexedEffectKind::WitnessHint,
            array_slots,
            index_var,
            None,
            span,
        );
        Ok(())
    }

    /// Snapshot the `Vec<SsaVar>` of slot wires for a declared array.
    /// Returns an error if `array` is missing or bound to a scalar.
    fn snapshot_array_slots(&self, array: &str) -> Result<Vec<SsaVar>, ProveIrError> {
        match self.env.get(array) {
            Some(InstEnvValue::Array(elems)) => Ok(elems.clone()),
            Some(InstEnvValue::Scalar(_)) => Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "symbolic indexed write into `{array}` but `{array}` is a scalar"
                ),
                span: None,
            }),
            None => Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "symbolic indexed write into `{array}` but the array is not declared in this scope"
                ),
                span: None,
            }),
        }
    }
}
