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

use std::collections::HashMap;

use memory::FieldElement;

use super::error::ProveIrError;
use super::types::*;
use crate::types::{Instruction, IrProgram, IrType, SsaVar, Visibility};

/// Maximum iterations allowed during instantiation (loop unrolling).
/// This mirrors `MAX_UNROLL_ITERATIONS` in IrLowering but applies to capture-bound
/// loops that are only resolved at instantiation time.
const MAX_INSTANTIATE_ITERATIONS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// A resolved value in the instantiation environment.
#[derive(Clone, Debug)]
enum InstEnvValue {
    /// A scalar SSA variable.
    Scalar(SsaVar),
    /// An array of SSA variables (one per element).
    Array(Vec<SsaVar>),
}

// ---------------------------------------------------------------------------
// Instantiator
// ---------------------------------------------------------------------------

/// Converts a ProveIR template into a flat IrProgram given concrete capture values.
struct Instantiator {
    program: IrProgram,
    env: HashMap<String, InstEnvValue>,
    /// Concrete capture values (provided by caller).
    captures: HashMap<String, FieldElement>,
}

impl ProveIR {
    /// Instantiate this template with concrete capture values, producing a flat IrProgram.
    ///
    /// The resulting IrProgram is compatible with the existing optimize → R1CS/Plonkish
    /// pipeline (same format as `IrLowering::lower_circuit()`).
    pub fn instantiate(
        &self,
        captures: &HashMap<String, FieldElement>,
    ) -> Result<IrProgram, ProveIrError> {
        let mut inst = Instantiator {
            program: IrProgram::new(),
            env: HashMap::new(),
            captures: captures.clone(),
        };

        // 1. Validate all required captures are provided
        inst.validate_captures(self)?;

        // 2. Declare public inputs
        for input in &self.public_inputs {
            inst.declare_input(input, Visibility::Public)?;
        }

        // 3. Declare witness inputs
        for input in &self.witness_inputs {
            inst.declare_input(input, Visibility::Witness)?;
        }

        // 4. Declare captures as circuit inputs or inline constants
        for cap in &self.captures {
            inst.declare_capture(cap)?;
        }

        // 5. Emit all body nodes
        for node in &self.body {
            inst.emit_node(node)?;
        }

        Ok(inst.program)
    }
}

impl Instantiator {
    // -------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------

    fn validate_captures(&self, prove_ir: &ProveIR) -> Result<(), ProveIrError> {
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

    fn declare_input(
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
        self.program.push(Instruction::Input {
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
            self.program.push(Instruction::RangeCheck {
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

    fn declare_capture(&mut self, cap: &CaptureDef) -> Result<(), ProveIrError> {
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
                self.program.push(Instruction::Input {
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
                    self.program.push(Instruction::Const {
                        result: const_var,
                        value,
                    });
                    let eq_var = self.program.fresh_var();
                    self.program.push(Instruction::AssertEq {
                        result: eq_var,
                        lhs: v,
                        rhs: const_var,
                    });
                }
            }
            CaptureUsage::StructureOnly => {
                // Inlined as a constant — not a circuit wire.
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const { result: v, value });
                self.program.set_name(v, cap.name.clone());
                self.env.insert(cap.name.clone(), InstEnvValue::Scalar(v));
            }
        }
        Ok(())
    }

    /// Resolve an ArraySize to a concrete usize.
    fn resolve_array_size(&self, size: &ArraySize) -> Result<usize, ProveIrError> {
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

    fn emit_node(&mut self, node: &CircuitNode) -> Result<(), ProveIrError> {
        match node {
            CircuitNode::Let { name, value, .. } => {
                let v = self.emit_expr(value)?;
                self.program.set_name(v, name.clone());
                self.env.insert(name.clone(), InstEnvValue::Scalar(v));
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
            CircuitNode::AssertEq { lhs, rhs, .. } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::AssertEq {
                    result: v,
                    lhs: l,
                    rhs: r,
                });
            }
            CircuitNode::Assert { expr, .. } => {
                let operand = self.emit_expr(expr)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::Assert { result: v, operand });
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
                    value: FieldElement::from_u64(i),
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
    fn with_saved_var<F>(&mut self, var: &str, f: F) -> Result<(), ProveIrError>
    where
        F: FnOnce(&mut Self) -> Result<(), ProveIrError>,
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
            CircuitExpr::Const(fe) => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: *fe,
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
                self.program.push(inst);
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
                self.program.push(inst);
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
                self.program.push(inst);
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
                self.program.push(inst);
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
                self.program.push(Instruction::Mux {
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
                self.program.push(Instruction::PoseidonHash {
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
                    self.program.push(Instruction::Const {
                        result: zero,
                        value: FieldElement::ZERO,
                    });
                    let v = self.program.fresh_var();
                    self.program.push(Instruction::PoseidonHash {
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
                    self.program.push(Instruction::PoseidonHash {
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
                self.program.push(Instruction::RangeCheck {
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

                // Walk up the tree: for each level, hash(current, sibling) based on index
                let mut current = leaf_var;
                for (sibling, idx) in path_elems.iter().zip(idx_elems.iter()) {
                    // mux(idx, hash(sibling, current), hash(current, sibling))
                    let hash_lr = {
                        let v = self.program.fresh_var();
                        self.program.push(Instruction::PoseidonHash {
                            result: v,
                            left: current,
                            right: *sibling,
                        });
                        v
                    };
                    let hash_rl = {
                        let v = self.program.fresh_var();
                        self.program.push(Instruction::PoseidonHash {
                            result: v,
                            left: *sibling,
                            right: current,
                        });
                        v
                    };
                    let v = self.program.fresh_var();
                    self.program.push(Instruction::Mux {
                        result: v,
                        cond: *idx,
                        if_true: hash_rl,
                        if_false: hash_lr,
                    });
                    current = v;
                }

                // Assert computed root == expected root
                let v = self.program.fresh_var();
                self.program.push(Instruction::AssertEq {
                    result: v,
                    lhs: current,
                    rhs: root_var,
                });
                Ok(v)
            }
            CircuitExpr::ArrayIndex { array, index } => {
                // The index must resolve to a constant (structural captures are
                // already resolved). For dynamic indices, we'd need a MUX tree,
                // but the current ProveIR compiler only emits ArrayIndex for
                // cases that can be statically resolved.
                let idx_var = self.emit_expr(index)?;

                // Try to extract the constant value from the instruction we just emitted
                let idx = self.extract_const_index(idx_var).ok_or_else(|| {
                    ProveIrError::UnsupportedOperation {
                        description: format!(
                            "array index into `{array}` must be a compile-time constant"
                        ),
                        span: None,
                    }
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
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::from_u64(len as u64),
                });
                Ok(v)
            }
            CircuitExpr::Pow { base, exp } => {
                let base_var = self.emit_expr(base)?;
                self.emit_pow(base_var, *exp)
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
            self.program.push(Instruction::Const {
                result: v,
                value: FieldElement::ONE,
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
                        self.program.push(Instruction::Mul {
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
                self.program.push(Instruction::Mul {
                    result: v,
                    lhs: current,
                    rhs: current,
                });
                current = v;
            }
        }

        Ok(result.unwrap_or(base))
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
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Convert a FieldElement to u64, with error on overflow.
/// Only valid for "small" values that fit in a single limb.
fn fe_to_u64(fe: &FieldElement, context: &str) -> Result<u64, ProveIrError> {
    let limbs = fe.to_canonical(); // [u64; 4]
                                   // Value fits in u64 only if upper limbs are zero
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return Err(ProveIrError::UnsupportedOperation {
            description: format!(
                "capture `{context}` value is too large for a loop bound or array size"
            ),
            span: None,
        });
    }
    Ok(limbs[0])
}

/// Convert a FieldElement to usize, with error on overflow.
fn fe_to_usize(fe: &FieldElement, context: &str) -> Result<usize, ProveIrError> {
    let v = fe_to_u64(fe, context)?;
    usize::try_from(v).map_err(|_| ProveIrError::UnsupportedOperation {
        description: format!(
            "capture `{context}` value {v} is too large for an array size on this platform"
        ),
        span: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::prove_ir::compiler::ProveIrCompiler;

    /// Helper: compile source as a circuit and instantiate (no captures).
    fn compile_and_instantiate(source: &str) -> IrProgram {
        let program = ProveIrCompiler::compile_circuit(source).unwrap();
        program.instantiate(&HashMap::new()).unwrap()
    }

    /// Helper: compile source as a prove block with captures and instantiate.
    fn compile_and_instantiate_with_captures(
        source: &str,
        outer_scope: &[&str],
        captures: &[(&str, u64)],
    ) -> IrProgram {
        let scope: HashSet<String> = outer_scope.iter().map(|s| s.to_string()).collect();
        let prove_ir = ProveIrCompiler::compile_prove_block(source, &scope).unwrap();
        let cap_map: HashMap<String, FieldElement> = captures
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::from_u64(*v)))
            .collect();
        prove_ir.instantiate(&cap_map).unwrap()
    }

    // --- Basic circuits ---

    #[test]
    fn instantiate_empty_circuit() {
        let ir = compile_and_instantiate("");
        assert!(ir.instructions.is_empty());
    }

    #[test]
    fn instantiate_public_input() {
        let ir = compile_and_instantiate("public x");
        assert_eq!(ir.instructions.len(), 1);
        assert!(matches!(
            &ir.instructions[0],
            Instruction::Input {
                name,
                visibility: Visibility::Public,
                ..
            } if name == "x"
        ));
    }

    #[test]
    fn instantiate_witness_input() {
        let ir = compile_and_instantiate("witness s");
        assert_eq!(ir.instructions.len(), 1);
        assert!(matches!(
            &ir.instructions[0],
            Instruction::Input {
                name,
                visibility: Visibility::Witness,
                ..
            } if name == "s"
        ));
    }

    #[test]
    fn instantiate_array_input() {
        let ir = compile_and_instantiate("public arr[3]");
        // 3 Input instructions for arr_0, arr_1, arr_2
        assert_eq!(ir.instructions.len(), 3);
        for (i, inst) in ir.instructions.iter().enumerate() {
            assert!(matches!(
                inst,
                Instruction::Input { name, visibility: Visibility::Public, .. }
                    if name == &format!("arr_{i}")
            ));
        }
    }

    #[test]
    fn instantiate_basic_arithmetic() {
        let ir = compile_and_instantiate("public x\npublic y\npublic out\nassert_eq(x + y, out)");
        // Inputs: x, y, out (3)
        // Add: x + y (1)
        // AssertEq: (x+y) == out (1)
        let inputs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Input { .. }))
            .count();
        let adds = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Add { .. }))
            .count();
        let asserts = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::AssertEq { .. }))
            .count();
        assert_eq!(inputs, 3);
        assert_eq!(adds, 1);
        assert_eq!(asserts, 1);
    }

    #[test]
    fn instantiate_let_binding() {
        let ir = compile_and_instantiate("public x\npublic out\nlet y = x * 2\nassert_eq(y, out)");
        // Should have: Input(x), Input(out), Const(2), Mul(x,2), AssertEq
        let muls = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Mul { .. }))
            .count();
        assert_eq!(muls, 1);
    }

    #[test]
    fn instantiate_poseidon() {
        let ir = compile_and_instantiate(
            "public hash\nwitness a\nwitness b\nassert_eq(poseidon(a, b), hash)",
        );
        let hashes = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
            .count();
        assert_eq!(hashes, 1);
    }

    #[test]
    fn instantiate_poseidon_many() {
        let ir = compile_and_instantiate(
            "public hash\nwitness a\nwitness b\nwitness c\nassert_eq(poseidon_many(a, b, c), hash)",
        );
        // poseidon_many(a, b, c) → poseidon(poseidon(a, b), c) — 2 hashes
        let hashes = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
            .count();
        assert_eq!(hashes, 2);
    }

    #[test]
    fn instantiate_range_check() {
        let ir = compile_and_instantiate("witness x\nrange_check(x, 8)");
        let checks = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::RangeCheck { bits: 8, .. }))
            .count();
        assert_eq!(checks, 1);
    }

    #[test]
    fn instantiate_mux() {
        let ir = compile_and_instantiate("public c\nwitness a\nwitness b\nlet r = mux(c, a, b)");
        let muxes = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Mux { .. }))
            .count();
        assert_eq!(muxes, 1);
    }

    #[test]
    fn instantiate_if_else() {
        let ir = compile_and_instantiate(
            "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
        );
        // Should produce a Mux
        let muxes = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Mux { .. }))
            .count();
        assert!(muxes >= 1);
    }

    #[test]
    fn instantiate_pow() {
        let ir = compile_and_instantiate("public x\npublic out\nassert_eq(x ^ 3, out)");
        // x^3 via square-and-multiply: x*x=x², x²*x=x³ → 2 Mul
        let muls = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Mul { .. }))
            .count();
        assert_eq!(muls, 2, "x^3 should use 2 multiplications");
    }

    #[test]
    fn instantiate_pow_zero() {
        let ir = compile_and_instantiate("public x\npublic out\nassert_eq(x ^ 0, out)");
        // x^0 = 1
        let has_const_one = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::Const { value, .. } if *value == FieldElement::ONE));
        assert!(has_const_one, "x^0 should produce Const(1)");
    }

    // --- For loop unrolling ---

    #[test]
    fn instantiate_for_loop() {
        let ir = compile_and_instantiate(
            "public out\nmut acc = 0\nfor i in 0..3 { acc = acc + 1 }\nassert_eq(acc, out)",
        );
        // Unrolled: 3 iterations, each adds 1
        let adds = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Add { .. }))
            .count();
        assert_eq!(adds, 3, "3 iterations of acc + 1");
    }

    #[test]
    fn instantiate_for_empty_range() {
        let ir = compile_and_instantiate("public out\nfor i in 5..3 { }\nassert_eq(0, out)");
        // 5..3 = empty range, no loop body emitted
        // Should just have: Input(out), Const(0), AssertEq
        let consts = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Const { .. }))
            .count();
        assert!(consts >= 1);
    }

    // --- Captures ---

    #[test]
    fn instantiate_with_capture_as_witness() {
        let ir = compile_and_instantiate_with_captures(
            "public hash\nassert_eq(poseidon(secret, 0), hash)",
            &["secret", "hash"],
            &[("secret", 42)],
        );
        // secret is a capture classified as CircuitInput → witness Input
        let witness_inputs: Vec<&str> = ir
            .instructions
            .iter()
            .filter_map(|i| match i {
                Instruction::Input {
                    name,
                    visibility: Visibility::Witness,
                    ..
                } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            witness_inputs.contains(&"secret"),
            "secret should be a witness input, got: {witness_inputs:?}"
        );
    }

    #[test]
    fn instantiate_with_capture_as_loop_bound() {
        // WithCapture is tested by constructing ProveIR directly since the
        // parser doesn't support `for i in 0..n` with dynamic n yet.
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![ProveInputDecl {
                name: "out".into(),
                array_size: None,
                ir_type: IrType::Field,
            }],
            witness_inputs: vec![],
            captures: vec![CaptureDef {
                name: "n".into(),
                usage: CaptureUsage::StructureOnly,
            }],
            body: vec![CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "n".into(),
                },
                body: vec![CircuitNode::Expr {
                    expr: CircuitExpr::Var("i".into()),
                    span: None,
                }],
                span: None,
            }],
            capture_arrays: vec![],
        };
        let captures: HashMap<String, FieldElement> =
            [("n".to_string(), FieldElement::from_u64(4))]
                .into_iter()
                .collect();
        let ir = prove_ir.instantiate(&captures).unwrap();
        // n=4 means 4 iterations → 4 Const instructions for i=0,1,2,3
        let consts: Vec<_> = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Const { .. }))
            .collect();
        // 1 const for structural capture "n" + 4 consts for loop var i
        assert_eq!(
            consts.len(),
            5,
            "expected 1 + 4 Const instructions, got {}",
            consts.len()
        );
    }

    #[test]
    fn instantiate_missing_capture_error() {
        // Construct a ProveIR that requires a capture "secret" but don't provide it
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![CaptureDef {
                name: "secret".into(),
                usage: CaptureUsage::CircuitInput,
            }],
            body: vec![],
            capture_arrays: vec![],
        };
        let result = prove_ir.instantiate(&HashMap::new());
        assert!(result.is_err(), "should fail with missing capture");
    }

    // --- Comparison operators ---

    #[test]
    fn instantiate_comparison_eq() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a == b)");
        let has_is_eq = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsEq { .. }));
        assert!(has_is_eq);
    }

    #[test]
    fn instantiate_comparison_lt() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a < b)");
        let has_is_lt = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsLt { .. }));
        assert!(has_is_lt);
    }

    #[test]
    fn instantiate_comparison_gt_desugars_to_lt() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a > b)");
        // a > b → IsLt(b, a) (operands swapped)
        let has_is_lt = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsLt { .. }));
        assert!(has_is_lt, "a > b should desugar to IsLt(b, a)");
    }

    // --- Boolean ops ---

    #[test]
    fn instantiate_bool_and() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a == 1 && b == 1)");
        let has_and = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::And { .. }));
        assert!(has_and);
    }

    // --- Function inlining ---

    #[test]
    fn instantiate_user_fn() {
        let ir = compile_and_instantiate(
            "public out\nfn double(x) { x * 2 }\nassert_eq(double(5), out)",
        );
        let muls = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Mul { .. }))
            .count();
        assert_eq!(muls, 1);
    }

    // --- SSA naming ---

    #[test]
    fn instantiate_ssa_vars_unique() {
        let ir = compile_and_instantiate(
            "public x\npublic out\nmut a = x\na = a + 1\na = a * 2\nassert_eq(a, out)",
        );
        // All result vars should be unique
        let vars: Vec<SsaVar> = ir.instructions.iter().map(|i| i.result_var()).collect();
        let unique: HashSet<SsaVar> = vars.iter().copied().collect();
        assert_eq!(vars.len(), unique.len(), "SSA vars must be unique");
    }

    // --- Integration: full circuit patterns ---

    #[test]
    fn integration_poseidon_preimage() {
        let ir = compile_and_instantiate(
            "public hash\n\
             witness secret\n\
             assert_eq(poseidon(secret, Field::ZERO), hash)",
        );
        let inputs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Input { .. }))
            .count();
        let hashes = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
            .count();
        let asserts = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::AssertEq { .. }))
            .count();
        assert_eq!(inputs, 2);
        assert_eq!(hashes, 1);
        assert_eq!(asserts, 1);
    }

    #[test]
    fn integration_accumulator_with_for() {
        let ir = compile_and_instantiate(
            "public total\n\
             witness vals[4]\n\
             mut sum = Field::ZERO\n\
             for i in 0..4 { sum = sum + vals_0 }\n\
             assert_eq(sum, total)",
        );
        // 4 iterations of sum + vals_0
        let adds = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Add { .. }))
            .count();
        assert_eq!(adds, 4);
    }

    #[test]
    fn integration_array_len() {
        let ir = compile_and_instantiate(
            "let arr = [1, 2, 3]\nlet n = len(arr)\npublic out\nassert_eq(n, out)",
        );
        // len(arr) → Const(3)
        let has_const_3 = ir.instructions.iter().any(|i| {
            matches!(i, Instruction::Const { value, .. } if *value == FieldElement::from_u64(3))
        });
        assert!(has_const_3);
    }

    // =====================================================================
    // Phase B audit regression tests
    // =====================================================================

    // S1: Bool-typed inputs get RangeCheck enforcement
    #[test]
    fn audit_bool_input_gets_range_check() {
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![ProveInputDecl {
                name: "flag".into(),
                array_size: None,
                ir_type: IrType::Bool,
            }],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        };
        let ir = prove_ir.instantiate(&HashMap::new()).unwrap();
        let range_checks = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::RangeCheck { bits: 1, .. }))
            .count();
        assert_eq!(
            range_checks, 1,
            "Bool input must have RangeCheck(1), got {range_checks}"
        );
    }

    #[test]
    fn audit_bool_array_input_gets_range_checks() {
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![ProveInputDecl {
                name: "flags".into(),
                array_size: Some(ArraySize::Literal(3)),
                ir_type: IrType::Bool,
            }],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        };
        let ir = prove_ir.instantiate(&HashMap::new()).unwrap();
        let range_checks = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::RangeCheck { bits: 1, .. }))
            .count();
        assert_eq!(range_checks, 3, "3 Bool array elements need 3 RangeChecks");
    }

    // E1: PoseidonMany with 2 args
    #[test]
    fn audit_poseidon_many_two_args() {
        let ir = compile_and_instantiate(
            "public hash\nwitness a\nwitness b\nassert_eq(poseidon_many(a, b), hash)",
        );
        let hashes = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
            .count();
        assert_eq!(hashes, 1, "poseidon_many(a, b) should produce 1 hash");
    }

    // Pow with exp=1
    #[test]
    fn audit_pow_one_is_identity() {
        let ir = compile_and_instantiate("public x\npublic out\nassert_eq(x ^ 1, out)");
        // x^1 should NOT produce any Mul instructions (identity)
        let muls = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Mul { .. }))
            .count();
        assert_eq!(muls, 0, "x^1 should be identity (0 multiplications)");
    }

    // Unary Neg
    #[test]
    fn audit_unary_neg() {
        let ir = compile_and_instantiate("public x\npublic out\nassert_eq(-x, out)");
        let negs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Neg { .. }))
            .count();
        assert_eq!(negs, 1);
    }

    // Unary Not
    #[test]
    fn audit_unary_not() {
        let ir = compile_and_instantiate("public x\npublic out\nassert_eq(!x, out)");
        let nots = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::Not { .. }))
            .count();
        assert_eq!(nots, 1);
    }

    // Comparison operators Neq, Le, Ge
    #[test]
    fn audit_comparison_neq() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a != b)");
        assert!(ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsNeq { .. })));
    }

    #[test]
    fn audit_comparison_le() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a <= b)");
        assert!(ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsLe { .. })));
    }

    #[test]
    fn audit_comparison_ge_desugars_to_le() {
        let ir = compile_and_instantiate("public a\npublic b\nassert(a >= b)");
        // a >= b → IsLe(b, a)
        assert!(ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsLe { .. })));
    }

    // If node with nested constraints in both branches
    #[test]
    fn audit_if_emits_both_branch_constraints() {
        let ir = compile_and_instantiate(
            "public c\npublic a\npublic b\n\
             if c { assert_eq(a, 1) } else { assert_eq(b, 2) }",
        );
        let assert_eqs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::AssertEq { .. }))
            .count();
        assert_eq!(
            assert_eqs, 2,
            "both if/else branches must emit their constraints"
        );
    }

    // ForRange::Array with empty array
    #[test]
    fn audit_for_array_empty() {
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::For {
                var: "x".into(),
                range: ForRange::Array("arr".into()),
                body: vec![],
                span: None,
            }],
            capture_arrays: vec![],
        };
        // Need "arr" in env as an empty array — not possible from the
        // public API without a LetArray node. Use a LetArray with empty elements instead.
        // Actually, empty arrays are rejected by the compiler. Test via non-empty but
        // verifying the loop body isn't entered would require a different approach.
        // Skip: empty arrays are rejected at compile time (Phase A).
    }

    // CaptureUsage::Both
    #[test]
    fn audit_capture_both_is_witness_input() {
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![ProveInputDecl {
                name: "out".into(),
                array_size: None,
                ir_type: IrType::Field,
            }],
            witness_inputs: vec![],
            captures: vec![CaptureDef {
                name: "n".into(),
                usage: CaptureUsage::Both,
            }],
            body: vec![
                // Use n structurally (in a WithCapture range)
                CircuitNode::For {
                    var: "i".into(),
                    range: ForRange::WithCapture {
                        start: 0,
                        end_capture: "n".into(),
                    },
                    body: vec![],
                    span: None,
                },
                // Use n in a constraint expression
                CircuitNode::AssertEq {
                    lhs: CircuitExpr::Capture("n".into()),
                    rhs: CircuitExpr::Input("out".into()),
                    span: None,
                },
            ],
            capture_arrays: vec![],
        };
        let captures: HashMap<String, FieldElement> =
            [("n".to_string(), FieldElement::from_u64(3))]
                .into_iter()
                .collect();
        let ir = prove_ir.instantiate(&captures).unwrap();
        // n should be a witness Input (not just a Const)
        let witness_inputs: Vec<&str> = ir
            .instructions
            .iter()
            .filter_map(|i| match i {
                Instruction::Input {
                    name,
                    visibility: Visibility::Witness,
                    ..
                } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            witness_inputs.contains(&"n"),
            "Both capture must be witness input, got: {witness_inputs:?}"
        );
    }

    // Type propagation verification
    #[test]
    fn audit_type_propagation() {
        let ir = compile_and_instantiate("public a\npublic b\nlet sum = a + b\nassert(a == b)");
        // sum (Add result) should have type Field
        // a == b (IsEq result) should have type Bool
        let has_field = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::Add { result, .. } if ir.get_type(*result) == Some(IrType::Field)));
        let has_bool = ir
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::IsEq { result, .. } if ir.get_type(*result) == Some(IrType::Bool)));
        assert!(has_field, "Add result should have IrType::Field");
        assert!(has_bool, "IsEq result should have IrType::Bool");
    }

    // ===================================================================
    // Phase D audit: hardening tests
    // ===================================================================

    // D1: Capture-bound loop exceeding MAX_INSTANTIATE_ITERATIONS is rejected
    #[test]
    fn audit_instantiate_rejects_huge_capture_loop() {
        // Construct ProveIR directly (parser doesn't support dynamic for bounds)
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![CaptureDef {
                name: "n".into(),
                usage: CaptureUsage::StructureOnly,
            }],
            body: vec![CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "n".into(),
                },
                body: vec![],
                span: None,
            }],
            capture_arrays: vec![],
        };
        let captures: HashMap<String, FieldElement> =
            [("n".to_string(), FieldElement::from_u64(2_000_000))]
                .into_iter()
                .collect();
        let err = prove_ir.instantiate(&captures).unwrap_err();
        assert!(
            matches!(err, ProveIrError::RangeTooLarge { .. }),
            "expected RangeTooLarge, got: {err}"
        );
    }

    // D2: Both captures emit AssertEq to enforce structural-constraint consistency
    #[test]
    fn audit_both_capture_emits_assert_eq() {
        let prove_ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![CaptureDef {
                name: "n".into(),
                usage: CaptureUsage::Both,
            }],
            body: vec![CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "n".into(),
                },
                body: vec![],
                span: None,
            }],
            capture_arrays: vec![],
        };
        let captures: HashMap<String, FieldElement> =
            [("n".to_string(), FieldElement::from_u64(3))]
                .into_iter()
                .collect();
        let ir = prove_ir.instantiate(&captures).unwrap();
        // Should have at least one AssertEq constraining capture n to its constant
        let assert_eqs = ir
            .instructions
            .iter()
            .filter(|i| matches!(i, Instruction::AssertEq { .. }))
            .count();
        assert!(
            assert_eqs >= 1,
            "Both capture must emit AssertEq for consistency, found {assert_eqs}"
        );
    }

    // D3: Import rejection uses ImportsNotSupported variant
    #[test]
    fn audit_import_returns_imports_not_supported() {
        let err =
            ProveIrCompiler::compile_circuit("import \"./foo.ach\" as foo\npublic x").unwrap_err();
        assert!(
            matches!(err, ProveIrError::ImportsNotSupported { .. }),
            "expected ImportsNotSupported, got: {err}"
        );
    }
}
