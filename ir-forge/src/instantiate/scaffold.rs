//! Scaffold methods on [`Instantiator`]: span-aware emission, capture
//! validation, input + capture declaration, array-size resolution.
//!
//! These are the building blocks the higher-level `emit_node` /
//! `emit_expr` walkers call to set up the SSA program before the
//! body walk begins. All methods are `pub(super)` so that
//! [`super::api`] (entry points) and [`super::stmts`] / [`super::exprs`]
//! / [`super::bits`] (body emission) can use them.

use memory::{FieldBackend, FieldElement};

use super::utils::fe_to_usize;
use super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::types::{ArraySize, CaptureDef, CaptureUsage, ProveIR, ProveInputDecl};
use ir_core::{Instruction, IrType, SsaVar, Visibility};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn push_inst(&mut self, inst: Instruction<F>) -> SsaVar {
        // Delegates to `ExtendedSink`, which writes
        // `Vec<ExtendedInstruction::Plain>` for the Lysis Walker to
        // consume downstream. The current span context is forwarded
        // so the sink can attach it to the result var's span side-
        // channel (ExtendedSink writes spans to its metadata
        // skeleton).
        self.sink.push_inst(inst, self.current_span.as_ref())
    }

    /// Emit a field constant, deduping against previously emitted Consts
    /// with the same value. Populates both [`const_cache`] (value→var)
    /// and [`const_values`] (var→value) so downstream peephole folds
    /// in `emit_expr` can recognise constant operands.
    ///
    /// Field-erased key: the 32-byte canonical representation, so
    /// equal values collapse regardless of which construction path
    /// built them (e.g., `FieldElement::from_u64(0)` vs
    /// `FieldElement::zero()`).
    pub(super) fn emit_const(&mut self, value: FieldElement<F>) -> SsaVar {
        let key = fe_canonical_bytes(&value);
        if let Some(&var) = self.const_cache.get(&key) {
            return var;
        }
        let var = self.fresh_var();
        self.push_inst(Instruction::Const { result: var, value });
        self.set_type(var, IrType::Field);
        self.const_cache.insert(key, var);
        self.const_values.insert(var, value);
        var
    }

    /// If `var` was emitted as a compile-time constant via [`emit_const`],
    /// return its field value. Used by `emit_expr` peephole folds.
    pub(super) fn const_value_of(&self, var: SsaVar) -> Option<FieldElement<F>> {
        self.const_values.get(&var).copied()
    }

    /// Lower a logical NOT to its arithmetic primitive: `Sub(1, operand)`.
    /// Used by `emit_expr` for `CircuitUnaryOp::Not`, by the comparison
    /// arms (`Neq`, `Le`, `Ge`) for the `1 - IsX(...)` pattern, and by
    /// `emit_node` for `CircuitNode::Assert`. Centralising the lowering
    /// keeps the `Const(1)` shared via [`emit_const`]'s cache and matches
    /// the form `ir-forge::lysis_lift::Walker` produces, so the legacy
    /// and Lysis pipelines stay byte-equivalent in R1CS multiset.
    pub(super) fn lower_not(&mut self, operand: SsaVar) -> SsaVar {
        let one = self.emit_const(FieldElement::<F>::one());
        let v = self.fresh_var();
        self.push_inst(Instruction::Sub {
            result: v,
            lhs: one,
            rhs: operand,
        });
        self.set_type(v, IrType::Bool);
        v
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
    pub(super) fn emit_input(
        &mut self,
        name: &str,
        visibility: Visibility,
        ir_type: IrType,
    ) -> SsaVar {
        let v = self.fresh_var();
        self.push_inst(Instruction::Input {
            result: v,
            name: name.to_string(),
            visibility,
        });
        self.set_name(v, name.to_string());
        self.set_type(v, ir_type);

        // Bool inputs must be constrained to {0, 1} via RangeCheck(1 bit).
        // Without this, a malicious prover could assign arbitrary field elements
        // to Bool inputs, breaking downstream boolean logic (And, Or, Not, Mux).
        if ir_type == IrType::Bool {
            let enforced = self.fresh_var();
            self.push_inst(Instruction::RangeCheck {
                result: enforced,
                operand: v,
                bits: 1,
            });
            self.set_type(enforced, IrType::Bool);
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
                let v = self.fresh_var();
                self.push_inst(Instruction::Input {
                    result: v,
                    name: cap.name.clone(),
                    visibility: Visibility::Witness,
                });
                self.set_name(v, cap.name.clone());
                self.set_type(v, IrType::Field);
                self.env.insert(cap.name.clone(), InstEnvValue::Scalar(v));

                // For `Both` captures: the value is used structurally (loop bounds,
                // array sizes) AND in constraints. We emit an AssertEq to enforce
                // that the witness value matches the structural constant. Without
                // this, a malicious prover could provide a different witness value
                // than the one used for structural decisions (e.g., loop count),
                // producing an unsound proof.
                if cap.usage == CaptureUsage::Both {
                    let const_var = self.emit_const(value);
                    let eq_var = self.fresh_var();
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
                let v = self.emit_const(value);
                self.set_name(v, cap.name.clone());
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
}

/// Pack a field element's canonical 4-limb representation into a
/// 32-byte key suitable for hashing. Identical values produce
/// identical keys regardless of the backend's internal form.
fn fe_canonical_bytes<F: FieldBackend>(fe: &FieldElement<F>) -> [u8; 32] {
    let limbs = fe.to_canonical();
    let mut bytes = [0u8; 32];
    for (i, l) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&l.to_le_bytes());
    }
    bytes
}
