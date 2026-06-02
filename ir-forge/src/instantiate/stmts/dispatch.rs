use memory::{FieldBackend, FieldElement};

use super::super::utils::fe_to_usize;
use super::super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::types::*;
use ir_core::{Instruction, SsaVar, Visibility};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(in crate::instantiate) fn emit_node(
        &mut self,
        node: &CircuitNode,
    ) -> Result<(), ProveIrError> {
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
                    if self.keeps_metadata() {
                        self.set_name(v, name.clone());
                    }
                    self.env.insert(name.clone(), InstEnvValue::Scalar(v));
                }
            }
            CircuitNode::LetArray { name, elements, .. } => {
                let mut elem_vars = Vec::with_capacity(elements.len());
                for (i, elem) in elements.iter().enumerate() {
                    let v = self.emit_expr(elem)?;
                    let elem_name = format!("{name}_{i}");
                    if self.keeps_metadata() {
                        self.set_name(v, elem_name.clone());
                    }
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
                // byte-equivalent in R1CS multiset.
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
                    if self.keeps_metadata() {
                        self.set_name(bit_v, elem_name.clone());
                    }
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
                    if self.keeps_metadata() {
                        self.set_name(v, name.clone());
                    }
                    self.push_inst(Instruction::Input {
                        result: v,
                        name: name.clone(),
                        visibility: Visibility::Witness,
                    });
                    self.env.insert(name.clone(), InstEnvValue::Scalar(v));
                }
            }
            CircuitNode::WitnessArrayDecl { name, size, .. } => {
                // Pre-allocate `size` witness wires for an internal
                // signal array `signal X[size];` (no init). The Lysis
                // frontend emits this so a downstream
                // `SymbolicIndexedEffect` can snapshot the array's
                // slot vec. Each slot becomes a witness `Input`
                // instruction named `{name}_{i}`. Legacy R1CS
                // compilation never reaches this — its lowering
                // unrolls indexed assignments before the slots are
                // needed.
                let size = self.resolve_array_size(size)?;

                // Re-use pre-allocated slots if the env already holds an
                // `InstEnvValue::Array(existing)` for this name. This
                // happens whenever a parent `comp.arr[i] <== rhs;` loop
                // ran *before* the inlined sub-component body's
                // `WitnessArrayDecl` does (the Class B eager-unroll
                // path: `emit_let_indexed_const` → `ensure_array_slot`
                // populates the array lazily as the parent feeds each
                // slot). Without this re-use the handler would allocate
                // a second set of fresh witness `Input` wires for the
                // same logical slot, leaking N orphan witnesses with
                // no constraint references. Confirmed empirically
                // closing a +256-wire orphan delta on EscalarMulAny(254)
                // and analogous slack on Pedersen / EscalarMulFix /
                // Poseidon / MiMCSponge / Pedersen_old / LessThan.
                if let Some(InstEnvValue::Array(existing)) = self.env.get(name) {
                    if existing.len() == size {
                        return Ok(());
                    }
                }

                let mut elem_vars = Vec::with_capacity(size);
                for i in 0..size {
                    let elem_name = format!("{name}_{i}");
                    if let Some(&pub_var) = self.output_pub_vars.get(&elem_name) {
                        // Public output array slot already pre-bound by
                        // scaffold — reuse the wire so SymbolicIndexed
                        // Effect AssertEqs land on the right channel.
                        elem_vars.push(pub_var);
                    } else {
                        let v = self.fresh_var();
                        if self.keeps_metadata() {
                            self.set_name(v, elem_name.clone());
                        }
                        self.push_inst(Instruction::Input {
                            result: v,
                            name: elem_name.clone(),
                            visibility: Visibility::Witness,
                        });
                        self.env.insert(elem_name, InstEnvValue::Scalar(v));
                        elem_vars.push(v);
                    }
                }
                self.env
                    .insert(name.clone(), InstEnvValue::Array(elem_vars));
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
                    // Symbolic index: emit a SymbolicIndexedEffect
                    // carrying the resolved `array_slots` snapshot for
                    // the walker to materialise per iteration.
                    let idx_var = self.emit_expr(index)?;
                    self.emit_let_indexed_symbolic(array, idx_var, value)?;
                }
            }
            CircuitNode::WitnessHintIndexed { array, index, .. } => {
                if let Ok(fe) = self.eval_const_expr(index) {
                    let idx = fe_to_usize(&fe, array)?;
                    self.emit_witness_hint_indexed_const(array, idx)?;
                } else {
                    let idx_var = self.emit_expr(index)?;
                    self.emit_witness_hint_indexed_symbolic(array, idx_var)?;
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
                        if self.keeps_metadata() {
                            self.set_name(fresh, name.clone());
                        }
                        self.env.insert(name.clone(), InstEnvValue::Scalar(fresh));
                        fresh
                    };
                    outputs.push(v);
                }
                self.push_inst(Instruction::WitnessCall(Box::new(
                    ir_core::WitnessCallBody {
                        outputs,
                        inputs,
                        program_bytes: program_bytes.clone(),
                    },
                )));
            }
            CircuitNode::ComponentCall {
                body_key,
                comp_name,
                param_subs,
                ..
            } => {
                // Expand a deferred component instance: resolve the
                // shared unmangled body, mangle it with this
                // instance's prefix (substituting params), emit each
                // node, then drop the mangled copy. This runs the
                // same canonical mangle the lowering-time inline path
                // runs, so the emitted instructions are byte-identical
                // to an inlined component — only the materialization
                // is deferred, keeping peak memory at one mangled
                // body rather than one inlined copy per instance.
                // Nested `ComponentCall`s recurse through `emit_node`.
                let subs: std::collections::HashMap<String, CircuitExpr> =
                    param_subs.iter().cloned().collect();
                let mangled = {
                    let body = self.component_bodies.get(body_key).ok_or_else(|| {
                        ProveIrError::UnsupportedOperation {
                            description: format!(
                                "ComponentCall references unknown body key `{body_key}`"
                            ),
                            span: None,
                        }
                    })?;
                    mangle_nodes(body, comp_name, &subs)
                };
                for n in &mangled {
                    self.emit_node(n)?;
                }
            }
        }
        Ok(())
    }
}
