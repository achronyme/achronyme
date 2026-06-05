use super::*;

mod witness;

impl<F: FieldBackend> Walker<F> {
    pub(super) fn emit_plain(&mut self, inst: &Instruction<F>) -> Result<(), WalkError> {
        match inst {
            Instruction::Const { result, value } => {
                let idx = self.builder.intern_field(*value);
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::LoadConst { dst, idx });
                self.bind(*result, dst);
                if let Some(v) = field_to_i64(value) {
                    self.walker_const.insert(*result, v);
                }
            }
            Instruction::Input {
                result,
                name,
                visibility,
            } => {
                let name_idx = self.builder.intern_string(name.clone());
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::LoadInput {
                    dst,
                    name_idx,
                    vis: map_vis(*visibility),
                });
                self.bind(*result, dst);
            }

            // ---------- pure binary ----------
            Instruction::Add { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitAdd {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
                if let (Some(a), Some(b)) = (
                    self.walker_const.get(lhs).copied(),
                    self.walker_const.get(rhs).copied(),
                ) {
                    if let Some(s) = a.checked_add(b) {
                        self.walker_const.insert(*result, s);
                    }
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
                if let (Some(a), Some(b)) = (
                    self.walker_const.get(lhs).copied(),
                    self.walker_const.get(rhs).copied(),
                ) {
                    if let Some(s) = a.checked_sub(b) {
                        self.walker_const.insert(*result, s);
                    }
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
                if let (Some(a), Some(b)) = (
                    self.walker_const.get(lhs).copied(),
                    self.walker_const.get(rhs).copied(),
                ) {
                    if let Some(s) = a.checked_mul(b) {
                        self.walker_const.insert(*result, s);
                    }
                }
            }
            // Field division `Div(lhs, rhs)` — emit `Opcode::EmitDiv`.
            // The executor materialises that as `Instruction::Div` for
            // the sink, and the R1CS backend (`zkc::r1cs_backend`)
            // lowers it via `divide_lcs`, which handles the witness-
            // side inverse hint and the `rhs * inv = 1` constraint.
            //
            // The walker_const const-fold branch is intentionally
            // skipped: field division has no compile-time meaningful
            // result for the usize-shaped walker-side constants
            // (which model loop indices, not field elements).
            Instruction::Div { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitDiv {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }

            // ---------- unary ----------
            Instruction::Neg { result, operand } => {
                let op = self.resolve(*operand)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitNeg { dst, operand: op });
                self.bind(*result, dst);
                if let Some(v) = self.walker_const.get(operand).copied() {
                    if let Some(n) = v.checked_neg() {
                        self.walker_const.insert(*result, n);
                    }
                }
            }

            // ---------- boolean / logic — desugared to arithmetic.
            //            The operands are assumed boolean (0 or 1) by
            //            the upstream circuit; Lysis doesn't re-check.
            Instruction::Not { result, operand } => {
                let one = self.one()?;
                let x = self.resolve(*operand)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: x,
                });
                self.bind(*result, dst);
            }
            Instruction::And { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            Instruction::Or { result, lhs, rhs } => {
                // x OR y = x + y - x*y (for booleans).
                let (l, r) = self.bin(*lhs, *rhs)?;
                let sum = self.allocator.alloc()?;
                self.push_op(Opcode::EmitAdd {
                    dst: sum,
                    lhs: l,
                    rhs: r,
                });
                let prod = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst: prod,
                    lhs: l,
                    rhs: r,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: sum,
                    rhs: prod,
                });
                self.bind(*result, dst);
            }

            // ---------- mux ----------
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let c = self.resolve(*cond)?;
                let t = self.resolve(*if_true)?;
                let e = self.resolve(*if_false)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMux {
                    dst,
                    cond: c,
                    then_v: t,
                    else_v: e,
                });
                self.bind(*result, dst);
            }

            // ---------- comparisons ----------
            Instruction::IsEq { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsEq {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            Instruction::IsLt { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLt {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsNeq(x,y) = 1 - IsEq(x,y).
            Instruction::IsNeq { result, lhs, rhs } => {
                let one = self.one()?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let eq = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsEq {
                    dst: eq,
                    lhs: l,
                    rhs: r,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: eq,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsLe(x,y) = 1 - IsLt(y,x).
            Instruction::IsLe { result, lhs, rhs } => {
                let one = self.one()?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let lt = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLt {
                    dst: lt,
                    lhs: r,
                    rhs: l,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: lt,
                });
                self.bind(*result, dst);
            }
            // Preserve the bitwidth hint so the R1CS backend can emit the
            // same single `(bits + 1)` comparison decomposition as circom's
            // `LessThan(bits)`, instead of falling back to full-field ranges.
            Instruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let max_bits =
                    u8::try_from(*bitwidth).map_err(|_| WalkError::OperandOutOfRange {
                        kind: "IsLtBounded.bitwidth",
                        limit: u8::MAX as u32,
                        got: *bitwidth,
                    })?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLtBounded {
                    dst,
                    lhs: l,
                    rhs: r,
                    max_bits,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsLeBounded(x,y,bits) = 1 - IsLtBounded(y,x,bits).
            Instruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let max_bits =
                    u8::try_from(*bitwidth).map_err(|_| WalkError::OperandOutOfRange {
                        kind: "IsLeBounded.bitwidth",
                        limit: u8::MAX as u32,
                        got: *bitwidth,
                    })?;
                let one = self.one()?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let lt = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLtBounded {
                    dst: lt,
                    lhs: r,
                    rhs: l,
                    max_bits,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: lt,
                });
                self.bind(*result, dst);
            }

            // ---------- hash ----------
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let l = self.resolve(*left)?;
                let r = self.resolve(*right)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitPoseidonHash {
                    dst,
                    in_regs: Box::new(vec![l, r]),
                });
                self.bind(*result, dst);
            }

            // ---------- constraint side-effects ----------
            Instruction::AssertEq {
                result: _,
                lhs,
                rhs,
                message,
            } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                match message {
                    Some(msg) => {
                        let msg_idx = self.builder.intern_string(msg.clone());
                        self.push_op(Opcode::EmitAssertEqMsg {
                            lhs: l,
                            rhs: r,
                            msg_idx,
                        });
                    }
                    None => {
                        self.push_op(Opcode::EmitAssertEq { lhs: l, rhs: r });
                    }
                }
            }
            Instruction::Assert {
                result: _,
                operand,
                message,
            } => {
                // Desugar: assert operand == 1.
                let one = self.one()?;
                let op = self.resolve(*operand)?;
                match message {
                    Some(msg) => {
                        let msg_idx = self.builder.intern_string(msg.clone());
                        self.push_op(Opcode::EmitAssertEqMsg {
                            lhs: op,
                            rhs: one,
                            msg_idx,
                        });
                    }
                    None => {
                        self.push_op(Opcode::EmitAssertEq { lhs: op, rhs: one });
                    }
                }
            }
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                if *bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "RangeCheck.bits",
                        limit: u32::from(u8::MAX),
                        got: *bits,
                    });
                }
                let op = self.resolve(*operand)?;
                self.push_op(Opcode::EmitRangeCheck {
                    var: op,
                    max_bits: *bits as u8,
                });
                // Result aliases operand once the bit-width constraint is
                // enforced; downstream consumers (Mux, Bool propagation,
                // IsLtBounded) read result, so bind it to operand's reg.
                self.bind(*result, op);
            }
            Instruction::Decompose {
                result: _,
                bit_results,
                operand,
                num_bits,
            } => {
                if *num_bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "Decompose.num_bits",
                        limit: u32::from(u8::MAX),
                        got: *num_bits,
                    });
                }
                let op = self.resolve(*operand)?;
                let base = self.allocator.alloc()?;
                // Extra bits (bit 1..num_bits-1) consume consecutive slots.
                for _ in 1..*num_bits {
                    let _ = self.allocator.alloc()?;
                }
                self.push_op(Opcode::EmitDecompose {
                    dst_arr: base,
                    src: op,
                    n_bits: *num_bits as u8,
                });
                // Bind each bit_result to its corresponding register.
                for (i, br) in bit_results.iter().enumerate() {
                    self.bind(*br, base + i as RegId);
                }
            }

            // ---------- integer div/mod ----------
            // SHA-256(64) emits IntDiv from `int_div(...)` calls in
            // `padBlocks`, so the walker emits IntDiv/IntMod as
            // first-class output. The Lysis bytecode carries
            // `EmitIntDiv` / `EmitIntMod` (codes 0x4D / 0x4E) with
            // `max_bits: u8`; programs whose semantic max_bits
            // exceeds 255 surface as `OperandOutOfRange` so callers
            // learn the limit at walker time rather than as a silent
            // constraint bug.
            Instruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                if *max_bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "IntDiv.max_bits",
                        limit: u32::from(u8::MAX),
                        got: *max_bits,
                    });
                }
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIntDiv {
                    dst,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits as u8,
                });
                self.bind(*result, dst);
            }
            Instruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                if *max_bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "IntMod.max_bits",
                        limit: u32::from(u8::MAX),
                        got: *max_bits,
                    });
                }
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIntMod {
                    dst,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits as u8,
                });
                self.bind(*result, dst);
            }

            Instruction::WitnessCall(call) => self.emit_witness_call(call)?,
        }
        Ok(())
    }
}
