use super::*;

pub(super) fn map_vis(v: Visibility) -> lysis::Visibility {
    match v {
        Visibility::Public => lysis::Visibility::Public,
        Visibility::Witness => lysis::Visibility::Witness,
    }
}

/// Compute the number of bytes an `ExtendedInstruction` body would
/// occupy when encoded. Walks the body without allocating registers;
/// each Instruction's size depends only on its variant plus (for
/// vector-carrying opcodes) the count of operands — both of which
/// are independent of the specific register assignment.
pub(super) fn body_byte_size<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> Result<u32, WalkError> {
    let mut total: u32 = 0;
    for inst in body {
        total = total.saturating_add(extinst_byte_size(inst)?);
    }
    Ok(total)
}

pub(super) fn extinst_byte_size<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
) -> Result<u32, WalkError> {
    match inst {
        ExtendedInstruction::Plain(i) => instruction_byte_size(i),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            // 1 tag + 1 reg + 4 start + 4 end + 2 body_len = 12
            let mut total = 12u32;
            total = total.saturating_add(body_byte_size(body)?);
            Ok(total)
        }
        // TemplateCall encodes as one `InstantiateTemplate` opcode in
        // the parent's body bytes. Compute its encoded size from a
        // placeholder shape — operand widths drive the size, not the
        // specific values.
        ExtendedInstruction::TemplateCall { captures, .. } => {
            let placeholder = Opcode::InstantiateTemplate {
                template_id: 0,
                capture_regs: Box::new(vec![0u8; captures.len()]),
                output_regs: Box::new(Vec::new()),
            };
            let mut buf = Vec::new();
            encode_opcode(&placeholder, &mut buf);
            Ok(buf.len() as u32)
        }
        // TemplateBody emits sideways into its own template buffer,
        // not into the parent's body bytes — its contribution to the
        // parent's `body_len` is zero. (Walker `emit_template_body`
        // routes the actual bytecode emission through a separate
        // TemplateBuf.)
        ExtendedInstruction::TemplateBody { .. } => Ok(0),
        // TODO Gap 1 Stage 3: replace with the synthesized per-
        // iteration cost. Until the unfolding is implemented the
        // variant cannot reach this path through normal flow — it
        // surfaces only when test fixtures construct it directly.
        ExtendedInstruction::SymbolicIndexedEffect { .. } => {
            Err(WalkError::SymbolicIndexedEffectNotEmittable)
        }
        // Read-side per-iteration alias — Stage 3 of Gap 1.5 will
        // replace this with the unfolding cost (zero opcodes; size 0)
        // once the per-iter walker rebinds slot regs.
        ExtendedInstruction::SymbolicArrayRead { .. } => {
            Err(WalkError::SymbolicArrayReadNotEmittable)
        }
        // TODO Gap 3 Stage 3: replace with the synthesised per-
        // iteration cost (one EmitDecompose plus the recompose chain
        // of Const/Mul/Add opcodes for the resolved shift amount).
        // Until the unfolding is implemented the variant cannot
        // reach this path through normal flow.
        ExtendedInstruction::SymbolicShift { .. } => Err(WalkError::SymbolicShiftNotEmittable),
    }
}

pub(super) fn instruction_byte_size<F: FieldBackend>(
    inst: &Instruction<F>,
) -> Result<u32, WalkError> {
    let ops = placeholder_opcodes(inst)?;
    let mut total: u32 = 0;
    for op in ops {
        let mut buf = Vec::new();
        encode_opcode(&op, &mut buf);
        total = total.saturating_add(buf.len() as u32);
    }
    Ok(total)
}

/// Dummy `Opcode`s whose cumulative encoded size matches what the
/// walker would emit for `inst` — including multi-opcode desugarings
/// (Not → Sub; Or → Add+Mul+Sub; Assert → AssertEq; etc). Used purely
/// for size computation — real emission flows through `ProgramBuilder`.
pub(super) fn placeholder_opcodes<F: FieldBackend>(
    inst: &Instruction<F>,
) -> Result<Vec<Opcode>, WalkError> {
    let bin = |op: Opcode| vec![op];
    Ok(match inst {
        Instruction::Const { .. } => bin(Opcode::LoadConst { dst: 0, idx: 0 }),
        Instruction::Input { .. } => bin(Opcode::LoadInput {
            dst: 0,
            name_idx: 0,
            vis: lysis::Visibility::Public,
        }),
        Instruction::Add { .. } => bin(Opcode::EmitAdd {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Sub { .. } => bin(Opcode::EmitSub {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Mul { .. } => bin(Opcode::EmitMul {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Neg { .. } => bin(Opcode::EmitNeg { dst: 0, operand: 0 }),
        Instruction::Mux { .. } => bin(Opcode::EmitMux {
            dst: 0,
            cond: 0,
            then_v: 0,
            else_v: 0,
        }),
        Instruction::IsEq { .. } => bin(Opcode::EmitIsEq {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::IsLt { .. } => bin(Opcode::EmitIsLt {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::PoseidonHash { .. } => bin(Opcode::EmitPoseidonHash {
            dst: 0,
            in_regs: Box::new(vec![0, 0]),
        }),
        Instruction::AssertEq { message, .. } => bin(if message.is_some() {
            Opcode::EmitAssertEqMsg {
                lhs: 0,
                rhs: 0,
                msg_idx: 0,
            }
        } else {
            Opcode::EmitAssertEq { lhs: 0, rhs: 0 }
        }),
        Instruction::RangeCheck { bits, .. } => bin(Opcode::EmitRangeCheck {
            var: 0,
            max_bits: *bits as u8,
        }),
        Instruction::Decompose { num_bits, .. } => bin(Opcode::EmitDecompose {
            dst_arr: 0,
            src: 0,
            n_bits: *num_bits as u8,
        }),

        // ---------- desugarings ----------
        Instruction::Not { .. } => bin(Opcode::EmitSub {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::And { .. } => bin(Opcode::EmitMul {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Or { .. } => vec![
            Opcode::EmitAdd {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
            Opcode::EmitMul {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
            Opcode::EmitSub {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
        ],
        Instruction::Assert { message, .. } => bin(if message.is_some() {
            Opcode::EmitAssertEqMsg {
                lhs: 0,
                rhs: 0,
                msg_idx: 0,
            }
        } else {
            Opcode::EmitAssertEq { lhs: 0, rhs: 0 }
        }),

        Instruction::IsNeq { .. } | Instruction::IsLe { .. } | Instruction::IsLeBounded { .. } => {
            let cmp = match inst {
                Instruction::IsNeq { .. } => Opcode::EmitIsEq {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
                Instruction::IsLeBounded { .. } => Opcode::EmitIsLtBounded {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                    max_bits: 0,
                },
                _ => Opcode::EmitIsLt {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
            };
            vec![
                cmp,
                Opcode::EmitSub {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
            ]
        }
        Instruction::IsLtBounded { .. } => bin(Opcode::EmitIsLtBounded {
            dst: 0,
            lhs: 0,
            rhs: 0,
            max_bits: 0,
        }),

        Instruction::WitnessCall(call) => bin(Opcode::EmitWitnessCall {
            bytecode_const_idx: 0,
            in_regs: Box::new(vec![0u8; call.inputs.len()]),
            out_regs: Box::new(vec![0u8; call.outputs.len()]),
        }),

        // Field Div: one 3-byte EmitDiv opcode, same shape as
        // EmitMul. The R1CS backend handles field-div semantics
        // downstream via `divide_lcs`.
        Instruction::Div { .. } => bin(Opcode::EmitDiv {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::IntDiv { max_bits, .. } => {
            if *max_bits > u32::from(u8::MAX) {
                return Err(WalkError::OperandOutOfRange {
                    kind: "IntDiv.max_bits",
                    limit: u32::from(u8::MAX),
                    got: *max_bits,
                });
            }
            bin(Opcode::EmitIntDiv {
                dst: 0,
                lhs: 0,
                rhs: 0,
                max_bits: *max_bits as u8,
            })
        }
        Instruction::IntMod { max_bits, .. } => {
            if *max_bits > u32::from(u8::MAX) {
                return Err(WalkError::OperandOutOfRange {
                    kind: "IntMod.max_bits",
                    limit: u32::from(u8::MAX),
                    got: *max_bits,
                });
            }
            bin(Opcode::EmitIntMod {
                dst: 0,
                lhs: 0,
                rhs: 0,
                max_bits: *max_bits as u8,
            })
        }
    })
}
