//! Bytecode executor — register-based dispatch loop that emits IR
//! into an [`IrSink`].
//!
//! The Phase 1 executor is a straight interpreter on the decoded
//! [`Program`]: every opcode dispatches through a single big `match`
//! and every emission goes through the sink. It is deliberately
//! naïve — no hash-consing, no optimization, no lazy evaluation —
//! because Phase 2 will replace the sink with a real interner while
//! keeping this same dispatch shape.
//!
//! ## Contract with the validator
//!
//! [`crate::bytecode::validate`] must have accepted the program
//! before [`execute`] runs; the executor relies on most structural
//! invariants (opcodes well-formed, const pool indices in range,
//! template ids defined) and only double-checks the few that depend
//! on runtime information:
//!
//! - **Rule 2** (family compat) — checked against
//!   `F::PRIME_ID` at entry via [`expected_family`].
//! - **Rule 5** (capture idx in range) — checked per-`LoadCapture`.
//! - **Rule 11 runtime backstop** — `max_call_depth` is re-checked
//!   at every `InstantiateTemplate` push.
//!
//! Any other structural error is a validator bug; the executor
//! surfaces it as [`LysisError::ReadUndefinedRegister`] or similar
//! so the program crashes loud rather than silently.

pub mod frame;
pub mod ir_sink;
pub mod stub_sink;

pub use frame::Frame;
pub use ir_sink::IrSink;
pub use stub_sink::StubSink;

use std::collections::HashMap;

use artik::FieldFamily;
use memory::field::{FieldBackend, FieldElement, PrimeId};

use crate::bytecode::const_pool::ConstPoolEntry;
use crate::bytecode::Opcode;
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::intern::{InstructionKind, NodeId};
use crate::program::Program;

/// The canonical family for a given `FieldBackend`. Mirrors Artik's
/// `check_family_compat` mapping.
pub fn expected_family<F: FieldBackend>() -> FieldFamily {
    match F::PRIME_ID {
        PrimeId::Bn254
        | PrimeId::Bls12_381
        | PrimeId::Grumpkin
        | PrimeId::Pallas
        | PrimeId::Vesta
        | PrimeId::Secp256r1
        | PrimeId::Bls12_377 => FieldFamily::BnLike256,
        PrimeId::Goldilocks => FieldFamily::Goldilocks64,
    }
}

/// Execute a validated program, producing emissions into `sink`.
///
/// `captures` are the root-level arguments (typically field constants
/// bound to `LoadCapture` opcodes). Emitting `LoadCapture idx` where
/// `idx >= captures.len()` is a runtime error (rule 5).
pub fn execute<F: FieldBackend, S: IrSink<F>>(
    program: &Program<F>,
    captures: &[FieldElement<F>],
    config: &LysisConfig,
    sink: &mut S,
) -> Result<(), LysisError> {
    // Rule 2: family compat at entry.
    let expected = expected_family::<F>();
    if program.header.family != expected {
        return Err(LysisError::FieldFamilyMismatch {
            declared: program.header.family,
            expected,
        });
    }

    // Build offset → body index map once.
    let mut offset_to_idx: HashMap<u32, usize> = HashMap::with_capacity(program.body.len());
    for (idx, instr) in program.body.iter().enumerate() {
        offset_to_idx.insert(instr.offset, idx);
    }

    // Determine the instruction range of the top-level (root) body:
    // every instruction whose offset is not inside any template body.
    let (root_start, root_end) = root_body_range(program);

    let mut frames: Vec<Frame> = vec![Frame {
        regs: vec![None; 256],
        pc: root_start,
        body_start_idx: root_start,
        body_end_idx: root_end,
        template_id: None,
        output_slots: Vec::new(),
        caller_output_regs: Vec::new(),
        caller_frame_idx: None,
    }];

    let mut instructions_executed: u64 = 0;

    loop {
        // Instruction budget.
        instructions_executed += 1;
        if instructions_executed > config.instruction_budget {
            return Err(LysisError::BudgetExhausted {
                ran: instructions_executed,
                budget: config.instruction_budget,
            });
        }

        let frame_idx = frames.len() - 1;
        let frame = &mut frames[frame_idx];

        if frame.pc >= frame.body_end_idx {
            // Ran off the frame without Return/Halt — validator
            // should have caught this but surface it clearly.
            let last_offset = program
                .body
                .get(frame.pc.saturating_sub(1))
                .map(|i| i.offset)
                .unwrap_or(0);
            return Err(LysisError::UnreachableReturn {
                at_offset: last_offset,
            });
        }

        let instr = &program.body[frame.pc];
        let advance = dispatch(
            instr,
            frame_idx,
            &mut frames,
            program,
            captures,
            config,
            sink,
            &offset_to_idx,
        )?;

        match advance {
            Step::Next => {
                frames[frame_idx].pc += 1;
            }
            Step::JumpToIndex(idx) => {
                frames[frame_idx].pc = idx;
            }
            Step::PushFrame(new_frame) => {
                frames.push(new_frame);
            }
            Step::PopFrame => {
                pop_frame(&mut frames)?;
            }
            Step::Halt => return Ok(()),
        }
    }
}

/// What the dispatcher does next in the outer loop.
enum Step {
    Next,
    JumpToIndex(usize),
    PushFrame(Frame),
    PopFrame,
    Halt,
}

fn root_body_range<F: FieldBackend>(program: &Program<F>) -> (usize, usize) {
    // Convention: the root body is the contiguous prefix of
    // `program.body` whose offsets are *not* inside any template
    // body. In practice the top-level body is everything up to the
    // first DefineTemplate-declared slice.
    if program.templates.is_empty() {
        return (0, program.body.len());
    }
    // Find the first instruction whose offset is inside some template body.
    for (idx, instr) in program.body.iter().enumerate() {
        if is_inside_any_template(program, instr.offset) {
            return (0, idx);
        }
    }
    (0, program.body.len())
}

fn is_inside_any_template<F: FieldBackend>(program: &Program<F>, offset: u32) -> bool {
    program.templates.iter().any(|t| {
        let end = t.body_offset.saturating_add(t.body_len);
        offset >= t.body_offset && offset < end
    })
}

#[allow(clippy::too_many_arguments)]
fn dispatch<F: FieldBackend, S: IrSink<F>>(
    instr: &crate::program::Instr,
    frame_idx: usize,
    frames: &mut [Frame],
    program: &Program<F>,
    captures: &[FieldElement<F>],
    config: &LysisConfig,
    sink: &mut S,
    offset_to_idx: &HashMap<u32, usize>,
) -> Result<Step, LysisError> {
    use Opcode::*;
    let offset = instr.offset;

    match &instr.opcode {
        // -----------------------------------------------------------
        // §4.3.1 Capture / environment
        // -----------------------------------------------------------
        LoadCapture { dst, idx } => {
            if (*idx as usize) >= captures.len() {
                return Err(LysisError::CaptureIdxOutOfRange {
                    at_offset: offset,
                    idx: *idx as u32,
                    len: captures.len() as u32,
                });
            }
            let fe = captures[*idx as usize];
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Const {
                result: id,
                value: fe,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        LoadConst { dst, idx } => {
            let entry =
                program
                    .const_pool
                    .get(*idx as usize)
                    .ok_or(LysisError::ConstIdxOutOfRange {
                        at_offset: offset,
                        idx: *idx as u32,
                        len: program.const_pool.len() as u32,
                    })?;
            let fe = match entry {
                ConstPoolEntry::Field(fe) => *fe,
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "LoadConst target is not a field entry",
                    });
                }
            };
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Const {
                result: id,
                value: fe,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        LoadInput { dst, name_idx, vis } => {
            let entry = program.const_pool.get(*name_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: offset,
                    idx: *name_idx as u32,
                    len: program.const_pool.len() as u32,
                },
            )?;
            let name = match entry {
                ConstPoolEntry::String(s) => s.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "LoadInput name_idx does not reference a string entry",
                    });
                }
            };
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Input {
                result: id,
                name,
                visibility: *vis,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EnterScope | ExitScope => {
            // Phase 1: scopes are informational. The lowering pass
            // (Phase 3) is what actually constructs the scoped
            // environment; the executor currently carries no env.
            Ok(Step::Next)
        }

        // -----------------------------------------------------------
        // §4.3.2 Control flow
        // -----------------------------------------------------------
        Jump { offset: rel } => {
            let target = (offset as i64) + (*rel as i64);
            resolve_jump(target, offset_to_idx).map(Step::JumpToIndex)
        }
        JumpIf { cond, offset: _rel } => {
            // Phase 1 conservative semantics: the executor does not
            // interpret field-element truth values, so it always
            // falls through. Real conditional branching lands in
            // Phase 3 along with the BTA — at that point JumpIf will
            // only appear in loop bodies where the condition is a
            // compile-time-known NodeId.
            let _ = read_reg(&frames[frame_idx], *cond, offset)?; // rule 9 backstop
            Ok(Step::Next)
        }
        Return => {
            if frames.len() == 1 {
                return Err(LysisError::UnreachableReturn { at_offset: offset });
            }
            Ok(Step::PopFrame)
        }
        Halt => Ok(Step::Halt),
        Trap { code } => Err(LysisError::Trap {
            code: *code,
            at_offset: offset,
        }),

        // -----------------------------------------------------------
        // §4.3.3 Loop semantics
        // -----------------------------------------------------------
        LoopUnroll { .. } | LoopRolled { .. } | LoopRange { .. } => {
            // Phase 3 implements the actual unrolling / dispatch —
            // Phase 1 leaves a structured trap so failures are
            // obvious rather than silent.
            Err(LysisError::ValidationFailed {
                rule: 0,
                location: offset,
                detail: "loop opcodes require Phase 3 lowering (not yet implemented)",
            })
        }

        // -----------------------------------------------------------
        // §4.3.4 Template instantiation
        // -----------------------------------------------------------
        DefineTemplate { .. } => {
            // Pure metadata: already harvested during decode. Skip.
            Ok(Step::Next)
        }
        InstantiateTemplate {
            template_id,
            capture_regs,
            output_regs,
        } => {
            let template = program
                .template(*template_id)
                .ok_or(LysisError::UndefinedTemplate {
                    at_offset: offset,
                    template_id: *template_id,
                })?;
            // Runtime rule-11 backstop.
            if (frames.len() as u32) >= config.max_call_depth {
                return Err(LysisError::CallStackOverflow {
                    depth: frames.len() as u32,
                    max: config.max_call_depth,
                });
            }
            let body_start =
                *offset_to_idx
                    .get(&template.body_offset)
                    .ok_or(LysisError::ValidationFailed {
                        rule: 7,
                        location: offset,
                        detail: "template body_offset does not resolve to an instruction index",
                    })?;
            // body_end = body_start + count of instructions in the
            // template slice.
            let slice_end = template.body_offset.saturating_add(template.body_len);
            let body_end = offset_to_idx
                .iter()
                .filter_map(|(&off, &idx)| {
                    if off >= template.body_offset && off < slice_end {
                        Some(idx + 1)
                    } else {
                        None
                    }
                })
                .max()
                .unwrap_or(body_start + 1);

            // Move captures from caller regs into new frame.
            let caller = &frames[frame_idx];
            let mut new_frame_regs: Vec<Option<NodeId>> = vec![None; template.frame_size as usize];
            for (i, cap_reg) in capture_regs.iter().enumerate() {
                if i >= new_frame_regs.len() {
                    break;
                }
                let val = read_reg(caller, *cap_reg, offset)?;
                new_frame_regs[i] = Some(val);
            }

            let new_frame = Frame {
                regs: new_frame_regs,
                pc: body_start,
                body_start_idx: body_start,
                body_end_idx: body_end,
                template_id: Some(*template_id),
                output_slots: vec![None; output_regs.len()],
                caller_output_regs: output_regs.clone(),
                caller_frame_idx: Some(frame_idx),
            };
            Ok(Step::PushFrame(new_frame))
        }
        TemplateOutput {
            output_idx,
            src_reg,
        } => {
            let frame = &mut frames[frame_idx];
            let val = frame
                .read(*src_reg)
                .ok_or(LysisError::ReadUndefinedRegister {
                    reg: *src_reg,
                    at_offset: offset,
                })?;
            if (*output_idx as usize) < frame.output_slots.len() {
                frame.output_slots[*output_idx as usize] = Some(val);
            }
            Ok(Step::Next)
        }

        // -----------------------------------------------------------
        // §4.3.5 IR emission
        // -----------------------------------------------------------
        EmitConst { dst, src_reg } => {
            // `src_reg` already holds a Const-emitted NodeId (produced
            // by a prior `LoadConst`/`LoadCapture`). The RFC treats
            // `EmitConst` as an alias — writing the same id into `dst`.
            let frame = &frames[frame_idx];
            let src = read_reg(frame, *src_reg, offset)?;
            frames[frame_idx].write(*dst, src);
            Ok(Step::Next)
        }

        EmitAdd { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Add {
                result: id,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitSub { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Sub {
                result: id,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitMul { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Mul {
                result: id,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitNeg { dst, operand } => {
            let op = read_reg(&frames[frame_idx], *operand, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Neg {
                result: id,
                operand: op,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        } => {
            let frame = &frames[frame_idx];
            let c = read_reg(frame, *cond, offset)?;
            let t = read_reg(frame, *then_v, offset)?;
            let e = read_reg(frame, *else_v, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::Mux {
                result: id,
                cond: c,
                if_true: t,
                if_false: e,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitDecompose {
            dst_arr,
            src,
            n_bits,
        } => {
            let operand = read_reg(&frames[frame_idx], *src, offset)?;
            let bit_results: Vec<NodeId> = (0..*n_bits).map(|_| sink.fresh_id()).collect();
            let result_id = operand; // mirror of ir::Instruction::Decompose
            sink.emit(InstructionKind::Decompose {
                result: result_id,
                bit_results: bit_results.clone(),
                operand,
                num_bits: *n_bits as u32,
            });
            // Lay out bits into regs[dst_arr..dst_arr+n_bits].
            let frame = &mut frames[frame_idx];
            for (i, b) in bit_results.iter().enumerate() {
                let reg = (*dst_arr as usize).saturating_add(i);
                if reg < frame.regs.len() {
                    frame.regs[reg] = Some(*b);
                }
            }
            Ok(Step::Next)
        }

        EmitAssertEq { lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::AssertEq {
                result: id,
                lhs: l,
                rhs: r,
                message: None,
            });
            Ok(Step::Next)
        }

        EmitRangeCheck { var, max_bits } => {
            let operand = read_reg(&frames[frame_idx], *var, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::RangeCheck {
                result: id,
                operand,
                bits: *max_bits as u32,
            });
            Ok(Step::Next)
        }

        EmitWitnessCall {
            bytecode_const_idx,
            in_regs,
            out_regs,
        } => {
            let entry = program.const_pool.get(*bytecode_const_idx as usize).ok_or(
                LysisError::ConstIdxOutOfRange {
                    at_offset: offset,
                    idx: *bytecode_const_idx as u32,
                    len: program.const_pool.len() as u32,
                },
            )?;
            let blob = match entry {
                ConstPoolEntry::ArtikBytecode(b) => b.clone(),
                _ => {
                    return Err(LysisError::ValidationFailed {
                        rule: 4,
                        location: offset,
                        detail: "EmitWitnessCall bytecode_const_idx is not an Artik blob",
                    });
                }
            };
            let inputs: Vec<NodeId> = in_regs
                .iter()
                .map(|r| read_reg(&frames[frame_idx], *r, offset))
                .collect::<Result<_, _>>()?;
            let outputs: Vec<NodeId> = (0..out_regs.len()).map(|_| sink.fresh_id()).collect();
            sink.emit(InstructionKind::WitnessCall {
                outputs: outputs.clone(),
                inputs,
                program_bytes: blob,
            });
            let frame = &mut frames[frame_idx];
            for (out_reg, id) in out_regs.iter().zip(outputs.iter()) {
                if (*out_reg as usize) < frame.regs.len() {
                    frame.regs[*out_reg as usize] = Some(*id);
                }
            }
            Ok(Step::Next)
        }

        EmitPoseidonHash { dst, in_regs } => {
            let inputs: Vec<NodeId> = in_regs
                .iter()
                .map(|r| read_reg(&frames[frame_idx], *r, offset))
                .collect::<Result<_, _>>()?;
            // RFC §4.3.5 shows `PoseidonHash(result, left, right)` — the
            // mirror enum matches, so we treat the first two inputs as
            // left/right. Hashes with arity ≠ 2 are left to Phase 3.
            if inputs.len() != 2 {
                return Err(LysisError::ValidationFailed {
                    rule: 0,
                    location: offset,
                    detail: "Phase 1 PoseidonHash supports arity 2 only",
                });
            }
            let id = sink.fresh_id();
            sink.emit(InstructionKind::PoseidonHash {
                result: id,
                left: inputs[0],
                right: inputs[1],
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsEq { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::IsEq {
                result: id,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }

        EmitIsLt { dst, lhs, rhs } => {
            let (l, r) = read_binary(&frames[frame_idx], *lhs, *rhs, offset)?;
            let id = sink.fresh_id();
            sink.emit(InstructionKind::IsLt {
                result: id,
                lhs: l,
                rhs: r,
            });
            frames[frame_idx].write(*dst, id);
            Ok(Step::Next)
        }
    }
}

fn read_reg(frame: &Frame, reg: u8, at_offset: u32) -> Result<NodeId, LysisError> {
    frame
        .read(reg)
        .ok_or(LysisError::ReadUndefinedRegister { reg, at_offset })
}

fn read_binary(
    frame: &Frame,
    lhs: u8,
    rhs: u8,
    at_offset: u32,
) -> Result<(NodeId, NodeId), LysisError> {
    Ok((
        read_reg(frame, lhs, at_offset)?,
        read_reg(frame, rhs, at_offset)?,
    ))
}

fn resolve_jump(target: i64, offset_to_idx: &HashMap<u32, usize>) -> Result<usize, LysisError> {
    if target < 0 || target > u32::MAX as i64 {
        return Err(LysisError::BadJumpTarget {
            at_offset: 0,
            target_offset: target,
        });
    }
    offset_to_idx
        .get(&(target as u32))
        .copied()
        .ok_or(LysisError::BadJumpTarget {
            at_offset: 0,
            target_offset: target,
        })
}

fn pop_frame(frames: &mut Vec<Frame>) -> Result<(), LysisError> {
    if frames.len() <= 1 {
        return Err(LysisError::UnreachableReturn { at_offset: 0 });
    }
    let popped = frames.pop().expect("stack len > 1 guarantees a frame");
    let caller_idx = popped
        .caller_frame_idx
        .expect("non-root frames carry caller idx");
    let caller = &mut frames[caller_idx];
    for (out_reg, slot) in popped
        .caller_output_regs
        .iter()
        .zip(popped.output_slots.iter())
    {
        if let Some(id) = slot {
            if (*out_reg as usize) < caller.regs.len() {
                caller.regs[*out_reg as usize] = Some(*id);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use artik::FieldFamily;
    use memory::field::{Bn254Fr, FieldElement};

    use crate::builder::ProgramBuilder;
    use crate::intern::Visibility;

    fn run(program: &Program<Bn254Fr>, captures: &[FieldElement<Bn254Fr>]) -> StubSink<Bn254Fr> {
        let mut sink = StubSink::new();
        execute(program, captures, &LysisConfig::default(), &mut sink).unwrap();
        sink
    }

    fn b() -> ProgramBuilder<Bn254Fr> {
        ProgramBuilder::new(FieldFamily::BnLike256)
    }

    fn one() -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0])
    }

    fn seven() -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_canonical([7, 0, 0, 0])
    }

    // -----------------------------------------------------------------
    // Smoke: bare halt runs.
    // -----------------------------------------------------------------

    #[test]
    fn bare_halt_terminates() {
        let mut builder = b();
        builder.halt();
        let sink = run(&builder.finish(), &[]);
        assert_eq!(sink.count(), 0);
    }

    // -----------------------------------------------------------------
    // LoadConst + emission ordering.
    // -----------------------------------------------------------------

    #[test]
    fn load_const_emits_const_instruction() {
        let mut builder = b();
        builder.intern_field(one());
        builder.load_const(0, 0).halt();
        let sink = run(&builder.finish(), &[]);
        assert_eq!(sink.count(), 1);
        assert!(matches!(
            sink.instructions()[0],
            InstructionKind::Const { .. }
        ));
    }

    #[test]
    fn load_capture_emits_const() {
        let mut builder = b();
        builder.load_capture(0, 0).halt();
        let sink = run(&builder.finish(), &[seven()]);
        assert_eq!(sink.count(), 1);
        match &sink.instructions()[0] {
            InstructionKind::Const { value, .. } => assert_eq!(*value, seven()),
            _ => panic!(),
        }
    }

    #[test]
    fn load_capture_out_of_range_errors() {
        let mut builder = b();
        builder.load_capture(0, 3).halt();
        let mut sink = StubSink::<Bn254Fr>::new();
        let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
        assert!(matches!(
            err,
            LysisError::CaptureIdxOutOfRange { idx: 3, .. }
        ));
    }

    // -----------------------------------------------------------------
    // Pure arithmetic chain.
    // -----------------------------------------------------------------

    #[test]
    fn add_mul_chain_emits_expected_sequence() {
        let mut builder = b();
        builder.intern_field(seven());
        builder.intern_field(one());
        builder
            .load_const(0, 0) // r0 = Const(7)
            .load_const(1, 1) // r1 = Const(1)
            .emit_add(2, 0, 1) // r2 = 7 + 1
            .emit_mul(3, 2, 2) // r3 = r2 * r2
            .halt();
        let sink = run(&builder.finish(), &[]);
        // 2 Consts + 1 Add + 1 Mul = 4 emissions.
        assert_eq!(sink.count(), 4);
        assert!(matches!(
            sink.instructions()[0],
            InstructionKind::Const { .. }
        ));
        assert!(matches!(
            sink.instructions()[1],
            InstructionKind::Const { .. }
        ));
        assert!(matches!(
            sink.instructions()[2],
            InstructionKind::Add { .. }
        ));
        assert!(matches!(
            sink.instructions()[3],
            InstructionKind::Mul { .. }
        ));
    }

    #[test]
    fn input_witness_then_range_check() {
        let mut builder = b();
        builder.intern_string("x");
        builder
            .load_input(0, 0, Visibility::Witness)
            .emit_range_check(0, 8)
            .halt();
        let sink = run(&builder.finish(), &[]);
        assert_eq!(sink.count(), 2);
        assert!(matches!(
            sink.instructions()[0],
            InstructionKind::Input { .. }
        ));
        assert!(matches!(
            sink.instructions()[1],
            InstructionKind::RangeCheck { .. }
        ));
    }

    // -----------------------------------------------------------------
    // Decompose lays out bits.
    // -----------------------------------------------------------------

    #[test]
    fn decompose_emits_and_binds_bits() {
        let mut builder = b();
        builder.intern_field(seven());
        builder
            .load_const(0, 0)
            .emit_decompose(1, 0, 4) // r1..r4 = bits of r0
            .halt();
        let sink = run(&builder.finish(), &[]);
        // Const + Decompose = 2 emissions.
        assert_eq!(sink.count(), 2);
        match &sink.instructions()[1] {
            InstructionKind::Decompose {
                bit_results,
                num_bits,
                ..
            } => {
                assert_eq!(*num_bits, 4);
                assert_eq!(bit_results.len(), 4);
            }
            _ => panic!("expected Decompose"),
        }
    }

    // -----------------------------------------------------------------
    // AssertEq / IsEq / IsLt emit the right variants.
    // -----------------------------------------------------------------

    #[test]
    fn assert_eq_emits_side_effect() {
        let mut builder = b();
        builder.intern_field(seven());
        builder.intern_field(seven());
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .emit_assert_eq(0, 1)
            .halt();
        let sink = run(&builder.finish(), &[]);
        assert_eq!(sink.count(), 3);
        assert!(matches!(
            sink.instructions()[2],
            InstructionKind::AssertEq { .. }
        ));
    }

    #[test]
    fn is_eq_emits_pure_compare() {
        let mut builder = b();
        builder.intern_field(seven());
        builder.intern_field(one());
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .emit_is_eq(2, 0, 1)
            .halt();
        let sink = run(&builder.finish(), &[]);
        assert!(matches!(
            sink.instructions()[2],
            InstructionKind::IsEq { .. }
        ));
    }

    #[test]
    fn is_lt_emits() {
        let mut builder = b();
        builder.intern_field(one());
        builder.intern_field(seven());
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .emit_is_lt(2, 0, 1)
            .halt();
        let sink = run(&builder.finish(), &[]);
        assert!(matches!(
            sink.instructions()[2],
            InstructionKind::IsLt { .. }
        ));
    }

    // -----------------------------------------------------------------
    // Poseidon arity-2.
    // -----------------------------------------------------------------

    #[test]
    fn poseidon_hash_arity_2_ok() {
        let mut builder = b();
        builder.intern_field(one());
        builder.intern_field(seven());
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .emit_poseidon_hash(2, vec![0, 1])
            .halt();
        let sink = run(&builder.finish(), &[]);
        assert!(matches!(
            sink.instructions()[2],
            InstructionKind::PoseidonHash { .. }
        ));
    }

    // -----------------------------------------------------------------
    // Trap surfaces as error.
    // -----------------------------------------------------------------

    #[test]
    fn trap_returns_trap_error() {
        let mut builder = b();
        builder.trap(0x42);
        let mut sink = StubSink::<Bn254Fr>::new();
        let err = execute(&builder.finish(), &[], &LysisConfig::default(), &mut sink).unwrap_err();
        assert!(matches!(err, LysisError::Trap { code: 0x42, .. }));
    }

    // -----------------------------------------------------------------
    // Budget.
    // -----------------------------------------------------------------

    #[test]
    fn budget_exhausted_triggers() {
        let mut builder = b();
        builder.intern_field(one());
        builder.intern_field(seven());
        builder
            .load_const(0, 0)
            .load_const(1, 1)
            .emit_add(2, 0, 1)
            .halt();
        let cfg = LysisConfig {
            instruction_budget: 2,
            ..Default::default()
        };
        let mut sink = StubSink::<Bn254Fr>::new();
        let err = execute(&builder.finish(), &[], &cfg, &mut sink).unwrap_err();
        assert!(matches!(err, LysisError::BudgetExhausted { .. }));
    }

    // -----------------------------------------------------------------
    // Scope opcodes are no-ops.
    // -----------------------------------------------------------------

    #[test]
    fn scope_ops_are_noops() {
        let mut builder = b();
        builder.enter_scope().exit_scope().halt();
        let sink = run(&builder.finish(), &[]);
        assert_eq!(sink.count(), 0);
    }

    // -----------------------------------------------------------------
    // Neg / Mux.
    // -----------------------------------------------------------------

    #[test]
    fn neg_emits() {
        let mut builder = b();
        builder.intern_field(seven());
        builder.load_const(0, 0).emit_neg(1, 0).halt();
        let sink = run(&builder.finish(), &[]);
        assert_eq!(sink.count(), 2);
        assert!(matches!(
            sink.instructions()[1],
            InstructionKind::Neg { .. }
        ));
    }

    #[test]
    fn mux_emits() {
        let mut builder = b();
        builder.intern_field(seven());
        builder.intern_field(one());
        builder
            .load_const(0, 0) // r0 = cond
            .load_const(1, 1) // r1 = then
            .load_const(2, 0) // r2 = else
            .emit_mux(3, 0, 1, 2)
            .halt();
        let sink = run(&builder.finish(), &[]);
        assert!(matches!(
            sink.instructions()[3],
            InstructionKind::Mux { .. }
        ));
    }
}
