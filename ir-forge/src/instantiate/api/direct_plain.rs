use lysis::{ChunkDrainingSink, InstructionKind, IrSink, NodeId};
use lysis_types::WitnessCallBody as LysisWitnessCallBody;
use memory::FieldBackend;

use ir_core::{Instruction, SsaVar, Visibility};

use crate::extended::ExtendedInstruction;

pub(super) fn direct_plain_drain_enabled() -> bool {
    std::env::var("ACH_LYSIS_DIRECT_PLAIN_DRAIN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub(super) fn direct_plain_validate_enabled() -> bool {
    std::env::var("ACH_LYSIS_DIRECT_PLAIN_VALIDATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub(super) fn trace_first_plain_forward_ref<F: FieldBackend>(body: &[ExtendedInstruction<F>]) {
    fn ensure_slot(slots: &mut Vec<bool>, var: SsaVar) {
        let idx = usize::try_from(var.0).expect("SsaVar index overflows usize");
        if idx >= slots.len() {
            slots.resize(idx + 1, false);
        }
    }

    fn is_defined(slots: &[bool], var: SsaVar) -> bool {
        let idx = usize::try_from(var.0).expect("SsaVar index overflows usize");
        slots.get(idx).copied().unwrap_or(false)
    }

    fn mark_defined(slots: &mut Vec<bool>, var: SsaVar) {
        let idx = usize::try_from(var.0).expect("SsaVar index overflows usize");
        ensure_slot(slots, var);
        slots[idx] = true;
    }

    let mut defined = Vec::new();
    for (idx, ext) in body.iter().enumerate() {
        let ExtendedInstruction::Plain(inst) = ext else {
            continue;
        };
        for operand in inst.operands() {
            if !is_defined(&defined, operand) {
                eprintln!(
                    "[lysis-drain] direct_plain_forward_ref idx={idx} missing={operand:?} inst={inst:?}"
                );
                return;
            }
        }
        mark_defined(&mut defined, inst.result_var());
        for extra in inst.extra_result_vars() {
            mark_defined(&mut defined, *extra);
        }
    }
    eprintln!(
        "[lysis-drain] direct_plain_forward_ref none body_len={}",
        body.len()
    );
}

pub(super) fn drain_plain_extended_chunks_interned<F: FieldBackend>(
    body: Vec<ExtendedInstruction<F>>,
    window: usize,
    chunk_capacity: usize,
    chunk_consumer: &mut dyn FnMut(Vec<InstructionKind<F>>),
) -> usize {
    fn slot(var: SsaVar) -> usize {
        usize::try_from(var.0).expect("SsaVar index overflows usize")
    }

    fn bind(map: &mut Vec<Option<NodeId>>, var: SsaVar, id: NodeId) {
        let idx = slot(var);
        if idx >= map.len() {
            map.resize(idx + 1, None);
        }
        map[idx] = Some(id);
    }

    fn resolve(map: &[Option<NodeId>], var: SsaVar) -> NodeId {
        map.get(slot(var))
            .and_then(|id| *id)
            .unwrap_or_else(|| panic!("direct plain drain missing SSA mapping for {var:?}"))
    }

    let mut sink = ChunkDrainingSink::<F>::with_streaming_window_chunked_capacity(
        window,
        chunk_capacity,
        chunk_consumer,
    );
    let mut map: Vec<Option<NodeId>> = Vec::new();
    let mut total = 0usize;

    for ext in body {
        let ExtendedInstruction::Plain(inst) = ext else {
            unreachable!("non-plain body rejected before draining");
        };
        total += 1;
        match inst {
            Instruction::Const { result, value } => {
                let id = sink.intern_pure(InstructionKind::Const {
                    result: NodeId::PLACEHOLDER,
                    value,
                });
                bind(&mut map, result, id);
            }
            Instruction::Input {
                result,
                name,
                visibility,
            } => {
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::Input {
                    result: id,
                    name,
                    visibility: match visibility {
                        Visibility::Public => lysis::Visibility::Public,
                        Visibility::Witness => lysis::Visibility::Witness,
                    },
                });
                bind(&mut map, result, id);
            }
            Instruction::Add { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::Add {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::Sub { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::Mul { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::Mul {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::Div { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::Div {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::Neg { result, operand } => {
                let id = sink.intern_pure(InstructionKind::Neg {
                    result: NodeId::PLACEHOLDER,
                    operand: resolve(&map, operand),
                });
                bind(&mut map, result, id);
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let id = sink.intern_pure(InstructionKind::Mux {
                    result: NodeId::PLACEHOLDER,
                    cond: resolve(&map, cond),
                    if_true: resolve(&map, if_true),
                    if_false: resolve(&map, if_false),
                });
                bind(&mut map, result, id);
            }
            Instruction::AssertEq {
                result,
                lhs,
                rhs,
                message,
            } => {
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::AssertEq {
                    result: id,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                    message,
                });
                bind(&mut map, result, id);
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let id = sink.intern_pure(InstructionKind::PoseidonHash {
                    result: NodeId::PLACEHOLDER,
                    left: resolve(&map, left),
                    right: resolve(&map, right),
                });
                bind(&mut map, result, id);
            }
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                let operand = resolve(&map, operand);
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::RangeCheck {
                    result: id,
                    operand,
                    bits,
                });
                bind(&mut map, result, id);
            }
            Instruction::Not { result, operand } => {
                let id = sink.intern_pure(InstructionKind::Not {
                    result: NodeId::PLACEHOLDER,
                    operand: resolve(&map, operand),
                });
                bind(&mut map, result, id);
            }
            Instruction::And { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::And {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::Or { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::Or {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::IsEq { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::IsEq {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::IsNeq {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::IsLt { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::IsLt {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::IsLe { result, lhs, rhs } => {
                let id = sink.intern_pure(InstructionKind::IsLe {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                });
                bind(&mut map, result, id);
            }
            Instruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let id = sink.intern_pure(InstructionKind::IsLtBounded {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                    bitwidth,
                });
                bind(&mut map, result, id);
            }
            Instruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                let id = sink.intern_pure(InstructionKind::IsLeBounded {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                    bitwidth,
                });
                bind(&mut map, result, id);
            }
            Instruction::Assert {
                result,
                operand,
                message,
            } => {
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::Assert {
                    result: id,
                    operand: resolve(&map, operand),
                    message,
                });
                bind(&mut map, result, id);
            }
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let operand = resolve(&map, operand);
                let bits: Vec<NodeId> = bit_results.iter().map(|_| sink.fresh_id()).collect();
                sink.emit_effect(InstructionKind::Decompose {
                    result: operand,
                    bit_results: bits.clone(),
                    operand,
                    num_bits,
                });
                bind(&mut map, result, operand);
                for (ssa, id) in bit_results.into_iter().zip(bits) {
                    bind(&mut map, ssa, id);
                }
            }
            Instruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                let id = sink.intern_pure(InstructionKind::IntDiv {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                    max_bits,
                });
                bind(&mut map, result, id);
            }
            Instruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                let id = sink.intern_pure(InstructionKind::IntMod {
                    result: NodeId::PLACEHOLDER,
                    lhs: resolve(&map, lhs),
                    rhs: resolve(&map, rhs),
                    max_bits,
                });
                bind(&mut map, result, id);
            }
            Instruction::WitnessCall(call) => {
                let outputs: Vec<NodeId> = call.outputs.iter().map(|_| sink.fresh_id()).collect();
                let inputs = call.inputs.into_iter().map(|v| resolve(&map, v)).collect();
                sink.emit_effect(InstructionKind::WitnessCall(Box::new(
                    LysisWitnessCallBody {
                        outputs: outputs.clone(),
                        inputs,
                        program_bytes: call.program_bytes,
                    },
                )));
                for (ssa, id) in call.outputs.into_iter().zip(outputs) {
                    bind(&mut map, ssa, id);
                }
            }
        }
    }
    sink.finalize();
    total
}
