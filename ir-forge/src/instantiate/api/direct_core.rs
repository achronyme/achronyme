//! Direct interning of a Plain instruction stream — the per-form
//! mirror of the Walker → bytecode → executor cable.
//!
//! On an all-Plain body the cable is an identity re-traversal whose
//! only semantic work is the interner's hash-consing (the
//! Instantiator pre-desugars boolean/comparison sugar at emission, so
//! the walker's own desugar arms never fire on walk-fed bodies).
//! [`DirectInternState::feed_plain`] performs, per instruction, the
//! exact `intern_pure` / `fresh_id` / `emit_effect` call sequence the
//! executor performs for the walker's lowering of it — including the
//! walker's desugarings (`Not`, `And`, `Or`, `IsNeq`, `IsLe`,
//! `IsLeBounded`, `Assert`) and its u8 bit-width guards, surfaced
//! through the same [`WalkError`] variants — so the interner assigns
//! identical `NodeId`s and the materialized stream is byte-identical.
//!
//! The walk-facing sink and the fallback contract for non-Plain
//! bodies live in [`super::direct_sink`]. The core is generic over
//! [`IrSink`] so the chunk-draining path can share it.

use lysis::{InstructionKind, IrSink, NodeId};
use lysis_types::WitnessCallBody as LysisWitnessCallBody;
use memory::{FieldBackend, FieldElement};

use ir_core::{Instruction, SsaVar, Visibility};

use crate::lysis_lift::WalkError;

const BIT_LIMIT: u32 = u8::MAX as u32;

/// SSA → interner-id state shared by the per-instruction arms.
pub(super) struct DirectInternState {
    /// Dense `SsaVar.0` → `NodeId` map (the walk numbers vars
    /// sequentially, so a Vec beats a hash map at circuit scale).
    map: Vec<Option<NodeId>>,
    /// Memoized `Const(1)` for the desugared forms — the walker's
    /// lazy `one` register. Interner dedup makes the memo an
    /// optimization only: a body-level `Const(1)` interns to it.
    one: Option<NodeId>,
    /// First error, surfaced after the walk through the same
    /// [`WalkError`] variants the cable raises. Sticky.
    error: Option<WalkError>,
}

impl DirectInternState {
    pub(super) fn new() -> Self {
        Self {
            map: Vec::new(),
            one: None,
            error: None,
        }
    }

    pub(super) fn take_error(&mut self) -> Option<WalkError> {
        self.error.take()
    }

    fn bind(&mut self, var: SsaVar, id: NodeId) {
        let idx = var.0 as usize;
        if idx >= self.map.len() {
            self.map.resize(idx + 1, None);
        }
        self.map[idx] = Some(id);
    }

    fn resolve(&mut self, var: SsaVar) -> Option<NodeId> {
        let found = self.map.get(var.0 as usize).copied().flatten();
        if found.is_none() {
            self.error.get_or_insert(WalkError::UndefinedSsaVar(var));
        }
        found
    }

    fn guard_bits(&mut self, kind: &'static str, got: u32) -> bool {
        if got > BIT_LIMIT {
            self.error.get_or_insert(WalkError::OperandOutOfRange {
                kind,
                limit: BIT_LIMIT,
                got,
            });
            return false;
        }
        true
    }

    fn one_id<F: FieldBackend, S: IrSink<F>>(&mut self, sink: &mut S) -> NodeId {
        if let Some(id) = self.one {
            return id;
        }
        let id = sink.intern_pure(InstructionKind::Const {
            result: NodeId::PLACEHOLDER,
            value: FieldElement::<F>::one(),
        });
        self.one = Some(id);
        id
    }

    fn pure_bin<F: FieldBackend, S: IrSink<F>>(
        &mut self,
        sink: &mut S,
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        make: impl FnOnce(NodeId, NodeId) -> InstructionKind<F>,
    ) {
        let (Some(l), Some(r)) = (self.resolve(lhs), self.resolve(rhs)) else {
            return;
        };
        let id = sink.intern_pure(make(l, r));
        self.bind(result, id);
    }

    /// Feed one Plain instruction, performing the same sink-call
    /// sequence the executor performs for the walker's lowering of it.
    pub(super) fn feed_plain<F: FieldBackend, S: IrSink<F>>(
        &mut self,
        sink: &mut S,
        inst: Instruction<F>,
    ) {
        if self.error.is_some() {
            return;
        }
        match inst {
            Instruction::Const { result, value } => {
                let id = sink.intern_pure(InstructionKind::Const {
                    result: NodeId::PLACEHOLDER,
                    value,
                });
                self.bind(result, id);
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
                self.bind(result, id);
            }
            Instruction::Add { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::Add {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            Instruction::Sub { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            Instruction::Mul { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::Mul {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            Instruction::Div { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::Div {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            Instruction::Neg { result, operand } => {
                let Some(op) = self.resolve(operand) else {
                    return;
                };
                let id = sink.intern_pure(InstructionKind::Neg {
                    result: NodeId::PLACEHOLDER,
                    operand: op,
                });
                self.bind(result, id);
            }
            // Walker desugar: Not(x) = Sub(one, x); `one` interns first.
            Instruction::Not { result, operand } => {
                let one = self.one_id(sink);
                let Some(x) = self.resolve(operand) else {
                    return;
                };
                let id = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: one,
                    rhs: x,
                });
                self.bind(result, id);
            }
            // Walker desugar: And(x, y) = Mul(x, y) (boolean operands).
            Instruction::And { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::Mul {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            // Walker desugar: Or(x, y) = x + y - x*y, in Add, Mul, Sub order.
            Instruction::Or { result, lhs, rhs } => {
                let (Some(l), Some(r)) = (self.resolve(lhs), self.resolve(rhs)) else {
                    return;
                };
                let sum = sink.intern_pure(InstructionKind::Add {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
                let prod = sink.intern_pure(InstructionKind::Mul {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
                let id = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: sum,
                    rhs: prod,
                });
                self.bind(result, id);
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let (Some(c), Some(t), Some(e)) = (
                    self.resolve(cond),
                    self.resolve(if_true),
                    self.resolve(if_false),
                ) else {
                    return;
                };
                let id = sink.intern_pure(InstructionKind::Mux {
                    result: NodeId::PLACEHOLDER,
                    cond: c,
                    if_true: t,
                    if_false: e,
                });
                self.bind(result, id);
            }
            Instruction::IsEq { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::IsEq {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            Instruction::IsLt { result, lhs, rhs } => {
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::IsLt {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
            }
            // Walker desugar: IsNeq(x, y) = Sub(one, IsEq(x, y)); `one`
            // interns before the IsEq (the walker resolves it first).
            Instruction::IsNeq { result, lhs, rhs } => {
                let one = self.one_id(sink);
                let (Some(l), Some(r)) = (self.resolve(lhs), self.resolve(rhs)) else {
                    return;
                };
                let eq = sink.intern_pure(InstructionKind::IsEq {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                });
                let id = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: one,
                    rhs: eq,
                });
                self.bind(result, id);
            }
            // Walker desugar: IsLe(x, y) = Sub(one, IsLt(y, x)).
            Instruction::IsLe { result, lhs, rhs } => {
                let one = self.one_id(sink);
                let (Some(l), Some(r)) = (self.resolve(lhs), self.resolve(rhs)) else {
                    return;
                };
                let lt = sink.intern_pure(InstructionKind::IsLt {
                    result: NodeId::PLACEHOLDER,
                    lhs: r,
                    rhs: l,
                });
                let id = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: one,
                    rhs: lt,
                });
                self.bind(result, id);
            }
            Instruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                if !self.guard_bits("IsLtBounded.bitwidth", bitwidth) {
                    return;
                }
                self.pure_bin(sink, result, lhs, rhs, |l, r| {
                    InstructionKind::IsLtBounded {
                        result: NodeId::PLACEHOLDER,
                        lhs: l,
                        rhs: r,
                        bitwidth,
                    }
                });
            }
            // Walker desugar: IsLeBounded(x, y, w) = Sub(one, IsLtBounded(y, x, w)).
            Instruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                if !self.guard_bits("IsLeBounded.bitwidth", bitwidth) {
                    return;
                }
                let one = self.one_id(sink);
                let (Some(l), Some(r)) = (self.resolve(lhs), self.resolve(rhs)) else {
                    return;
                };
                let lt = sink.intern_pure(InstructionKind::IsLtBounded {
                    result: NodeId::PLACEHOLDER,
                    lhs: r,
                    rhs: l,
                    bitwidth,
                });
                let id = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: one,
                    rhs: lt,
                });
                self.bind(result, id);
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let (Some(l), Some(r)) = (self.resolve(left), self.resolve(right)) else {
                    return;
                };
                let id = sink.intern_pure(InstructionKind::PoseidonHash {
                    result: NodeId::PLACEHOLDER,
                    left: l,
                    right: r,
                });
                self.bind(result, id);
            }
            // The cable never binds an AssertEq result to a register, so
            // a (nonsensical) downstream read fails on both paths.
            Instruction::AssertEq {
                result: _,
                lhs,
                rhs,
                message,
            } => {
                let (Some(l), Some(r)) = (self.resolve(lhs), self.resolve(rhs)) else {
                    return;
                };
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::AssertEq {
                    result: id,
                    lhs: l,
                    rhs: r,
                    message,
                });
            }
            // Walker desugar: Assert(x) = AssertEq(x, one).
            Instruction::Assert {
                result: _,
                operand,
                message,
            } => {
                let one = self.one_id(sink);
                let Some(op) = self.resolve(operand) else {
                    return;
                };
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::AssertEq {
                    result: id,
                    lhs: op,
                    rhs: one,
                    message,
                });
            }
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                if !self.guard_bits("RangeCheck.bits", bits) {
                    return;
                }
                let Some(op) = self.resolve(operand) else {
                    return;
                };
                let id = sink.fresh_id();
                sink.emit_effect(InstructionKind::RangeCheck {
                    result: id,
                    operand: op,
                    bits,
                });
                // Result aliases the operand once the bit-width
                // constraint is enforced — the fresh effect id never
                // reaches a register on the cable either.
                self.bind(result, op);
            }
            Instruction::Decompose {
                result: _,
                bit_results,
                operand,
                num_bits,
            } => {
                if !self.guard_bits("Decompose.num_bits", num_bits) {
                    return;
                }
                let Some(op) = self.resolve(operand) else {
                    return;
                };
                let bits: Vec<NodeId> = (0..num_bits).map(|_| sink.fresh_id()).collect();
                sink.emit_effect(InstructionKind::Decompose {
                    result: op,
                    bit_results: bits.clone(),
                    operand: op,
                    num_bits,
                });
                // The walker binds only the bit results; the aggregate
                // `result` var is unreadable downstream on the cable
                // and stays unreadable here.
                for (ssa, id) in bit_results.into_iter().zip(bits) {
                    self.bind(ssa, id);
                }
            }
            Instruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                if !self.guard_bits("IntDiv.max_bits", max_bits) {
                    return;
                }
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::IntDiv {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                    max_bits,
                });
            }
            Instruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                if !self.guard_bits("IntMod.max_bits", max_bits) {
                    return;
                }
                self.pure_bin(sink, result, lhs, rhs, |l, r| InstructionKind::IntMod {
                    result: NodeId::PLACEHOLDER,
                    lhs: l,
                    rhs: r,
                    max_bits,
                });
            }
            Instruction::WitnessCall(call) => {
                let mut inputs = Vec::with_capacity(call.inputs.len());
                for var in &call.inputs {
                    let Some(id) = self.resolve(*var) else {
                        return;
                    };
                    inputs.push(id);
                }
                let outputs: Vec<NodeId> =
                    (0..call.outputs.len()).map(|_| sink.fresh_id()).collect();
                sink.emit_effect(InstructionKind::WitnessCall(Box::new(
                    LysisWitnessCallBody {
                        outputs: outputs.clone(),
                        inputs,
                        program_bytes: call.program_bytes,
                    },
                )));
                for (ssa, id) in call.outputs.into_iter().zip(outputs) {
                    self.bind(ssa, id);
                }
            }
        }
    }
}
