//! ExtendedInstruction walker (RFC §6.3).
//!
//! Consumes a `Vec<ExtendedInstruction<F>>` and emits a Lysis
//! `Program<F>` whose execution reproduces the original instruction
//! stream modulo the interner's hash-cons deduplication.
//!
//! ## Scope
//!
//! Phase 3.B.7 handles:
//!
//! - `Plain(Instruction<F>)` — every arithmetic, logic, hash, and
//!   side-effect variant except `WitnessCall` (Artik bytecode blob
//!   interning defers to a later iteration).
//! - `LoopUnroll` — emits the Lysis `LoopUnroll` opcode with an
//!   inline body. The executor's Phase 3.B.8 loop machinery takes
//!   care of iteration binding and hash-cons dedup within the body.
//!
//! Not handled:
//!
//! - `TemplateBody` / `TemplateCall` — template extraction is wired
//!   through `extract.rs`, but the bytecode emission of
//!   `DefineTemplate` + `InstantiateTemplate` flows through a
//!   different path that Phase 3.C will connect to the oracle gate.
//!   Walkers that hit these variants in Phase 3 return
//!   `WalkError::TemplateNotSupported`; the walker driver
//!   (future work) falls back to inline unrolling when that error
//!   appears.
//! - `WitnessCall` — requires Artik bytecode blob interning. Defer.
//! - Negative loop bounds — `LoopUnroll` uses `u32` in the bytecode,
//!   so negative `i64` bounds are rejected up-front.
//!
//! ## Register allocation
//!
//! Bump allocation via `lysis::lower::RegAllocator`: every SsaVar
//! that defines a fresh value gets the next register, and the
//! mapping persists for the whole program (no release). Frame size
//! is the high water mark.

use std::collections::HashMap;

use artik::FieldFamily;
use lysis::bytecode::encoding::encode_opcode;
use lysis::bytecode::Opcode;
use lysis::lower::{AllocError, RegAllocator, RegId};
use lysis::program::Program;
use lysis::ProgramBuilder;
use memory::{FieldBackend, FieldElement};

use crate::prove_ir::extended::ExtendedInstruction;
use crate::types::{Instruction, SsaVar, Visibility};

/// Errors raised by [`Walker::lower`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// Register file ran out.
    Alloc(AllocError),
    /// The body contains a `TemplateCall` or `TemplateBody`; Phase
    /// 3.B.7 only emits inline + `LoopUnroll`.
    TemplateNotSupported,
    /// `WitnessCall` is not yet emitted by the walker (needs Artik
    /// bytecode interning).
    WitnessCallNotSupported,
    /// An operand referenced an SsaVar that was never produced by an
    /// earlier instruction in the walk. Either the program is
    /// malformed or the walker is missing a variant.
    UndefinedSsaVar(SsaVar),
    /// `LoopUnroll.start` or `LoopUnroll.end` was negative; the
    /// bytecode's `u32` bounds can't represent it.
    NegativeLoopBound { start: i64, end: i64 },
    /// A `LoopUnroll` body exceeded the `u16` byte-length field.
    LoopBodyTooLong { bytes: u32 },
    /// Internal invariant: a desugaring reached for the `one` constant
    /// register before the pre-scan allocated it. This is a walker
    /// bug — surface it rather than silently emitting a Trap.
    OneConstNotInitialized,
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alloc(e) => write!(f, "walker: {e}"),
            Self::TemplateNotSupported => f.write_str(
                "walker: TemplateCall/TemplateBody not emitted yet (Phase 3 MVP uses LoopUnroll only)",
            ),
            Self::WitnessCallNotSupported => {
                f.write_str("walker: WitnessCall emission pending")
            }
            Self::UndefinedSsaVar(v) => write!(f, "walker: undefined SsaVar {v}"),
            Self::NegativeLoopBound { start, end } => {
                write!(f, "walker: LoopUnroll bounds must be ≥ 0 (got {start}..{end})")
            }
            Self::LoopBodyTooLong { bytes } => {
                write!(f, "walker: LoopUnroll body length {bytes} exceeds u16 max")
            }
            Self::OneConstNotInitialized => f.write_str(
                "walker: desugaring referenced `one` register but pre-scan did not allocate it (walker bug)",
            ),
        }
    }
}

impl std::error::Error for WalkError {}

impl From<AllocError> for WalkError {
    fn from(e: AllocError) -> Self {
        Self::Alloc(e)
    }
}

/// Emits Lysis bytecode from an `ExtendedInstruction` stream.
pub struct Walker<F: FieldBackend> {
    builder: ProgramBuilder<F>,
    allocator: RegAllocator,
    ssa_to_reg: HashMap<SsaVar, RegId>,
    /// Register holding the field element 1. Lazily allocated at the
    /// start of [`Self::lower`] iff the body contains a desugaring that
    /// references it (Not, Assert, IsNeq, IsLe, IsLeBounded). Emitting
    /// at the top — outside every `LoopUnroll` — keeps the body's
    /// pre-computed byte size correct.
    one_reg: Option<RegId>,
}

impl<F: FieldBackend> Walker<F> {
    pub fn new(family: FieldFamily) -> Self {
        Self {
            builder: ProgramBuilder::new(family),
            allocator: RegAllocator::new(),
            ssa_to_reg: HashMap::new(),
            one_reg: None,
        }
    }

    /// Lower an entire body into a finished [`Program`]. Appends a
    /// terminating `Halt` after the last emitted opcode.
    pub fn lower(mut self, body: &[ExtendedInstruction<F>]) -> Result<Program<F>, WalkError> {
        if body_needs_one_const(body) {
            let idx = self.builder.intern_field(FieldElement::<F>::one()) as u16;
            let reg = self.allocator.alloc()?;
            self.builder.load_const(reg, idx);
            self.one_reg = Some(reg);
        }
        for inst in body {
            self.emit(inst)?;
        }
        self.builder.halt();
        Ok(self.builder.finish())
    }

    /// Return the pre-allocated register holding `1`, or error if the
    /// pre-scan missed it (walker-internal invariant violation).
    fn one(&self) -> Result<RegId, WalkError> {
        self.one_reg.ok_or(WalkError::OneConstNotInitialized)
    }

    fn emit(&mut self, inst: &ExtendedInstruction<F>) -> Result<(), WalkError> {
        match inst {
            ExtendedInstruction::Plain(i) => self.emit_plain(i),
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body,
            } => self.emit_loop_unroll(*iter_var, *start, *end, body),
            ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => {
                Err(WalkError::TemplateNotSupported)
            }
        }
    }

    fn emit_plain(&mut self, inst: &Instruction<F>) -> Result<(), WalkError> {
        match inst {
            Instruction::Const { result, value } => {
                let idx = self.builder.intern_field(*value) as u16;
                let dst = self.allocator.alloc()?;
                self.builder.load_const(dst, idx);
                self.bind(*result, dst);
            }
            Instruction::Input {
                result,
                name,
                visibility,
            } => {
                let name_idx = self.builder.intern_string(name.clone()) as u16;
                let dst = self.allocator.alloc()?;
                self.builder.load_input(dst, name_idx, map_vis(*visibility));
                self.bind(*result, dst);
            }

            // ---------- pure binary ----------
            Instruction::Add { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_add(dst, l, r);
                self.bind(*result, dst);
            }
            Instruction::Sub { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_sub(dst, l, r);
                self.bind(*result, dst);
            }
            Instruction::Mul { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_mul(dst, l, r);
                self.bind(*result, dst);
            }
            // Lysis has no dedicated EmitDiv opcode yet — fall through
            // to Mul-by-inverse or refuse. For Phase 3 MVP we refuse;
            // ProveIR programs rarely emit Div at this layer.
            Instruction::Div { .. } => {
                return Err(WalkError::WitnessCallNotSupported);
            }

            // ---------- unary ----------
            Instruction::Neg { result, operand } => {
                let op = self.resolve(*operand)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_neg(dst, op);
                self.bind(*result, dst);
            }

            // ---------- boolean / logic — desugared to arithmetic.
            //            The operands are assumed boolean (0 or 1) by
            //            the upstream circuit; Lysis doesn't re-check.
            Instruction::Not { result, operand } => {
                let one = self.one()?;
                let x = self.resolve(*operand)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_sub(dst, one, x);
                self.bind(*result, dst);
            }
            Instruction::And { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_mul(dst, l, r);
                self.bind(*result, dst);
            }
            Instruction::Or { result, lhs, rhs } => {
                // x OR y = x + y - x*y (for booleans).
                let (l, r) = self.bin(*lhs, *rhs)?;
                let sum = self.allocator.alloc()?;
                self.builder.emit_add(sum, l, r);
                let prod = self.allocator.alloc()?;
                self.builder.emit_mul(prod, l, r);
                let dst = self.allocator.alloc()?;
                self.builder.emit_sub(dst, sum, prod);
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
                self.builder.emit_mux(dst, c, t, e);
                self.bind(*result, dst);
            }

            // ---------- comparisons ----------
            Instruction::IsEq { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_is_eq(dst, l, r);
                self.bind(*result, dst);
            }
            Instruction::IsLt { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.builder.emit_is_lt(dst, l, r);
                self.bind(*result, dst);
            }
            Instruction::IsNeq { .. }
            | Instruction::IsLe { .. }
            | Instruction::IsLtBounded { .. }
            | Instruction::IsLeBounded { .. } => {
                // Lysis opcodes for these are not yet defined in the
                // bytecode surface. Phase 4 extends; for now refuse.
                return Err(WalkError::WitnessCallNotSupported);
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
                self.builder.emit_poseidon_hash(dst, vec![l, r]);
                self.bind(*result, dst);
            }

            // ---------- constraint side-effects ----------
            Instruction::AssertEq {
                result: _,
                lhs,
                rhs,
                message: _,
            } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                self.builder.emit_assert_eq(l, r);
            }
            Instruction::Assert {
                result: _, operand, ..
            } => {
                // Desugar: assert operand == 1.
                let one = self.one()?;
                let op = self.resolve(*operand)?;
                self.builder.emit_assert_eq(op, one);
            }
            Instruction::RangeCheck {
                result: _,
                operand,
                bits,
            } => {
                if *bits > u32::from(u8::MAX) {
                    return Err(WalkError::WitnessCallNotSupported);
                }
                let op = self.resolve(*operand)?;
                self.builder.emit_range_check(op, *bits as u8);
            }
            Instruction::Decompose {
                result: _,
                bit_results,
                operand,
                num_bits,
            } => {
                if *num_bits > u32::from(u8::MAX) {
                    return Err(WalkError::WitnessCallNotSupported);
                }
                let op = self.resolve(*operand)?;
                let base = self.allocator.alloc()?;
                // Extra bits (bit 1..num_bits-1) consume consecutive slots.
                for _ in 1..*num_bits {
                    let _ = self.allocator.alloc()?;
                }
                self.builder.emit_decompose(base, op, *num_bits as u8);
                // Bind each bit_result to its corresponding register.
                for (i, br) in bit_results.iter().enumerate() {
                    self.bind(*br, base + i as RegId);
                }
            }

            // ---------- integer div/mod + witness call ----------
            Instruction::IntDiv { .. } | Instruction::IntMod { .. } => {
                return Err(WalkError::WitnessCallNotSupported);
            }
            Instruction::WitnessCall { .. } => {
                return Err(WalkError::WitnessCallNotSupported);
            }
        }
        Ok(())
    }

    fn emit_loop_unroll(
        &mut self,
        iter_var: SsaVar,
        start: i64,
        end: i64,
        body: &[ExtendedInstruction<F>],
    ) -> Result<(), WalkError> {
        if start < 0 || end < 0 {
            return Err(WalkError::NegativeLoopBound { start, end });
        }
        let start_u32 = start as u32;
        let end_u32 = end as u32;

        let iter_reg = self.allocator.alloc()?;
        self.bind(iter_var, iter_reg);

        // Pre-compute the body's encoded byte length so the
        // LoopUnroll opcode can carry it. We build a throw-away
        // walker state that matches our current reg allocator
        // exactly — this lets size calculation depend on the
        // allocator's current offset (it doesn't today, but keeping
        // the abstraction gives Phase 4 room).
        let body_len = body_byte_size(body)?;
        if body_len > u32::from(u16::MAX) {
            return Err(WalkError::LoopBodyTooLong { bytes: body_len });
        }

        self.builder
            .loop_unroll(iter_reg, start_u32, end_u32, body_len as u16);

        for inst in body {
            self.emit(inst)?;
        }
        Ok(())
    }

    fn bin(&self, lhs: SsaVar, rhs: SsaVar) -> Result<(RegId, RegId), WalkError> {
        Ok((self.resolve(lhs)?, self.resolve(rhs)?))
    }

    fn resolve(&self, var: SsaVar) -> Result<RegId, WalkError> {
        self.ssa_to_reg
            .get(&var)
            .copied()
            .ok_or(WalkError::UndefinedSsaVar(var))
    }

    fn bind(&mut self, var: SsaVar, reg: RegId) {
        self.ssa_to_reg.insert(var, reg);
    }
}

fn map_vis(v: Visibility) -> lysis::Visibility {
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
fn body_byte_size<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> Result<u32, WalkError> {
    let mut total: u32 = 0;
    for inst in body {
        total = total.saturating_add(extinst_byte_size(inst)?);
    }
    Ok(total)
}

fn extinst_byte_size<F: FieldBackend>(inst: &ExtendedInstruction<F>) -> Result<u32, WalkError> {
    match inst {
        ExtendedInstruction::Plain(i) => instruction_byte_size(i),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            // 1 tag + 1 reg + 4 start + 4 end + 2 body_len = 12
            let mut total = 12u32;
            total = total.saturating_add(body_byte_size(body)?);
            Ok(total)
        }
        ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => {
            Err(WalkError::TemplateNotSupported)
        }
    }
}

fn instruction_byte_size<F: FieldBackend>(inst: &Instruction<F>) -> Result<u32, WalkError> {
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
fn placeholder_opcodes<F: FieldBackend>(inst: &Instruction<F>) -> Result<Vec<Opcode>, WalkError> {
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
            in_regs: vec![0, 0],
        }),
        Instruction::AssertEq { .. } => bin(Opcode::EmitAssertEq { lhs: 0, rhs: 0 }),
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
        Instruction::Assert { .. } => bin(Opcode::EmitAssertEq { lhs: 0, rhs: 0 }),

        _ => return Err(WalkError::WitnessCallNotSupported),
    })
}

/// Returns `true` iff the body (recursively) contains at least one
/// instruction whose desugaring references the `one` constant register.
/// Used by [`Walker::lower`] to decide whether to eagerly emit a
/// top-level `LoadConst(1)`.
fn body_needs_one_const<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    body.iter().any(|inst| match inst {
        ExtendedInstruction::Plain(i) => instruction_needs_one(i),
        ExtendedInstruction::LoopUnroll { body, .. } => body_needs_one_const(body),
        ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => {
            false
        }
    })
}

fn instruction_needs_one<F: FieldBackend>(inst: &Instruction<F>) -> bool {
    matches!(inst, Instruction::Not { .. } | Instruction::Assert { .. })
}

#[cfg(test)]
mod tests {
    use lysis::{execute, InterningSink, LysisConfig};
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::types::Visibility as IrVisibility;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    fn plain(inst: Instruction<Bn254Fr>) -> ExtendedInstruction<Bn254Fr> {
        ExtendedInstruction::Plain(inst)
    }

    /// Emit + execute the body through a fresh InterningSink; return
    /// the materialized `Vec<InstructionKind>`.
    fn run(body: &[ExtendedInstruction<Bn254Fr>]) -> Vec<lysis::InstructionKind<Bn254Fr>> {
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(body).expect("lower");
        let mut sink = InterningSink::<Bn254Fr>::new();
        execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
        sink.materialize()
    }

    #[test]
    fn lowers_empty_body_to_halt_only() {
        let out = run(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn lowers_const_add_const() {
        let body = vec![
            plain(Instruction::Const {
                result: ssa(0),
                value: fe(7),
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(3),
            }),
            plain(Instruction::Add {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        // Two Consts + one Add.
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], lysis::InstructionKind::Const { .. }));
        assert!(matches!(out[1], lysis::InstructionKind::Const { .. }));
        assert!(matches!(out[2], lysis::InstructionKind::Add { .. }));
    }

    #[test]
    fn lowers_range_check_and_decompose() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::RangeCheck {
                result: ssa(0),
                operand: ssa(0),
                bits: 8,
            }),
            plain(Instruction::Decompose {
                result: ssa(0),
                bit_results: vec![ssa(1), ssa(2), ssa(3), ssa(4)],
                operand: ssa(0),
                num_bits: 4,
            }),
        ];
        let out = run(&body);
        // Input + RangeCheck + Decompose = 3 instructions.
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], lysis::InstructionKind::Input { .. }));
        assert!(matches!(out[1], lysis::InstructionKind::RangeCheck { .. }));
        let bit_count = match &out[2] {
            lysis::InstructionKind::Decompose { bit_results, .. } => bit_results.len(),
            _ => panic!(),
        };
        assert_eq!(bit_count, 4);
    }

    #[test]
    fn lowers_assert_eq_side_effect() {
        let body = vec![
            plain(Instruction::Const {
                result: ssa(0),
                value: fe(5),
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(5),
            }),
            plain(Instruction::AssertEq {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
                message: None,
            }),
        ];
        let out = run(&body);
        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 1);
    }

    #[test]
    fn lowers_loop_unroll_three_iterations() {
        // for i in 0..3: r_mul = i * i
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 3,
            body: vec![plain(Instruction::Mul {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(0),
            })],
        }];
        let out = run(&body);
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let muls = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
            .count();
        assert_eq!(consts, 3, "one Const per iteration (iter_var)");
        assert_eq!(muls, 3, "three Muls, one per iteration");
    }

    #[test]
    fn refuses_template_call() {
        let body = vec![ExtendedInstruction::TemplateCall {
            template_id: crate::prove_ir::extended::TemplateId(0),
            captures: vec![],
            outputs: vec![],
        }];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert_eq!(err, WalkError::TemplateNotSupported);
    }

    #[test]
    fn refuses_negative_loop_bound() {
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: -1,
            end: 2,
            body: vec![],
        }];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert!(matches!(err, WalkError::NegativeLoopBound { .. }));
    }

    #[test]
    fn desugars_not_to_sub_with_one() {
        // Not(x) = 1 - x. Expect: LoadConst(1), Input(x), Sub(one, x).
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Not {
                result: ssa(1),
                operand: ssa(0),
            }),
        ];
        let out = run(&body);
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(consts, 1, "one pre-allocated Const for `one`");
        assert_eq!(subs, 1, "Not desugars to one Sub");
    }

    #[test]
    fn desugars_and_to_mul() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::And {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        // And does NOT need `one` — no extra Const emitted.
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let muls = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
            .count();
        assert_eq!(consts, 0, "no one-const needed when only And is used");
        assert_eq!(muls, 1, "And desugars to one Mul");
    }

    #[test]
    fn desugars_or_to_add_mul_sub() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Or {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        let adds = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Add { .. }))
            .count();
        let muls = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(adds, 1);
        assert_eq!(muls, 1);
        assert_eq!(subs, 1);
    }

    #[test]
    fn desugars_assert_to_assert_eq_with_one() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Assert {
                result: ssa(1),
                operand: ssa(0),
                message: None,
            }),
        ];
        let out = run(&body);
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(consts, 1, "one pre-allocated Const for `one`");
        assert_eq!(asserts, 1, "Assert(x) desugars to AssertEq(x, one)");
    }

    #[test]
    fn desugars_not_inside_loop_body() {
        // The `one` Const is emitted ABOVE the loop so body_byte_size
        // stays correct. Use iter bounds that avoid collision with 1
        // (which would get hash-cons deduped against `one`): 3..6.
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 3,
            end: 6,
            body: vec![plain(Instruction::Not {
                result: ssa(1),
                operand: ssa(0),
            })],
        }];
        let out = run(&body);
        // Expect: 1 one-const + 3 distinct iter consts (3, 4, 5) + 3 Subs.
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(consts, 4, "one + 3 distinct iter vars");
        assert_eq!(subs, 3, "Not per iteration");
    }

    #[test]
    fn refuses_witness_call() {
        let body = vec![plain(Instruction::WitnessCall {
            outputs: vec![ssa(0)],
            inputs: vec![],
            program_bytes: vec![],
        })];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert_eq!(err, WalkError::WitnessCallNotSupported);
    }
}
