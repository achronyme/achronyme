//! `ExtendedInstruction<F>` — the ProveIR schema that the Lysis
//! lifter consumes.
//!
//! ProveIR today lowers to `Vec<Instruction<F>>` via the eager
//! `instantiate` pipeline. That pipeline inlines template bodies,
//! unrolls every loop, and produces the flat SSA stream the R1CS
//! backend expects. The downside — visible as a 6.4 GB peak RSS OOM
//! on SHA-256(64) — is that identical sub-trees get re-emitted
//! per-iteration.
//!
//! The extended schema keeps the same pure-op vocabulary
//! ([`Instruction<F>`] unchanged) but adds three variants that carry
//! the structural information the Lysis lifter needs:
//!
//! - [`ExtendedInstruction::Plain`] wraps an existing
//!   [`Instruction<F>`]. Every site in the ProveIR compiler that
//!   used to push an `Instruction<F>` into a `Vec` can migrate by
//!   wrapping in `Plain(...)`.
//! - [`ExtendedInstruction::TemplateBody`] declares a reusable body
//!   that will be instantiated N times with different captures.
//!   Produced by the lifter's template extraction pass
//!   (RFC §6.2); NOT a language surface construct — `D5` in RFC
//!   §2 is explicit about no syntax change.
//! - [`ExtendedInstruction::TemplateCall`] instantiates a
//!   previously-declared body. The `outputs` slots are the SSA
//!   vars the call binds in the caller's frame.
//! - [`ExtendedInstruction::LoopUnroll`] carries a data-dependent
//!   loop that BTA could not lift. The body stays as
//!   `Vec<ExtendedInstruction<F>>` (can nest) and the lifter emits
//!   the executor's `LoopUnroll` opcode instead of a template
//!   call.
//!
//! `ir::Instruction<F>` stays exactly as it is. R1CS, the optimizer,
//! `Display`, the inspector, and every `impl<F>` on `Instruction<F>`
//! keep working unchanged. The two types coexist through
//! [`ExtendedInstruction::Plain`] and the `From<Instruction<F>>`
//! conversion in the companion commit.

use diagnostics::SpanRange;
use ir_core::{Instruction, SsaVar};
use memory::{Bn254Fr, FieldBackend};

/// Opaque handle for a [`ExtendedInstruction::TemplateBody`]
/// declaration. `u16` matches the wire-level `template_id` field in
/// Lysis bytecode opcodes (see `lysis::Opcode::DefineTemplate`).
///
/// New ids are handed out by the lifter — ProveIR authors never name
/// a `TemplateId` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TemplateId(pub u16);

impl std::fmt::Display for TemplateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "T{}", self.0)
    }
}

/// ProveIR instruction with the four additional shapes the Lysis
/// lifter needs (RFC §3.1.1, §6.3).
///
/// The generic parameter matches `Instruction<F>`'s so `Plain`
/// passes straight through without type-state gymnastics.
#[derive(Debug, Clone)]
pub enum ExtendedInstruction<F: FieldBackend = Bn254Fr> {
    /// A pre-existing SSA instruction — pass-through. Every
    /// callable / assert / input / arithmetic op that the current
    /// `ir::prove_ir::instantiate` produces is wrapped here.
    Plain(Instruction<F>),

    /// Declare a reusable template body. Produced by the BTA +
    /// lambda-lifting pass (RFC §6.1, §6.2). The body is itself an
    /// `ExtendedInstruction` list so nested templates / loops
    /// nest naturally.
    ///
    /// `frame_size` bounds the register file for one instantiation;
    /// `n_params` is the capture count the `TemplateCall` must
    /// satisfy.
    TemplateBody {
        id: TemplateId,
        frame_size: u8,
        n_params: u8,
        /// SSA vars (in capture-index order) that the body references
        /// from the enclosing scope. The walker binds `captures[i]`
        /// to register `i` of the template frame before emitting the
        /// body, mirroring the executor's `InstantiateTemplate`
        /// dispatch (which copies caller's `capture_regs[i]` into
        /// callee's `regs[i]`). `captures.len()` must equal
        /// `n_params`. Carried on the `TemplateBody` variant — not
        /// inferred at walker time — because BTA's `OuterRef` set
        /// already pinned the order at lift time, and re-deriving it
        /// inside the walker would require a second OuterRef scan.
        captures: Vec<SsaVar>,
        body: Vec<ExtendedInstruction<F>>,
    },

    /// Instantiate a previously-declared [`TemplateBody`].
    ///
    /// `captures` are SSA vars already defined in the enclosing
    /// frame; the lifter copies their values into the new frame's
    /// parameter slots. `outputs` are the SSA vars the caller
    /// expects populated when the call returns.
    TemplateCall {
        template_id: TemplateId,
        captures: Vec<SsaVar>,
        outputs: Vec<SsaVar>,
    },

    /// A loop whose body varies by iteration in a way BTA could
    /// not lift (RFC §6.1.1 `DataDependent`). The bytecode emitter
    /// writes a `Lysis::Opcode::LoopUnroll` and inlines the body.
    ///
    /// `start` / `end` are compile-time-known bounds (if they
    /// weren't, the classification would be `Parametric` and a
    /// template would have been produced instead).
    LoopUnroll {
        iter_var: SsaVar,
        start: i64,
        end: i64,
        body: Vec<ExtendedInstruction<F>>,
    },

    /// A side-effect (signal write or witness hint) at an array slot
    /// whose index is an SSA-symbolic expression — i.e. depends on
    /// the enclosing `LoopUnroll`'s `iter_var` rather than a
    /// compile-time constant.
    ///
    /// Without this variant, every `paddedIn[i] <-- 0` /
    /// `out[i] <-- ...` in a circom loop would have to be
    /// force-unrolled at the circom lowering layer (see
    /// `circom/src/lowering/statements/loops.rs::LoopLowering::IndexedAssignmentLoop`),
    /// making the IR stream balloon to N inline copies of every
    /// loop body. With `SymbolicIndexedEffect`, the IR keeps the
    /// loop rolled inside a `LoopUnroll`, BTA can probe-classify it
    /// as `Uniform`, and structural extraction lifts the body to a
    /// single `TemplateBody`.
    ///
    /// # Field semantics
    ///
    /// - `kind` — `Let` for signal-assignment writes
    ///   (`arr[i] <-- expr`); `WitnessHint` for the
    ///   `<-- expr` shape that becomes a witness `Input` rather than
    ///   a constraint.
    /// - `array_slots` — pre-resolved list of element SSA vars (the
    ///   instantiate-time materialization of the array's elements,
    ///   e.g. `[paddedIn_0, paddedIn_1, ..., paddedIn_N-1]`).
    ///   Walker indexes into this with the const-folded index at
    ///   per-iteration unfolding time. Carrying the list directly
    ///   avoids round-tripping through the instantiate-time `env`,
    ///   which is gone by walker time.
    /// - `index_var` — SSA var holding the index expression. At BTA
    ///   probe time, two probes resolve this to different slot-
    ///   tagged Const nodes. At walker unfolding time, the executor
    ///   const-folds it into a literal `usize` so the array element
    ///   resolves uniquely per iteration.
    /// - `value_var` — for `Let`, the SSA var holding the value to
    ///   write. `None` for `WitnessHint` (the witness is a fresh
    ///   `Input` named `array_<index>`).
    /// - `span` — optional source span; passes through diagnostic
    ///   reporting.
    SymbolicIndexedEffect {
        kind: IndexedEffectKind,
        array_slots: Vec<SsaVar>,
        index_var: SsaVar,
        value_var: Option<SsaVar>,
        span: Option<SpanRange>,
    },

    /// A read from an array slot at an SSA-symbolic index — the
    /// symmetric counterpart of [`Self::SymbolicIndexedEffect`] on the
    /// read side. Pre-Gap-1.5, every `out[i] <-- in[i]` in a circom
    /// loop required `in[i]` to const-fold at instantiate time
    /// ([`crate::instantiate`] eager array indexing); for the SHA-256
    /// padding loop the index is the loop var so the read can't fold
    /// without unrolling, the very thing Gap 1 keeps rolled.
    ///
    /// With `SymbolicArrayRead`, instantiation mints a fresh SSA
    /// `result_var` to hand back to the caller without emitting any
    /// `Plain` instruction; at walker time the read resolves to
    /// `array_slots[idx]` per iteration and `result_var` is rebound to
    /// that slot's already-bound register. No opcode is emitted — the
    /// node is a symbolic alias that disappears once the index is
    /// known.
    ///
    /// # Field semantics
    ///
    /// - `result_var` — fresh SSA var produced for the caller of
    ///   `emit_expr`. Per-iteration the walker rebinds it to the
    ///   resolved slot's register; downstream uses inside the same
    ///   iteration body resolve correctly. Outside the rolled loop
    ///   `result_var` would carry the LAST iteration's binding, but
    ///   construction-by-construction the read is only emitted for
    ///   loop-iter-dependent indices, so its uses are necessarily
    ///   inside the same loop body.
    /// - `array_slots` — pre-resolved list of element SSA vars (same
    ///   shape as `SymbolicIndexedEffect::array_slots`).
    /// - `index_var` — SSA var holding the index expression. Walker
    ///   const-folds this via `walker_const`; failure to fold is a
    ///   `WalkError::SymbolicArrayReadNotEmittable`.
    /// - `span` — optional source span.
    SymbolicArrayRead {
        result_var: SsaVar,
        array_slots: Vec<SsaVar>,
        index_var: SsaVar,
        span: Option<SpanRange>,
    },

    /// A `>>` or `<<` shift whose amount is an SSA-symbolic
    /// expression — i.e. depends on the enclosing `LoopUnroll`'s
    /// `iter_var` rather than a compile-time constant.
    ///
    /// Without this variant, every `(in >> i)` / `(in << i)` where
    /// `i` is a loop-iter variable would hit the `resolve_const_u32`
    /// gate in [`crate::instantiate`]'s `ShiftR`/`ShiftL` arms
    /// (`exprs.rs:558-583`) and surface as
    /// `ProveIrError::UnsupportedOperation "shift right amount must
    /// be a compile-time constant"`. SHA-256's padding loop
    /// (`paddedIn[…] <== (nBits >> k) & 1` for `k = 0..nBits`) hits
    /// this even though `k` is a loop-iter constant — the
    /// instantiator's symbolic mode treats `k` as an SSA value.
    ///
    /// With `SymbolicShift`, the IR keeps the shift rolled inside a
    /// `LoopUnroll`; per-iteration the walker const-folds `shift_var`
    /// via `walker_const`, then materialises the same
    /// decompose-then-recompose sequence that
    /// [`crate::instantiate::Instantiator::emit_shift_right`] /
    /// `emit_shift_left` would have emitted at instantiate time. The
    /// rolled body (with the structural shift node) lifts to a
    /// `TemplateBody` if BTA classifies it `Uniform`.
    ///
    /// # Field semantics
    ///
    /// - `result_var` — fresh SSA var produced for the caller of
    ///   `emit_expr`. Per-iteration the walker rebinds it to the
    ///   register that holds the shifted value. Same containment
    ///   invariant as `SymbolicArrayRead::result_var`: the var is
    ///   only used inside the rolled body that introduced it.
    /// - `operand_var` — SSA var holding the value being shifted,
    ///   already emitted as a normal `Plain` instruction by the
    ///   instantiator before this extended op.
    /// - `shift_var` — SSA var holding the shift amount. Walker
    ///   const-folds this to a non-negative `i64` via `walker_const`;
    ///   failure to fold is a
    ///   `WalkError::SymbolicShiftNotEmittable`.
    /// - `num_bits` — bit-width for the operand decomposition
    ///   (constant at instantiate time, identical to the
    ///   non-symbolic shift path's `num_bits` field).
    /// - `direction` — right vs left shift discriminator (see
    ///   [`ShiftDirection`]).
    /// - `span` — optional source span; passes through diagnostic
    ///   reporting.
    SymbolicShift {
        result_var: SsaVar,
        operand_var: SsaVar,
        shift_var: SsaVar,
        num_bits: u32,
        direction: ShiftDirection,
        span: Option<SpanRange>,
    },
}

/// Discriminator for [`ExtendedInstruction::SymbolicShift`].
///
/// `Right` — `operand >> shift` drops the lowest `shift` bits.
/// `Left` — `operand << shift` prepends `shift` zero bits, truncated
/// to `num_bits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShiftDirection {
    Right,
    Left,
}

/// Discriminator for [`ExtendedInstruction::SymbolicIndexedEffect`].
///
/// `Let` — `arr[i] <-- expr` writes a value into the array slot,
/// emitting a constraint that the slot equals the value.
/// `WitnessHint` — `arr[i] <-- expr` in witness-only context emits
/// a fresh `Input(Witness, "arr_{i}")`; the value is resolved later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexedEffectKind {
    Let,
    WitnessHint,
}

impl<F: FieldBackend> ExtendedInstruction<F> {
    /// `true` if this node is a plain pre-existing `Instruction<F>`
    /// with no Lysis-specific structure. Convenient for callers
    /// that want to short-circuit on the common migration case.
    pub fn is_plain(&self) -> bool {
        matches!(self, ExtendedInstruction::Plain(_))
    }

    /// If `Plain`, return the wrapped instruction by reference.
    /// Otherwise `None`.
    pub fn as_plain(&self) -> Option<&Instruction<F>> {
        match self {
            ExtendedInstruction::Plain(inst) => Some(inst),
            _ => None,
        }
    }

    /// If `Plain`, move out the wrapped instruction. Otherwise
    /// return the unchanged `ExtendedInstruction` as `Err` so the
    /// caller can branch without losing data.
    pub fn into_plain(self) -> Result<Instruction<F>, Self> {
        match self {
            ExtendedInstruction::Plain(inst) => Ok(inst),
            other => Err(other),
        }
    }
}

/// The migration primitive for ProveIR authors: every existing
/// `Instruction<F>` push site can be rewritten as
/// `push(inst.into())` to emit the `ExtendedInstruction<F>` form
/// one call at a time.
impl<F: FieldBackend> From<Instruction<F>> for ExtendedInstruction<F> {
    fn from(inst: Instruction<F>) -> Self {
        ExtendedInstruction::Plain(inst)
    }
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use ir_core::Visibility;

    use super::*;

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    #[test]
    fn plain_round_trips_instruction() {
        let inst = Instruction::<Bn254Fr>::Add {
            result: ssa(3),
            lhs: ssa(1),
            rhs: ssa(2),
        };
        let ext = ExtendedInstruction::Plain(inst.clone());
        assert!(ext.is_plain());
        assert!(matches!(ext.as_plain(), Some(Instruction::Add { .. })));
    }

    #[test]
    fn template_body_holds_nested_extended_instructions() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            ExtendedInstruction::Plain(Instruction::Const {
                result: ssa(0),
                value: fe(1),
            }),
            ExtendedInstruction::Plain(Instruction::Add {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(0),
            }),
        ];
        let t = ExtendedInstruction::<Bn254Fr>::TemplateBody {
            id: TemplateId(7),
            frame_size: 16,
            n_params: 2,
            captures: vec![ssa(50), ssa(51)],
            body,
        };
        assert!(!t.is_plain());
        assert!(t.as_plain().is_none());
    }

    #[test]
    fn template_call_captures_and_outputs() {
        let call = ExtendedInstruction::<Bn254Fr>::TemplateCall {
            template_id: TemplateId(7),
            captures: vec![ssa(1), ssa(2)],
            outputs: vec![ssa(10), ssa(11)],
        };
        match call {
            ExtendedInstruction::TemplateCall {
                template_id,
                captures,
                outputs,
            } => {
                assert_eq!(template_id, TemplateId(7));
                assert_eq!(captures.len(), 2);
                assert_eq!(outputs.len(), 2);
            }
            _ => panic!("expected TemplateCall"),
        }
    }

    #[test]
    fn loop_unroll_nests_body() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::Plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: Visibility::Witness,
            })];
        let loop_node = ExtendedInstruction::<Bn254Fr>::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 4,
            body,
        };
        assert!(!loop_node.is_plain());
    }

    #[test]
    fn template_id_displays_with_t_prefix() {
        assert_eq!(format!("{}", TemplateId(42)), "T42");
    }

    #[test]
    fn symbolic_indexed_effect_let_carries_resolved_array_slots() {
        let effect = ExtendedInstruction::<Bn254Fr>::SymbolicIndexedEffect {
            kind: IndexedEffectKind::Let,
            array_slots: vec![ssa(10), ssa(11), ssa(12), ssa(13)],
            index_var: ssa(20),
            value_var: Some(ssa(30)),
            span: None,
        };
        assert!(!effect.is_plain());
        assert!(effect.as_plain().is_none());
        match effect {
            ExtendedInstruction::SymbolicIndexedEffect {
                kind,
                array_slots,
                index_var,
                value_var,
                ..
            } => {
                assert_eq!(kind, IndexedEffectKind::Let);
                assert_eq!(array_slots.len(), 4);
                assert_eq!(index_var, ssa(20));
                assert_eq!(value_var, Some(ssa(30)));
            }
            _ => panic!("expected SymbolicIndexedEffect"),
        }
    }

    #[test]
    fn symbolic_indexed_effect_witness_hint_omits_value() {
        let effect = ExtendedInstruction::<Bn254Fr>::SymbolicIndexedEffect {
            kind: IndexedEffectKind::WitnessHint,
            array_slots: vec![ssa(0), ssa(1)],
            index_var: ssa(5),
            value_var: None,
            span: None,
        };
        match effect {
            ExtendedInstruction::SymbolicIndexedEffect {
                kind, value_var, ..
            } => {
                assert_eq!(kind, IndexedEffectKind::WitnessHint);
                assert!(value_var.is_none());
            }
            _ => panic!("expected SymbolicIndexedEffect"),
        }
    }

    #[test]
    fn symbolic_array_read_carries_result_and_slots() {
        let read = ExtendedInstruction::<Bn254Fr>::SymbolicArrayRead {
            result_var: ssa(40),
            array_slots: vec![ssa(10), ssa(11), ssa(12), ssa(13)],
            index_var: ssa(20),
            span: None,
        };
        assert!(!read.is_plain());
        assert!(read.as_plain().is_none());
        match read {
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                ..
            } => {
                assert_eq!(result_var, ssa(40));
                assert_eq!(array_slots.len(), 4);
                assert_eq!(index_var, ssa(20));
            }
            _ => panic!("expected SymbolicArrayRead"),
        }
    }

    #[test]
    fn symbolic_array_read_distinct_from_indexed_effect() {
        let read = ExtendedInstruction::<Bn254Fr>::SymbolicArrayRead {
            result_var: ssa(0),
            array_slots: vec![ssa(1)],
            index_var: ssa(2),
            span: None,
        };
        let write = ExtendedInstruction::<Bn254Fr>::SymbolicIndexedEffect {
            kind: IndexedEffectKind::Let,
            array_slots: vec![ssa(1)],
            index_var: ssa(2),
            value_var: Some(ssa(3)),
            span: None,
        };
        // Sanity: the two variants don't accidentally pattern-match the
        // same tag, so downstream exhaustive matches stay exhaustive.
        assert!(matches!(
            read,
            ExtendedInstruction::SymbolicArrayRead { .. }
        ));
        assert!(matches!(
            write,
            ExtendedInstruction::SymbolicIndexedEffect { .. }
        ));
    }

    #[test]
    fn symbolic_shift_carries_operand_amount_and_width() {
        let shift = ExtendedInstruction::<Bn254Fr>::SymbolicShift {
            result_var: ssa(50),
            operand_var: ssa(10),
            shift_var: ssa(20),
            num_bits: 32,
            direction: ShiftDirection::Right,
            span: None,
        };
        assert!(!shift.is_plain());
        assert!(shift.as_plain().is_none());
        match shift {
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                num_bits,
                direction,
                ..
            } => {
                assert_eq!(result_var, ssa(50));
                assert_eq!(operand_var, ssa(10));
                assert_eq!(shift_var, ssa(20));
                assert_eq!(num_bits, 32);
                assert_eq!(direction, ShiftDirection::Right);
            }
            _ => panic!("expected SymbolicShift"),
        }
    }

    #[test]
    fn symbolic_shift_left_distinct_from_right() {
        let l = ExtendedInstruction::<Bn254Fr>::SymbolicShift {
            result_var: ssa(0),
            operand_var: ssa(1),
            shift_var: ssa(2),
            num_bits: 8,
            direction: ShiftDirection::Left,
            span: None,
        };
        let r = ExtendedInstruction::<Bn254Fr>::SymbolicShift {
            result_var: ssa(0),
            operand_var: ssa(1),
            shift_var: ssa(2),
            num_bits: 8,
            direction: ShiftDirection::Right,
            span: None,
        };
        // Discriminator differs even with otherwise-identical fields.
        match (&l, &r) {
            (
                ExtendedInstruction::SymbolicShift { direction: dl, .. },
                ExtendedInstruction::SymbolicShift { direction: dr, .. },
            ) => assert_ne!(dl, dr),
            _ => panic!("expected two SymbolicShift"),
        }
    }

    #[test]
    fn indexed_effect_kind_distinguishes_let_from_witness_hint() {
        // Sanity check: the discriminator stays a small Copy enum so
        // it can be embedded in match arms without lifetime gymnastics.
        let a = IndexedEffectKind::Let;
        let b = IndexedEffectKind::WitnessHint;
        assert_ne!(a, b);
        let c = a; // Copy
        assert_eq!(a, c);
    }

    #[test]
    fn from_instruction_wraps_as_plain() {
        let inst = Instruction::<Bn254Fr>::Const {
            result: ssa(0),
            value: fe(5),
        };
        let ext: ExtendedInstruction<Bn254Fr> = inst.into();
        assert!(ext.is_plain());
    }

    #[test]
    fn vec_map_into_works() {
        // The migration pattern: push `inst.into()` or run
        // `instrs.into_iter().map(Into::into)` on an existing Vec.
        let input: Vec<Instruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(0),
                value: fe(1),
            },
            Instruction::Add {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(0),
            },
        ];
        let output: Vec<ExtendedInstruction<Bn254Fr>> = input.into_iter().map(Into::into).collect();
        assert_eq!(output.len(), 2);
        assert!(output.iter().all(|e| e.is_plain()));
    }

    #[test]
    fn into_plain_round_trips_when_plain() {
        let inst = Instruction::<Bn254Fr>::Mul {
            result: ssa(3),
            lhs: ssa(1),
            rhs: ssa(2),
        };
        let ext: ExtendedInstruction<Bn254Fr> = inst.clone().into();
        let back = ext.into_plain().expect("plain variant");
        match back {
            Instruction::Mul { result, lhs, rhs } => {
                assert_eq!(result, ssa(3));
                assert_eq!(lhs, ssa(1));
                assert_eq!(rhs, ssa(2));
            }
            _ => panic!("expected Mul"),
        }
    }

    #[test]
    fn into_plain_returns_err_for_non_plain() {
        let call = ExtendedInstruction::<Bn254Fr>::TemplateCall {
            template_id: TemplateId(0),
            captures: vec![],
            outputs: vec![],
        };
        let err = call.into_plain().expect_err("non-plain variant");
        assert!(matches!(err, ExtendedInstruction::TemplateCall { .. }));
    }
}
