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
    /// `ir::prove_ir::instantiate` produces is wrapped here
    /// when the compiler migrates to emit
    /// `ExtendedInstruction<F>` (Phase 3.C.6 in the circom
    /// frontend).
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
