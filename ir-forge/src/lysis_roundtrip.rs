//! Wrap an `IrProgram<F>` as a body of `ExtendedInstruction::Plain`,
//! lower through Walker → Sink → materialize, and return a fresh
//! `IrProgram<F>` with the deduplicated instruction stream.
//!
//! This is the **smoke gate** for the Lysis cable. It proves the
//! `ExtendedInstruction → Lysis → Vec<Instruction>` path works
//! end-to-end on real `IrProgram<F>` shapes.
//!
//! ## Limitations of the round-trip path
//!
//! - **No structural reduction.** Every input `Instruction<F>` is
//!   wrapped as [`ExtendedInstruction::Plain`], so the walker emits a
//!   flat instruction stream — no `LoopUnroll`. The Lysis interner
//!   still hash-conses identical pure ops, but multiplicative loop
//!   amplification (e.g. SHA-256(64)) is unaffected: the HARD GATE
//!   probe in `circom/tests/e2e.rs::sha256_64_r1cs_probe` would hang
//!   under this round-trip path. The `ExtendedSink` integration is
//!   what emits real `LoopUnroll` nodes and unlocks the gate.
//! - **Metadata is dropped.** `var_names`, `var_types`, `var_spans`,
//!   and `input_spans` are not reattached to the materialized
//!   program: SSA renumbering through the interner makes the
//!   `old_var → new_var` mapping ambiguous (the interner emits in
//!   dedup order, not source order). The oracle gate in
//!   `zkc::lysis_oracle` does not consult these fields and R1CS
//!   compilation does not require them, so the smoke test still
//!   discriminates `Equivalent` correctly.
//! - **Walker coverage gaps surface as [`RoundTripError::Walk`].**
//!   `IntDiv`, `IntMod`, and field `Div` are all walker-supported
//!   today via `EmitIntDiv` / `EmitIntMod` / `EmitDiv`. Remaining
//!   gaps are tracked per variant in `walker.rs::lift_*`.
//! - **Walker desugarings break strict oracle equivalence on a
//!   subset of variants.** The Walker rewrites
//!   `Assert(x)` → `AssertEq(x, one)` (with a hoisted `Const(1)`),
//!   `Not(x)` → `Sub(one, x)`, `And` → `Mul`,
//!   `Or` → `Add minus Mul`, `IsNeq` → `Sub(one, IsEq)`,
//!   `IsLe` → `Sub(one, IsLt(swap))`, `IsLtBounded` / `IsLeBounded`
//!   similarly. The rewrites are SEMANTICALLY equivalent at proof
//!   time but produce a DIFFERENT R1CS constraint multiset (the new
//!   `one` wire perturbs the linear-combination shape). The oracle's
//!   step-3 multiset compare is bit-strict, so any fixture whose
//!   legacy `IrProgram` contains those variants is classified
//!   `ConstraintsDiffer` even though both pipelines compute the
//!   same circuit. The cross-validation test
//!   (`zkc/tests/lysis_roundtrip_smoke.rs`) works around this by
//!   building fixtures from the variant subset the Walker
//!   round-trips byte-identical: `Const`, `Input`, `Add`, `Sub`,
//!   `Mul`, `IsEq`, `IsLt`, `Mux`, `AssertEq`, `RangeCheck`,
//!   `Decompose`, `PoseidonHash`.

use ir_core::{Instruction, IrProgram};
use lysis::{execute, expected_family, InterningSink, LysisConfig, LysisError};
use memory::FieldBackend;

use crate::extended::ExtendedInstruction;
use crate::lysis_lift::{WalkError, Walker};
use crate::lysis_materialize::materialize_interning_sink;

/// Errors raised by [`lysis_roundtrip`].
#[derive(Debug)]
pub enum RoundTripError {
    /// The walker rejected the body — typically an unsupported
    /// instruction variant (Div, IntDiv, IntMod, TemplateCall) or a
    /// Lysis-bytecode limit (RangeCheck >255 bits, negative loop
    /// bounds, oversize loop body).
    Walk(WalkError),
    /// The bytecode failed to decode or validate, or the executor
    /// aborted (instruction budget exhausted, field family mismatch,
    /// etc.).
    Lysis(LysisError),
}

impl std::fmt::Display for RoundTripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Walk(e) => write!(f, "lysis_roundtrip: walker error: {e}"),
            Self::Lysis(e) => write!(f, "lysis_roundtrip: lysis runtime error: {e}"),
        }
    }
}

impl std::error::Error for RoundTripError {}

impl From<WalkError> for RoundTripError {
    fn from(e: WalkError) -> Self {
        Self::Walk(e)
    }
}

impl From<LysisError> for RoundTripError {
    fn from(e: LysisError) -> Self {
        Self::Lysis(e)
    }
}

/// Round-trip an `IrProgram<F>` through the Lysis pipeline.
///
/// Steps:
/// 1. Drain the input's `Vec<Instruction<F>>` and wrap each entry as
///    [`ExtendedInstruction::Plain`].
/// 2. Lower through [`Walker::lower`] into a Lysis `Program`.
/// 3. Encode → decode the bytecode (defensive — exercises the wire
///    format on every call so future schema drift trips the smoke
///    test, not a downstream gate).
/// 4. In **debug builds**, run `lysis::bytecode::validate` on the
///    decoded program. The validator enforces RFC §4.5
///    well-formedness, fully backstopped by the executor at runtime;
///    release builds skip it for speed.
/// 5. Execute the bytecode against an [`InterningSink`].
/// 6. Materialize the sink to a flat `Vec<Instruction<F>>`.
/// 7. Reassemble into a fresh [`IrProgram`] with `next_var` set to
///    the SSA watermark (max defined var + 1). Metadata is dropped
///    per the module-level note.
pub fn lysis_roundtrip<F: FieldBackend>(
    program: IrProgram<F>,
) -> Result<IrProgram<F>, RoundTripError> {
    let body: Vec<ExtendedInstruction<F>> = program
        .into_instructions()
        .into_iter()
        .map(ExtendedInstruction::Plain)
        .collect();

    let walker = Walker::<F>::new(expected_family::<F>());
    let bytecode = walker.lower(&body)?;

    // Defensive wire-format round-trip. Validate is debug-only (the
    // executor enforces well-formedness invariants at runtime, so
    // release builds skip the static check — see `lower_extended_through_lysis`
    // doc for the full rationale).
    let bytes = lysis::encode(&bytecode);
    let decoded = lysis::decode::<F>(&bytes)?;
    if cfg!(debug_assertions) {
        lysis::bytecode::validate(&decoded, &LysisConfig::default())?;
    }

    let mut sink = InterningSink::<F>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink)?;
    let instructions = materialize_interning_sink(sink);

    let mut out = IrProgram::<F>::new();
    let next_var = ssa_watermark(&instructions);
    out.set_instructions(instructions);
    out.set_next_var(next_var);
    Ok(out)
}

/// Highest `SsaVar` index defined by any instruction in `insts`,
/// plus 1 — the value `IrProgram::fresh_var()` would return next.
/// Considers both `result_var()` and `extra_result_vars()` (Decompose
/// produces N bit slots beyond its primary result).
fn ssa_watermark<F: FieldBackend>(insts: &[Instruction<F>]) -> u32 {
    let mut max: Option<u32> = None;
    let mut bump = |v: u32| match max {
        Some(m) if v <= m => {}
        _ => max = Some(v),
    };
    for inst in insts {
        bump(inst.result_var().0);
        for extra in inst.extra_result_vars() {
            bump(extra.0);
        }
    }
    max.map(|m| m + 1).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir_core::{IrType, SsaVar, Visibility};
    use memory::{Bn254Fr, FieldElement};

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    /// Build a tiny IrProgram: one Input + two Consts + Add + AssertEq.
    /// Mirrors what `instantiate` would produce for `assert(in == 1 + 2)`.
    fn tiny_program() -> IrProgram<Bn254Fr> {
        let mut p = IrProgram::<Bn254Fr>::new();
        p.push(Instruction::Input {
            result: ssa(0),
            name: "in".into(),
            visibility: Visibility::Witness,
        });
        p.set_type(ssa(0), IrType::Field);
        p.push(Instruction::Const {
            result: ssa(1),
            value: fe(1),
        });
        p.push(Instruction::Const {
            result: ssa(2),
            value: fe(2),
        });
        p.push(Instruction::Add {
            result: ssa(3),
            lhs: ssa(1),
            rhs: ssa(2),
        });
        p.push(Instruction::AssertEq {
            result: ssa(4),
            lhs: ssa(0),
            rhs: ssa(3),
            message: None,
        });
        p.set_next_var(5);
        p
    }

    #[test]
    fn roundtrip_returns_a_valid_program() {
        let original = tiny_program();
        let original_len = original.len();
        let lysis = lysis_roundtrip(original).expect("roundtrip ok");
        // The pure pipeline keeps Input + Const + Const + Add + AssertEq.
        // Const dedup is per-value: 1 ≠ 2 so neither folds.
        assert!(!lysis.is_empty(), "round-trip produced empty program");
        assert!(
            lysis.len() <= original_len,
            "interner should not inflate ({} vs {})",
            lysis.len(),
            original_len
        );
        assert!(
            lysis.next_var() as usize >= lysis.len(),
            "next_var watermark below instruction count"
        );
    }

    #[test]
    fn roundtrip_preserves_assert_eq_count() {
        let original = tiny_program();
        let lysis = lysis_roundtrip(original).expect("roundtrip ok");
        let asserts = lysis
            .iter()
            .filter(|i| matches!(i, Instruction::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 1, "AssertEq is a side-effect, never deduped");
    }

    #[test]
    fn roundtrip_drops_metadata() {
        // Documents Stage-1 limitation W1.2: metadata does NOT
        // survive the round-trip. If a future change starts
        // preserving them, this test will (correctly) need updating.
        let original = tiny_program();
        assert!(original.get_type(ssa(0)).is_some(), "precondition");
        let lysis = lysis_roundtrip(original).expect("roundtrip ok");
        // SSA numbering changes too — assert on absence of *any*
        // type info rather than checking specific vars.
        assert!(
            lysis.var_types.is_empty(),
            "Stage-1 round-trip drops metadata; got {:?}",
            lysis.var_types
        );
        assert!(lysis.var_names.is_empty());
        assert!(lysis.var_spans.is_empty());
        assert!(lysis.input_spans.is_empty());
    }

    #[test]
    fn empty_program_roundtrips_to_empty() {
        let empty = IrProgram::<Bn254Fr>::new();
        let lysis = lysis_roundtrip(empty).expect("roundtrip ok");
        assert!(lysis.is_empty());
        assert_eq!(lysis.next_var(), 0);
    }

    #[test]
    fn ssa_watermark_handles_extra_result_vars() {
        // Decompose's extra result vars sit above its primary
        // result. Confirm the watermark accounts for them.
        let mut p = IrProgram::<Bn254Fr>::new();
        p.push(Instruction::Input {
            result: ssa(0),
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Decompose {
            result: ssa(1),
            operand: ssa(0),
            bit_results: vec![ssa(2), ssa(3), ssa(4), ssa(5)],
            num_bits: 4,
        });
        p.set_next_var(6);
        let watermark = ssa_watermark(p.instructions());
        assert_eq!(watermark, 6, "must include Decompose extra result vars");
    }
}
