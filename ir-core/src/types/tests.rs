use super::*;
use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldElement};

#[test]
fn fresh_var_increments() {
    let mut p: IrProgram = IrProgram::new();
    assert_eq!(p.fresh_var(), SsaVar(0));
    assert_eq!(p.fresh_var(), SsaVar(1));
    assert_eq!(p.fresh_var(), SsaVar(2));
    assert_eq!(p.next_var, 3);
}

#[test]
fn result_var_extracts_correctly() {
    let inst: Instruction = Instruction::Add {
        result: SsaVar(42),
        lhs: SsaVar(0),
        rhs: SsaVar(1),
    };
    assert_eq!(inst.result_var(), SsaVar(42));
}

#[test]
fn push_appends_and_returns_result() {
    let mut p: IrProgram = IrProgram::new();
    let v = p.fresh_var();
    let r = p.push(Instruction::Const {
        result: v,
        value: FieldElement::from_u64(99),
    });
    assert_eq!(r, SsaVar(0));
    assert_eq!(p.instructions.len(), 1);
}

#[test]
fn has_side_effects() {
    let assert_inst: Instruction = Instruction::AssertEq {
        result: SsaVar(0),
        lhs: SsaVar(1),
        rhs: SsaVar(2),
        message: None,
    };
    assert!(assert_inst.has_side_effects());

    let add_inst: Instruction = Instruction::Add {
        result: SsaVar(0),
        lhs: SsaVar(1),
        rhs: SsaVar(2),
    };
    assert!(!add_inst.has_side_effects());
}

#[test]
fn set_get_type_round_trip() {
    let mut p: IrProgram = IrProgram::new();
    let v0 = p.fresh_var();
    let v1 = p.fresh_var();
    assert!(p.get_type(v0).is_none());
    p.set_type(v0, IrType::Field);
    p.set_type(v1, IrType::Bool);
    assert_eq!(p.get_type(v0), Some(IrType::Field));
    assert_eq!(p.get_type(v1), Some(IrType::Bool));
}

#[test]
fn ir_type_display() {
    assert_eq!(format!("{}", IrType::Field), "Field");
    assert_eq!(format!("{}", IrType::Bool), "Bool");
}

#[test]
fn operands_returns_correct_vars() {
    let mux: Instruction = Instruction::Mux {
        result: SsaVar(10),
        cond: SsaVar(1),
        if_true: SsaVar(2),
        if_false: SsaVar(3),
    };
    assert_eq!(mux.operands(), vec![SsaVar(1), SsaVar(2), SsaVar(3)]);

    let c = Instruction::Const {
        result: SsaVar(0),
        value: FieldElement::ZERO,
    };
    assert!(c.operands().is_empty());
}

#[test]
fn ssa_var_display() {
    assert_eq!(format!("{}", SsaVar(0)), "%0");
    assert_eq!(format!("{}", SsaVar(42)), "%42");
}

#[test]
fn visibility_display() {
    assert_eq!(format!("{}", Visibility::Public), "public");
    assert_eq!(format!("{}", Visibility::Witness), "witness");
}

#[test]
fn instruction_display() {
    let inst: Instruction = Instruction::Input {
        result: SsaVar(0),
        name: "x".into(),
        visibility: Visibility::Public,
    };
    assert_eq!(format!("{inst}"), "%0 = Input(\"x\", public)");

    let inst: Instruction = Instruction::Mul {
        result: SsaVar(2),
        lhs: SsaVar(0),
        rhs: SsaVar(1),
    };
    assert_eq!(format!("{inst}"), "%2 = Mul(%0, %1)");

    let inst: Instruction = Instruction::Const {
        result: SsaVar(3),
        value: FieldElement::from_u64(42),
    };
    assert_eq!(format!("{inst}"), "%3 = Const(42)");

    let inst: Instruction = Instruction::RangeCheck {
        result: SsaVar(5),
        operand: SsaVar(4),
        bits: 8,
    };
    assert_eq!(format!("{inst}"), "%5 = RangeCheck(%4, 8)");

    let inst: Instruction = Instruction::Mux {
        result: SsaVar(6),
        cond: SsaVar(0),
        if_true: SsaVar(1),
        if_false: SsaVar(2),
    };
    assert_eq!(format!("{inst}"), "%6 = Mux(%0, %1, %2)");
}

#[test]
fn program_display() {
    let mut p: IrProgram = IrProgram::new();
    let v0 = p.fresh_var();
    p.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    let v1 = p.fresh_var();
    p.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    let v2 = p.fresh_var();
    p.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    p.set_name(v2, "product".into());

    let output = format!("{p}");
    assert!(output.contains("%0 = Input(\"x\", public)"));
    assert!(output.contains("%1 = Input(\"y\", witness)"));
    assert!(output.contains("%2 = Mul(%0, %1)  ; product"));
}

#[test]
fn set_get_span_round_trip() {
    let mut p: IrProgram = IrProgram::new();
    let v0 = p.fresh_var();
    let v1 = p.fresh_var();
    let span = SpanRange::new(10, 20, 3, 5, 3, 15);
    assert!(p.get_span(v0).is_none());
    p.set_span(v0, span.clone());
    assert_eq!(p.get_span(v0), Some(&span));
    assert!(p.get_span(v1).is_none());
}

// `var_spans_survive_dce` moved to `ir/src/passes/dce.rs` — it exercises
// the DCE pass, which lives in `ir` not `ir-core`.

// Pin the enum's in-memory size so layout changes are intentional, not
// accidental. The total scales O(post-O1 instruction count) — at
// ECDSA-scale circuits (~20M instructions) every byte here is hundreds
// of MB. `WitnessCall` is boxed; the in-place size is currently bounded
// by `AssertEq` (`Option<String>` payload) and `Decompose` (a `Vec`
// header plus three ids).
#[test]
fn instruction_size_pinned() {
    assert_eq!(std::mem::size_of::<Instruction<Bn254Fr>>(), 56);
}
