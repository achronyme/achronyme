//! `canonicalize_ssa` — topological renaming of SsaVars to `0..N`.
//!
//! Two `IrProgram<F>` produced by different paths (legacy `instantiate`
//! vs Lysis lifter) often describe the same circuit but allocate SSA ids
//! in different orders — fresh-var counters are non-deterministic across
//! independent emitters. The oracle's first job is to fold that
//! difference away so downstream comparison can rely on positional
//! identity.
//!
//! Algorithm: walk `instructions` (already in topological / SSA order)
//! and assign each defined SsaVar a fresh id in visitation order. Then
//! rebuild the program with every SsaVar — both definition sites and
//! operand reads — substituted via the renamer. Side-band metadata
//! keyed by SsaVar (`var_names`, `var_types`, `var_spans`) gets its
//! keys remapped; `input_spans` is keyed by name and copies as-is.
//!
//! Properties (validated by tests below):
//!
//! - **Pure**: takes `&IrProgram<F>`, returns a fresh program. Input is
//!   not mutated.
//! - **Idempotent**: `canonicalize(canonicalize(p)) == canonicalize(p)`.
//! - **Permissive on undefined operands**: if an operand SsaVar is not
//!   in the renamer (use-before-def — a malformed program), it is left
//!   unchanged. Detection of malformed IR is the responsibility of the
//!   IR validator, not the oracle.

use std::collections::HashMap;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Canonical form of `p` — every SsaVar renamed to its visitation
/// index in `0..N` (instructions in order, with `Decompose::bit_results`
/// and `WitnessCall::outputs` extras taking subsequent ids before the
/// next instruction's primary).
pub fn canonicalize_ssa<F: FieldBackend>(p: &IrProgram<F>) -> IrProgram<F> {
    let mut renamer: HashMap<SsaVar, SsaVar> = HashMap::with_capacity(p.next_var as usize);
    let mut next: u32 = 0;

    for inst in &p.instructions {
        renamer.insert(inst.result_var(), SsaVar(next));
        next += 1;
        for &extra in inst.extra_result_vars() {
            renamer.insert(extra, SsaVar(next));
            next += 1;
        }
    }

    let mut out = IrProgram::new();
    out.next_var = next;
    out.instructions.reserve(p.instructions.len());

    for inst in &p.instructions {
        let mut new_inst = inst.clone();
        rewrite_all_vars(&mut new_inst, &renamer);
        out.instructions.push(new_inst);
    }

    for (old_var, name) in &p.var_names {
        if let Some(&new_var) = renamer.get(old_var) {
            out.var_names.insert(new_var, name.clone());
        }
    }
    for (old_var, ty) in &p.var_types {
        if let Some(&new_var) = renamer.get(old_var) {
            out.var_types.insert(new_var, *ty);
        }
    }
    for (old_var, span) in &p.var_spans {
        if let Some(&new_var) = renamer.get(old_var) {
            out.var_spans.insert(new_var, span.clone());
        }
    }

    out.input_spans = p.input_spans.clone();

    out
}

/// Rewrite every SsaVar in `inst` — both the def slots (result, extra
/// results) and the operand reads — via `renamer`. Variants without
/// SsaVars (Const value, Input name/visibility) are left intact.
fn rewrite_all_vars<F: FieldBackend>(inst: &mut Instruction<F>, renamer: &HashMap<SsaVar, SsaVar>) {
    let r = |v: &mut SsaVar| {
        if let Some(&new) = renamer.get(v) {
            *v = new;
        }
    };
    match inst {
        Instruction::Const { result, .. } => {
            r(result);
        }
        Instruction::Input { result, .. } => {
            r(result);
        }
        Instruction::Add { result, lhs, rhs }
        | Instruction::Sub { result, lhs, rhs }
        | Instruction::Mul { result, lhs, rhs }
        | Instruction::Div { result, lhs, rhs } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::Neg { result, operand } | Instruction::Not { result, operand } => {
            r(result);
            r(operand);
        }
        Instruction::Assert {
            result, operand, ..
        }
        | Instruction::RangeCheck {
            result, operand, ..
        } => {
            r(result);
            r(operand);
        }
        Instruction::And { result, lhs, rhs }
        | Instruction::Or { result, lhs, rhs }
        | Instruction::IsEq { result, lhs, rhs }
        | Instruction::IsNeq { result, lhs, rhs }
        | Instruction::IsLt { result, lhs, rhs }
        | Instruction::IsLe { result, lhs, rhs } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::IsLtBounded {
            result, lhs, rhs, ..
        }
        | Instruction::IsLeBounded {
            result, lhs, rhs, ..
        }
        | Instruction::IntDiv {
            result, lhs, rhs, ..
        }
        | Instruction::IntMod {
            result, lhs, rhs, ..
        } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::Mux {
            result,
            cond,
            if_true,
            if_false,
        } => {
            r(result);
            r(cond);
            r(if_true);
            r(if_false);
        }
        Instruction::AssertEq {
            result, lhs, rhs, ..
        } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::PoseidonHash {
            result,
            left,
            right,
        } => {
            r(result);
            r(left);
            r(right);
        }
        Instruction::Decompose {
            result,
            operand,
            bit_results,
            ..
        } => {
            r(result);
            r(operand);
            for b in bit_results.iter_mut() {
                r(b);
            }
        }
        Instruction::WitnessCall {
            outputs, inputs, ..
        } => {
            for o in outputs.iter_mut() {
                r(o);
            }
            for i in inputs.iter_mut() {
                r(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IrType, Visibility};
    use diagnostics::SpanRange;
    use memory::{Bn254Fr, FieldElement};

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_u64(n)
    }

    fn span(lo: u32, hi: u32) -> SpanRange {
        SpanRange::new(lo as usize, hi as usize, 1, lo as usize, 1, hi as usize)
    }

    fn assert_canonical_shape<F: FieldBackend>(p: &IrProgram<F>) {
        let mut expected = 0u32;
        for inst in &p.instructions {
            assert_eq!(
                inst.result_var(),
                SsaVar(expected),
                "primary def out of canonical order"
            );
            expected += 1;
            for &extra in inst.extra_result_vars() {
                assert_eq!(extra, SsaVar(expected), "extra def out of canonical order");
                expected += 1;
            }
        }
        assert_eq!(p.next_var, expected, "next_var trails canonical id count");
    }

    #[test]
    fn canonicalize_empty_program() {
        let p: IrProgram<Bn254Fr> = IrProgram::new();
        let q = canonicalize_ssa(&p);
        assert!(q.instructions.is_empty());
        assert_eq!(q.next_var, 0);
        assert!(q.var_names.is_empty());
        assert!(q.var_types.is_empty());
        assert!(q.var_spans.is_empty());
    }

    #[test]
    fn canonicalize_single_const_renames_to_zero() {
        // Use a non-trivial starting var id so we can see the rename happen.
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 7;
        p.instructions.push(Instruction::Const {
            result: SsaVar(7),
            value: fe(42),
        });
        p.next_var = 8;

        let q = canonicalize_ssa(&p);
        assert_eq!(q.next_var, 1);
        assert_eq!(q.instructions.len(), 1);
        match &q.instructions[0] {
            Instruction::Const { result, value } => {
                assert_eq!(*result, SsaVar(0));
                assert_eq!(*value, fe(42));
            }
            _ => panic!("expected Const"),
        }
        assert_canonical_shape(&q);
    }

    #[test]
    fn canonicalize_renames_in_visitation_order() {
        // Three instructions allocated with non-monotonic SsaVar ids.
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 100;
        p.instructions.push(Instruction::Const {
            result: SsaVar(10),
            value: fe(1),
        });
        p.instructions.push(Instruction::Const {
            result: SsaVar(20),
            value: fe(2),
        });
        p.instructions.push(Instruction::Add {
            result: SsaVar(5),
            lhs: SsaVar(10),
            rhs: SsaVar(20),
        });

        let q = canonicalize_ssa(&p);

        assert_eq!(q.next_var, 3);
        assert_canonical_shape(&q);

        match &q.instructions[2] {
            Instruction::Add { result, lhs, rhs } => {
                assert_eq!(*result, SsaVar(2));
                assert_eq!(*lhs, SsaVar(0)); // was SsaVar(10), first def
                assert_eq!(*rhs, SsaVar(1)); // was SsaVar(20), second def
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn canonicalize_is_idempotent() {
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 50;
        p.instructions.push(Instruction::Input {
            result: SsaVar(40),
            name: "x".into(),
            visibility: Visibility::Public,
        });
        p.instructions.push(Instruction::Const {
            result: SsaVar(15),
            value: fe(7),
        });
        p.instructions.push(Instruction::Mul {
            result: SsaVar(30),
            lhs: SsaVar(40),
            rhs: SsaVar(15),
        });
        p.instructions.push(Instruction::AssertEq {
            result: SsaVar(45),
            lhs: SsaVar(30),
            rhs: SsaVar(15),
            message: None,
        });

        let q1 = canonicalize_ssa(&p);
        let q2 = canonicalize_ssa(&q1);

        assert_eq!(q1.next_var, q2.next_var);
        assert_eq!(q1.instructions.len(), q2.instructions.len());
        for (a, b) in q1.instructions.iter().zip(q2.instructions.iter()) {
            assert_eq!(format!("{a}"), format!("{b}"));
        }
    }

    #[test]
    fn canonicalize_decompose_extras_renamed() {
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 100;
        p.instructions.push(Instruction::Input {
            result: SsaVar(50),
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        p.instructions.push(Instruction::Decompose {
            result: SsaVar(60),
            operand: SsaVar(50),
            bit_results: vec![SsaVar(70), SsaVar(71), SsaVar(72), SsaVar(73)],
            num_bits: 4,
        });

        let q = canonicalize_ssa(&p);

        assert_eq!(q.next_var, 6); // Input(0) + Decompose primary(1) + 4 bits(2..=5)
        assert_canonical_shape(&q);

        match &q.instructions[1] {
            Instruction::Decompose {
                result,
                operand,
                bit_results,
                ..
            } => {
                assert_eq!(*result, SsaVar(1));
                assert_eq!(*operand, SsaVar(0));
                assert_eq!(
                    *bit_results,
                    vec![SsaVar(2), SsaVar(3), SsaVar(4), SsaVar(5)]
                );
            }
            _ => panic!("expected Decompose"),
        }
    }

    #[test]
    fn canonicalize_witness_call_outputs_renamed() {
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 100;
        p.instructions.push(Instruction::Input {
            result: SsaVar(80),
            name: "in".into(),
            visibility: Visibility::Witness,
        });
        p.instructions.push(Instruction::WitnessCall {
            outputs: vec![SsaVar(90), SsaVar(91), SsaVar(92)],
            inputs: vec![SsaVar(80)],
            program_bytes: vec![0xAB, 0xCD],
        });

        let q = canonicalize_ssa(&p);

        assert_eq!(q.next_var, 4); // Input(0) + WitnessCall outputs(1,2,3)
        assert_canonical_shape(&q);

        match &q.instructions[1] {
            Instruction::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                assert_eq!(*outputs, vec![SsaVar(1), SsaVar(2), SsaVar(3)]);
                assert_eq!(*inputs, vec![SsaVar(0)]);
                assert_eq!(*program_bytes, vec![0xAB, 0xCD]);
            }
            _ => panic!("expected WitnessCall"),
        }
    }

    #[test]
    fn canonicalize_remaps_var_metadata_keys() {
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 10;
        p.instructions.push(Instruction::Const {
            result: SsaVar(5),
            value: fe(99),
        });
        p.set_name(SsaVar(5), "magic".into());
        p.set_type(SsaVar(5), IrType::Field);
        p.set_span(SsaVar(5), span(0, 5));
        p.input_spans.insert("xinput".into(), span(10, 16));

        let q = canonicalize_ssa(&p);

        assert_eq!(q.get_name(SsaVar(0)), Some("magic"));
        assert_eq!(q.get_type(SsaVar(0)), Some(IrType::Field));
        assert_eq!(q.get_span(SsaVar(0)), Some(&span(0, 5)));
        // Input spans are keyed by name — copied verbatim.
        assert_eq!(q.input_spans.get("xinput"), Some(&span(10, 16)));
        // Old keys must not survive.
        assert!(q.get_name(SsaVar(5)).is_none());
        assert!(q.get_type(SsaVar(5)).is_none());
        assert!(q.get_span(SsaVar(5)).is_none());
    }

    #[test]
    fn canonicalize_collapses_different_numbering_into_same_form() {
        // Two structurally identical programs allocated with different
        // SsaVar id sequences. Canonical form must be identical, modulo
        // the FieldElement value ordering that the IR carries.
        let mut a: IrProgram<Bn254Fr> = IrProgram::new();
        a.next_var = 100;
        a.instructions.push(Instruction::Input {
            result: SsaVar(10),
            name: "x".into(),
            visibility: Visibility::Public,
        });
        a.instructions.push(Instruction::Const {
            result: SsaVar(20),
            value: fe(3),
        });
        a.instructions.push(Instruction::Mul {
            result: SsaVar(30),
            lhs: SsaVar(10),
            rhs: SsaVar(20),
        });

        let mut b: IrProgram<Bn254Fr> = IrProgram::new();
        b.next_var = 7;
        b.instructions.push(Instruction::Input {
            result: SsaVar(0),
            name: "x".into(),
            visibility: Visibility::Public,
        });
        b.instructions.push(Instruction::Const {
            result: SsaVar(1),
            value: fe(3),
        });
        b.instructions.push(Instruction::Mul {
            result: SsaVar(6),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
        });

        let qa = canonicalize_ssa(&a);
        let qb = canonicalize_ssa(&b);

        assert_eq!(qa.next_var, qb.next_var);
        assert_eq!(qa.instructions.len(), qb.instructions.len());
        for (x, y) in qa.instructions.iter().zip(qb.instructions.iter()) {
            assert_eq!(format!("{x}"), format!("{y}"));
        }
    }

    #[test]
    fn canonicalize_does_not_mutate_input() {
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 33;
        p.instructions.push(Instruction::Const {
            result: SsaVar(33),
            value: fe(1),
        });
        let snapshot = format!("{p}");
        let snapshot_next = p.next_var;

        let _q = canonicalize_ssa(&p);

        assert_eq!(format!("{p}"), snapshot);
        assert_eq!(p.next_var, snapshot_next);
    }

    #[test]
    fn canonicalize_leaves_undefined_operands_unchanged() {
        // Malformed program: Add references SsaVar(99) which is not defined.
        // canonicalize should not panic; the undefined operand stays as-is.
        let mut p: IrProgram<Bn254Fr> = IrProgram::new();
        p.next_var = 100;
        p.instructions.push(Instruction::Const {
            result: SsaVar(10),
            value: fe(1),
        });
        p.instructions.push(Instruction::Add {
            result: SsaVar(20),
            lhs: SsaVar(10),
            rhs: SsaVar(99),
        });

        let q = canonicalize_ssa(&p);

        match &q.instructions[1] {
            Instruction::Add { result, lhs, rhs } => {
                assert_eq!(*result, SsaVar(1));
                assert_eq!(*lhs, SsaVar(0));
                assert_eq!(*rhs, SsaVar(99)); // unchanged
            }
            _ => panic!("expected Add"),
        }
    }
}
