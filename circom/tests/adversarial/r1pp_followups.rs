use super::*;

// ============================================================================
// Placeholder-aware lower_multi_index — cross-mode pin
// ============================================================================
//
// `lower_multi_index` skips its const-fold fast path when the active
// memoization placeholder loop variable appears in any index slot,
// and `is_memoizable` admits bodies with multi-dim shapes like
// `c[i][k]`.
//
// This regression test pins the contract: under both R1PP_ENABLED=0
// and R1PP_ENABLED=1, the Mux3 wrapper must produce IDENTICAL
// constraint counts AND must continue to reject the same forgery
// (`out` flipped while the selector encodes a different index). The
// test is "trivially passing" today — Mux3's MultiMux3(1) instance
// has n=1 < 4 so the iteration-count gate already rejects
// memoization regardless of the multi-dim gate. If a future widening
// expands the population of memoizable bodies, this test becomes the
// regression watchdog proving the placeholder-aware path keeps the
// IR byte-identical.
//
// Counter-factual procedure (manual, off-CI): stage Edit 4 (gate
// removed) WITHOUT Edits 1+2 on a temporary branch and re-run this
// test under R1PP_ENABLED=1. It MUST fail (witness mismatch or
// constraint divergence), proving the placeholder gates were
// load-bearing.

fn compile_mux3_active_selector() -> (R1CSCompiler<Bn254Fr>, Vec<Fe>) {
    compile_valid_witness(
        "test/circomlib/mux3_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 1),
            ("s_1", 1),
            ("s_2", 0),
        ],
        false,
    )
}

#[test]
fn r1pp_followup_a_mux3_constraint_count_byte_identical_across_modes() {
    let (compiler_off, _w_off) = {
        let _g = R1ppEnvGuard::new("0");
        compile_mux3_active_selector()
    };
    let count_off = compiler_off.cs.num_constraints();

    let (compiler_on, _w_on) = {
        let _g = R1ppEnvGuard::new("1");
        compile_mux3_active_selector()
    };
    let count_on = compiler_on.cs.num_constraints();

    assert_eq!(
        count_off, count_on,
        "R1″ Follow-up A regression: Mux3 must produce byte-identical \
         constraint counts under R1PP_ENABLED=0 and R1PP_ENABLED=1. A \
         divergence here means Edits 1+2 (placeholder-aware \
         lower_multi_index) failed to keep memoized lowering equivalent \
         to legacy unrolling. Counter-factual: this test is what fails \
         when Edit 4 ships without Edits 1+2."
    );
}

/// A template-local `var` array whose declared length is a parameter
/// expression (`2*k-1`), read inside a loop whose bound is that same
/// expression. The expression bound routes the loop through the
/// memoized unroll path. Local `var` arrays have no ProveIR array
/// binding (only per-element zero-init `Let`s), so the memoized
/// path's post-substitution fold must collapse the residual
/// `acc[<const>]` to the flat scalar `acc_<i>` exactly as the
/// direct-unroll path does — otherwise the read dangles at
/// instantiate (`… is not an array`). `compile_valid_witness` panics
/// if instantiate fails OR the honest witness does not verify, so
/// this asserts correctness under BOTH modes; the constraint-count
/// equality additionally pins mode equivalence. This is the minimal
/// regression watchdog for the circomlib BigMultNoCarry `out_poly`
/// blocker on the secp256k1 boss-fight path.
fn compile_var_array_expr_bound_loop() -> (R1CSCompiler<Bn254Fr>, Vec<Fe>) {
    compile_valid_witness(
        "test/circomlib/var_array_expr_bound_loop_test.circom",
        &[("a_0", 2), ("a_1", 3), ("a_2", 4)],
        false,
    )
}

#[test]
fn var_array_expr_bound_loop_byte_identical_across_modes() {
    let (compiler_off, _w_off) = {
        let _g = R1ppEnvGuard::new("0");
        compile_var_array_expr_bound_loop()
    };
    let count_off = compiler_off.cs.num_constraints();

    let (compiler_on, _w_on) = {
        let _g = R1ppEnvGuard::new("1");
        compile_var_array_expr_bound_loop()
    };
    let count_on = compiler_on.cs.num_constraints();

    assert_eq!(
        count_off, count_on,
        "expression-bound-loop read of a template-local `var` array \
         must produce identical constraint counts under \
         R1PP_ENABLED=0 (direct unroll) and R1PP_ENABLED=1 (memoized \
         unroll). A divergence — or an instantiate panic under \
         R1PP_ENABLED=1 — means the memoized path failed to collapse \
         the local-var-array residual to its flat scalar slot."
    );
}

/// Dormant until Edit 4 widens memoization to multi-dim bodies. With
/// the current iteration-count gate (`< 4`) and the still-active
/// `body_has_multi_dim_index` gate, Mux3's MultiMux3(1) instance never
/// memoizes regardless of `R1PP_ENABLED` value, so this test asserts
/// the same property as `mux3_forge_output_with_active_selector_rejected`
/// for now. It earns its keep AFTER Edit 4: the constraint-count test
/// above pins structural divergence, but a lowering bug that produces
/// the SAME constraint COUNT with WRONG constraint CONTENTS would slip
/// past it. This forgery test catches that residue by exercising the
/// soundness property under R1PP=1 specifically.
#[test]
fn r1pp_followup_a_mux3_forgery_rejected_under_r1pp_on() {
    let (compiler, mut witness) = {
        let _g = R1ppEnvGuard::new("1");
        compile_mux3_active_selector()
    };

    let w_out = wire(&compiler, "out");
    // Honest: index = 1+2+0 = 3 → out = c[3] = 40.
    assert_eq!(witness[w_out.index()], Fe::from_u64(40));

    witness[w_out.index()] = Fe::from_u64(10);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "R1″ Follow-up A regression: forging Mux3's `out` under \
         R1PP_ENABLED=1 must still be rejected. If memoized lowering \
         dropped a constraint OR produced same-count-different-contents \
         IR, this assertion catches the under-constraint silently \
         introduced by the optimisation."
    );
}

// ============================================================================
// EdDSAPoseidon cross-mode pin
// ============================================================================
//
// `is_memoizable` does not carry a `body_reads_capture_array` gate —
// empirical investigation across the full e2e suite showed such a
// gate would fire 5 times and never return `true`, so it would be a
// behavioural no-op (no template memoizes that wouldn't have
// memoized without it).
//
// This regression pin compiles EdDSAPoseidon — the heaviest circuit
// in the corpus, exercising Ark/Mix/PoseidonEx/EscalarMulFix —
// under both R1PP modes and asserts the constraint counts are
// byte-identical. If a future change accidentally re-introduces a
// behaviour-altering gate or breaks the cross-mode equivalence
// contract, this test trips immediately.

fn compile_eddsaposeidon_constraint_count() -> usize {
    use std::collections::HashMap;
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/eddsaposeidon_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon compile failed: {e}"));
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, Fe> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler
        .compile_ir(&program)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon R1CS compile failed: {e}"));
    compiler.cs.num_constraints()
}

#[test]
fn r1pp_followup_b_eddsaposeidon_constraint_count_byte_identical_across_modes() {
    let count_off = {
        let _g = R1ppEnvGuard::new("0");
        compile_eddsaposeidon_constraint_count()
    };

    let count_on = {
        let _g = R1ppEnvGuard::new("1");
        compile_eddsaposeidon_constraint_count()
    };

    assert_eq!(
        count_off, count_on,
        "R1″ Follow-up B regression: EdDSAPoseidon must produce \
         byte-identical R1CS constraint counts under R1PP_ENABLED=0 \
         and R1PP_ENABLED=1. A divergence here means a behaviour-\
         altering gate slipped into is_memoizable since Follow-up B's \
         vestigial-gate cleanup, breaking cross-mode equivalence."
    );
}

/// Components that are declared but never wire-triggered (e.g. a
/// sub-component whose input signal is never assigned) are inlined at
/// the end of statement lowering by draining the `pending` component
/// map. That map is a `HashMap`, whose key iteration order is
/// per-process random; if the drain followed that order, the lowered
/// node sequence — and therefore every downstream IR, bytecode, and
/// constraint the circuit emits — would differ from one process to the
/// next for byte-identical input. The drain sorts the component names
/// so the inline order is stable and reproducible.
///
/// This pin builds twelve such components in a scrambled declaration
/// order, each emitting a uniquely identifiable `===` constraint, and
/// asserts the constraints land in name-sorted order in the lowered
/// body. With twelve components an unsorted (hash-order) drain matches
/// the sorted order with probability 1/12! ≈ 2e-9, so a regression
/// that drops the canonical ordering fails this test in essentially
/// every process — without depending on any specific hash seed.
#[test]
fn unwired_pending_components_inline_in_deterministic_name_order() {
    use ir_forge::types::{CircuitExpr, CircuitNode};

    // Scrambled declaration order: neither sorted nor reverse-sorted,
    // so a stable result can only come from explicit canonicalization.
    let decl = [
        "c05", "c11", "c01", "c08", "c03", "c12", "c07", "c02", "c10", "c04", "c09", "c06",
    ];
    let mut body = String::from("signal output d;");
    for (i, c) in decl.iter().enumerate() {
        // `Mk`'s input `x` is never wired, so each instance falls
        // through to the leftover-pending drain. The unique parameter
        // makes every emitted `===` constraint individually identifiable.
        body.push_str(&format!("component {c} = Mk({});", 700_001 + i));
    }
    body.push_str("d <== 0;");
    let src = format!(
        "template Mk(k) {{ signal input x; x === k; }} \
         template Main() {{ {body} }} \
         component main = Main();"
    );

    let result = circom::compile_to_prove_ir(&src).expect("compile_to_prove_ir failed");

    // Collect, in body order, the instance name of every `cNN.x === k`
    // constraint the drained components emit.
    fn collect(nodes: &[CircuitNode], seq: &mut Vec<String>) {
        for n in nodes {
            match n {
                CircuitNode::AssertEq {
                    lhs: CircuitExpr::Var(v),
                    ..
                } => {
                    if let Some(inst) = v.strip_suffix(".x") {
                        seq.push(inst.to_string());
                    }
                }
                CircuitNode::For { body, .. } => collect(body, seq),
                CircuitNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect(then_body, seq);
                    collect(else_body, seq);
                }
                _ => {}
            }
        }
    }
    let mut seq = Vec::new();
    collect(&result.prove_ir.body, &mut seq);

    assert_eq!(
        seq.len(),
        decl.len(),
        "expected one inlined `===` per pending component; got {seq:?}"
    );

    let mut sorted = seq.clone();
    sorted.sort();
    assert_eq!(
        seq, sorted,
        "leftover-pending components inlined out of name-sorted order \
         ({seq:?}); the drain must canonicalize the HashMap iteration \
         order, or the lowered body — and all downstream IR, bytecode, \
         and constraints — become per-process non-deterministic for \
         identical input"
    );
}
