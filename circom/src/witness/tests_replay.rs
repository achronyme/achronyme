//! Differential tests: the slot-addressed template replay must produce
//! a map EQUAL to the reference interpreter's on every walk edge case —
//! nested components, indexed namespace collisions, unevaluable skips,
//! both-branch `If`, rolled `For` ranges in all four shapes, Artik
//! witness calls, and assert failures.

use std::collections::HashMap;

use ir_forge::types::{CircuitBinOp, CircuitExpr, CircuitNode, FieldConst, ForRange, ProveIR};
use memory::{Bn254Fr, FieldElement};

use super::compute::{compute_witness_hints_reference, compute_witness_hints_with_captures};

type Fe = FieldElement<Bn254Fr>;

fn fe(v: u64) -> Fe {
    Fe::from_u64(v)
}

fn prove_ir(body: Vec<CircuitNode>, bodies: &[(&str, Vec<CircuitNode>)]) -> ProveIR {
    ProveIR {
        name: None,
        public_inputs: Vec::new(),
        witness_inputs: Vec::new(),
        captures: Vec::new(),
        body,
        capture_arrays: Vec::new(),
        component_bodies: bodies
            .iter()
            .map(|(k, b)| (k.to_string(), b.clone()))
            .collect(),
    }
}

fn var(name: &str) -> CircuitExpr {
    CircuitExpr::Var(name.to_string())
}

fn cap(name: &str) -> CircuitExpr {
    CircuitExpr::Capture(name.to_string())
}

fn konst(v: u64) -> CircuitExpr {
    CircuitExpr::Const(FieldConst::from_u64(v))
}

fn add(lhs: CircuitExpr, rhs: CircuitExpr) -> CircuitExpr {
    CircuitExpr::BinOp {
        op: CircuitBinOp::Add,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
    }
}

fn let_(name: &str, value: CircuitExpr) -> CircuitNode {
    CircuitNode::Let {
        name: name.to_string(),
        value,
        span: None,
    }
}

fn hint(name: &str, value: CircuitExpr) -> CircuitNode {
    CircuitNode::WitnessHint {
        name: name.to_string(),
        hint: value,
        span: None,
    }
}

fn call(body_key: &str, comp_name: &str, subs: Vec<(&str, CircuitExpr)>) -> CircuitNode {
    CircuitNode::ComponentCall {
        body_key: body_key.to_string(),
        comp_name: comp_name.to_string(),
        param_subs: subs.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        span: None,
    }
}

/// Both paths over the same ProveIR + inputs + captures, asserted equal;
/// returns the map for additional shape assertions.
fn assert_paths_equal(
    ir: &ProveIR,
    inputs: &HashMap<String, Fe>,
    captures: &HashMap<String, u64>,
) -> HashMap<String, Fe> {
    let replayed = compute_witness_hints_with_captures(ir, inputs, captures).expect("replay path");
    let reference = compute_witness_hints_reference(ir, inputs, captures).expect("reference path");
    assert_eq!(replayed, reference, "replay env != reference env");
    replayed
}

#[test]
fn nested_components_match_reference() {
    let inner = vec![
        let_("x", add(cap("p"), cap("p"))),
        call("leaf", "c2", vec![("q", cap("p"))]),
        let_("w", add(var("c2.y"), konst(10))),
    ];
    let leaf = vec![let_("y", add(cap("q"), konst(1)))];
    let top = vec![
        let_("a", konst(5)),
        call("inner", "c1", vec![("p", add(var("a"), konst(1)))]),
        let_("z", add(var("c1.x"), konst(1))),
    ];
    let ir = prove_ir(top, &[("inner", inner), ("leaf", leaf)]);
    let env = assert_paths_equal(&ir, &HashMap::new(), &HashMap::new());

    assert_eq!(env.get("a"), Some(&fe(5)));
    assert_eq!(env.get("c1.x"), Some(&fe(12)));
    assert_eq!(env.get("c1.c2.y"), Some(&fe(7)));
    assert_eq!(env.get("c1.w"), Some(&fe(17)));
    assert_eq!(env.get("z"), Some(&fe(13)));
}

#[test]
fn indexed_namespace_and_collisions_match() {
    let top = vec![
        // Scalar named `out_1`, then array write out[1]: same flat key.
        let_("out_1", konst(5)),
        CircuitNode::LetIndexed {
            array: "out".to_string(),
            index: konst(1),
            value: konst(9),
            span: None,
        },
        CircuitNode::WitnessHintIndexed {
            array: "w".to_string(),
            index: konst(0),
            hint: konst(3),
            span: None,
        },
        CircuitNode::LetArray {
            name: "arr".to_string(),
            elements: vec![konst(11), var("missing"), konst(13)],
            span: None,
        },
        // ArrayIndex read of arr[2] -> arr_2.
        let_(
            "r",
            CircuitExpr::ArrayIndex {
                array: "arr".to_string(),
                index: Box::new(konst(2)),
            },
        ),
        // Read of an absent element: skipped, leaves no trace.
        let_(
            "r2",
            CircuitExpr::ArrayIndex {
                array: "arr".to_string(),
                index: Box::new(konst(1)),
            },
        ),
    ];
    let ir = prove_ir(top, &[]);
    let env = assert_paths_equal(&ir, &HashMap::new(), &HashMap::new());

    assert_eq!(env.get("out_1"), Some(&fe(9)), "collision: last write wins");
    assert_eq!(env.get("w_0"), Some(&fe(3)));
    assert_eq!(env.get("arr_0"), Some(&fe(11)));
    assert_eq!(env.get("arr_1"), None, "unevaluable element skipped");
    assert_eq!(env.get("r"), Some(&fe(13)));
    assert_eq!(env.get("r2"), None);
}

#[test]
fn if_with_unknown_cond_walks_both_branches() {
    let top = vec![
        CircuitNode::If {
            cond: var("missing"),
            then_body: vec![let_("t", konst(1))],
            else_body: vec![let_("e", konst(2))],
            span: None,
        },
        CircuitNode::If {
            cond: konst(0),
            then_body: vec![let_("t2", konst(1))],
            else_body: vec![let_("e2", konst(2))],
            span: None,
        },
    ];
    let ir = prove_ir(top, &[]);
    let env = assert_paths_equal(&ir, &HashMap::new(), &HashMap::new());

    assert_eq!(env.get("t"), Some(&fe(1)), "unknown cond: both branches");
    assert_eq!(env.get("e"), Some(&fe(2)), "unknown cond: both branches");
    assert_eq!(env.get("t2"), None, "zero cond: else only");
    assert_eq!(env.get("e2"), Some(&fe(2)));
}

#[test]
fn for_ranges_match_in_all_shapes() {
    let big = FieldConst::from_decimal_str("340282366920938463463374607431768211456")
        .expect("2^128 parses"); // does not fit u64
    let inner = vec![
        // Folded: n substituted with Const(2).
        CircuitNode::For {
            var: "i".to_string(),
            range: ForRange::WithCapture {
                start: 0,
                end_capture: "n".to_string(),
            },
            body: vec![CircuitNode::LetIndexed {
                array: "a".to_string(),
                index: var("i"),
                value: add(var("i"), konst(100)),
                span: None,
            }],
            span: None,
        },
        // Non-u64 const sub: stays a capture lookup, misses, body runs
        // once without the loop var.
        CircuitNode::For {
            var: "j".to_string(),
            range: ForRange::WithCapture {
                start: 0,
                end_capture: "m".to_string(),
            },
            body: vec![let_("once", konst(7))],
            span: None,
        },
        // Computed bound over a substituted expression: k+1.
        CircuitNode::For {
            var: "t".to_string(),
            range: ForRange::WithExpr {
                start: 0,
                end_expr: Box::new(add(cap("k"), konst(1))),
            },
            body: vec![CircuitNode::LetIndexed {
                array: "b".to_string(),
                index: var("t"),
                value: var("t"),
                span: None,
            }],
            span: None,
        },
    ];
    let top = vec![
        // Top-level capture hit: end bound from the captures map.
        CircuitNode::For {
            var: "i".to_string(),
            range: ForRange::WithCapture {
                start: 0,
                end_capture: "n".to_string(),
            },
            body: vec![CircuitNode::LetIndexed {
                array: "top".to_string(),
                index: var("i"),
                value: var("i"),
                span: None,
            }],
            span: None,
        },
        call(
            "inner",
            "c",
            vec![
                ("n", konst(2)),
                ("m", CircuitExpr::Const(big)),
                ("k", add(konst(1), konst(1))),
            ],
        ),
        // The loop var persists after the loop.
        let_("after", var("i")),
    ];
    let ir = prove_ir(top, &[("inner", inner)]);
    let captures: HashMap<String, u64> = [("n".to_string(), 3u64)].into_iter().collect();
    let env = assert_paths_equal(&ir, &HashMap::new(), &captures);

    assert_eq!(env.get("top_2"), Some(&fe(2)), "top-level capture bound");
    assert_eq!(env.get("after"), Some(&fe(2)), "loop var persists");
    assert_eq!(env.get("c.a_1"), Some(&fe(101)), "folded const bound");
    assert_eq!(env.get("c.a_2"), None);
    assert_eq!(env.get("c.once"), Some(&fe(7)), "non-u64 bound: walk once");
    assert_eq!(env.get("c.j"), None, "walk-once inserts no loop var");
    assert_eq!(env.get("c.b_2"), Some(&fe(2)), "computed bound k+1");
}

#[test]
fn witness_call_matches_and_skip_is_permanent() {
    // Square program: out[0] = in[0]^2 (same shape the memo tests use).
    let body = vec![
        artik::ir::Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        artik::ir::Instr::FMul { dst: 1, a: 0, b: 0 },
        artik::ir::Instr::WriteWitness { slot_id: 0, src: 1 },
        artik::ir::Instr::Return { srcs: Vec::new() },
    ];
    let program = artik::program::Program::new(memory::FieldFamily::BnLike256, 2, Vec::new(), body);
    let bytes = artik::bytecode::encode(&program);

    let top = vec![
        let_("x", konst(6)),
        CircuitNode::WitnessCall {
            output_bindings: vec!["sq".to_string()],
            input_signals: vec![var("x")],
            program_bytes: bytes.clone(),
            span: None,
        },
        // Unresolvable input: the whole call is skipped, permanently.
        CircuitNode::WitnessCall {
            output_bindings: vec!["never".to_string()],
            input_signals: vec![var("missing")],
            program_bytes: bytes,
            span: None,
        },
        hint("y", add(var("sq"), konst(1))),
        hint("gone", var("never")),
    ];
    let ir = prove_ir(top, &[]);
    let env = assert_paths_equal(&ir, &HashMap::new(), &HashMap::new());

    assert_eq!(env.get("sq"), Some(&fe(36)));
    assert_eq!(env.get("y"), Some(&fe(37)));
    assert_eq!(env.get("never"), None, "skipped call binds nothing");
    assert_eq!(env.get("gone"), None);
}

#[test]
fn component_call_inside_rolled_for_reenters_instance() {
    // The same instance prefix is replayed per iteration; its writes
    // overwrite the previous iteration's.
    let inner = vec![let_("x", add(cap("p"), konst(1)))];
    let top = vec![CircuitNode::For {
        var: "i".to_string(),
        range: ForRange::Literal { start: 0, end: 3 },
        body: vec![call("inner", "c", vec![("p", var("i"))])],
        span: None,
    }];
    let ir = prove_ir(top, &[("inner", inner)]);
    let env = assert_paths_equal(&ir, &HashMap::new(), &HashMap::new());

    assert_eq!(env.get("c.x"), Some(&fe(3)), "last iteration wins");
}

#[test]
fn assert_failure_matches_reference() {
    let top = vec![CircuitNode::Assert {
        expr: konst(0),
        message: Some("boom".to_string()),
        span: None,
    }];
    let ir = prove_ir(top, &[]);
    let inputs = HashMap::new();
    let captures = HashMap::new();
    let replay_err = compute_witness_hints_with_captures::<Bn254Fr>(&ir, &inputs, &captures)
        .expect_err("replay must fail");
    let reference_err = compute_witness_hints_reference::<Bn254Fr>(&ir, &inputs, &captures)
        .expect_err("reference must fail");
    assert_eq!(replay_err.message, reference_err.message);
    assert_eq!(replay_err.message, "boom");
}

#[test]
fn seeding_keeps_inputs_authoritative_over_captures() {
    let top = vec![hint("y", add(var("n"), konst(1)))];
    let ir = prove_ir(top, &[]);
    let inputs: HashMap<String, Fe> = [("n".to_string(), fe(10))].into_iter().collect();
    let captures: HashMap<String, u64> = [("n".to_string(), 99u64)].into_iter().collect();
    let env = assert_paths_equal(&ir, &inputs, &captures);

    assert_eq!(env.get("n"), Some(&fe(10)), "input wins over capture");
    assert_eq!(env.get("y"), Some(&fe(11)));
}

#[test]
fn skipped_hint_is_absent_not_zero() {
    let top = vec![
        hint("x", var("missing")),
        hint(
            "p",
            CircuitExpr::PoseidonHash {
                left: Box::new(konst(1)),
                right: Box::new(konst(2)),
            },
        ),
    ];
    let ir = prove_ir(top, &[]);
    let env = assert_paths_equal(&ir, &HashMap::new(), &HashMap::new());
    assert_eq!(env.get("x"), None);
    assert_eq!(env.get("p"), None, "off-circuit construct is unevaluable");
}
