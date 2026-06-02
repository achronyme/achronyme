use std::collections::HashMap;

use ir_forge::types::{CircuitBinOp, CircuitExpr, CircuitNode, FieldConst};

use super::fold::fold_expr;
use super::fold_known_array_indices;
use crate::lowering::utils::bigval::BigVal;
use crate::lowering::utils::EvalValue;

fn const_(v: u64) -> CircuitExpr {
    CircuitExpr::Const(FieldConst::from_u64(v))
}

fn scalar(v: u64) -> EvalValue {
    EvalValue::Scalar(BigVal::from_u64(v))
}

fn array_1d(values: &[u64]) -> EvalValue {
    EvalValue::Array(values.iter().map(|&v| scalar(v)).collect())
}

fn kav_with(name: &str, value: EvalValue) -> HashMap<String, EvalValue> {
    let mut m = HashMap::new();
    m.insert(name.to_string(), value);
    m
}

/// Single-dim Ark-shape: `out_i <== in_i + C[Add(LoopVar(0), Const(r))]`.
/// After substitute_loop_var the index becomes
/// `Add(Const(N), Const(r))`. The fold pass must collapse that to
/// `Const(C[N+r])`.
#[test]
fn folds_ark_shape_after_substitute() {
    let kav = kav_with("C", array_1d(&[100, 200, 300, 400, 500]));
    // index = Add(Const(2), Const(1)) — represents loop var i=2
    // already substituted with r=1.
    let mut expr = CircuitExpr::ArrayIndex {
        array: "C".to_string(),
        index: Box::new(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(const_(2)),
            rhs: Box::new(const_(1)),
        }),
    };
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, const_(400)); // C[2+1] = C[3] = 400
}

/// Bare `Const(N)` index also folds. This mirrors the post-fold
/// shape for `C[i]` where the placeholder substituted directly to a
/// `Const` leaf at the outermost position.
#[test]
fn folds_bare_const_index() {
    let kav = kav_with("C", array_1d(&[42, 43, 44]));
    let mut expr = CircuitExpr::ArrayIndex {
        array: "C".to_string(),
        index: Box::new(const_(1)),
    };
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, const_(43));
}

/// Non-`Const` index after substitute leaves the node structurally unchanged.
#[test]
fn passes_through_non_const_index() {
    let kav = kav_with("C", array_1d(&[100, 200, 300]));
    let original = CircuitExpr::ArrayIndex {
        array: "C".to_string(),
        index: Box::new(CircuitExpr::Var("unresolved".to_string())),
    };
    let mut expr = original.clone();
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, original);
}

/// Index with a `LoopVar` leaf inside `BinOp` does not fold.
#[test]
fn passes_through_loopvar_residual() {
    let kav = kav_with("C", array_1d(&[100, 200, 300]));
    let original = CircuitExpr::ArrayIndex {
        array: "C".to_string(),
        index: Box::new(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::LoopVar(0)),
            rhs: Box::new(const_(1)),
        }),
    };
    let mut expr = original.clone();
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, original);
}

/// `ArrayIndex { array }` whose key is absent from `kav` is left untouched.
#[test]
fn passes_through_missing_key() {
    let kav = HashMap::new();
    let original = CircuitExpr::ArrayIndex {
        array: "S".to_string(),
        index: Box::new(const_(0)),
    };
    let mut expr = original.clone();
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, original);
}

/// memoization admit/soundness check: 2-D `EvalValue::Array(EvalValue::
/// Array(_))` with a uniform inner length resolves via row-major
/// flatten. `M[j*inner_len + i]` decomposes to `M[j][i]`.
#[test]
fn folds_uniform_2d_via_row_major_flatten() {
    let inner_a = array_1d(&[1, 2, 3]); // M[0]
    let inner_b = array_1d(&[4, 5, 6]); // M[1]
    let inner_c = array_1d(&[7, 8, 9]); // M[2]
    let m = EvalValue::Array(vec![inner_a, inner_b, inner_c]);
    let kav = kav_with("M", m);
    // M[1][2] linearised with inner_len=3 -> 1*3+2 = 5
    let mut expr = CircuitExpr::ArrayIndex {
        array: "M".to_string(),
        index: Box::new(const_(5)),
    };
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, const_(6)); // M[1][2] = 6
}

#[test]
fn folds_uniform_2d_first_element() {
    let inner_a = array_1d(&[42, 43, 44]);
    let inner_b = array_1d(&[45, 46, 47]);
    let m = EvalValue::Array(vec![inner_a, inner_b]);
    let kav = kav_with("M", m);
    let mut expr = CircuitExpr::ArrayIndex {
        array: "M".to_string(),
        index: Box::new(const_(0)),
    };
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, const_(42));
}

/// Ragged 2-D must not fold.
#[test]
fn passes_through_ragged_2d() {
    let inner_a = array_1d(&[1, 2, 3]); // length 3
    let inner_b = array_1d(&[4, 5]); // length 2 — RAGGED
    let m = EvalValue::Array(vec![inner_a, inner_b]);
    let kav = kav_with("M", m);
    let original = CircuitExpr::ArrayIndex {
        array: "M".to_string(),
        index: Box::new(const_(3)),
    };
    let mut expr = original.clone();
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, original);
}

/// 3-D `EvalValue::Array(Array(Array(_)))` is not handled.
#[test]
fn passes_through_3d_array_value() {
    let leaf_a = array_1d(&[1, 2]);
    let leaf_b = array_1d(&[3, 4]);
    let row = EvalValue::Array(vec![leaf_a, leaf_b]);
    let m = EvalValue::Array(vec![row]);
    let kav = kav_with("M", m);
    let original = CircuitExpr::ArrayIndex {
        array: "M".to_string(),
        index: Box::new(const_(0)),
    };
    let mut expr = original.clone();
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, original);
}

/// Out-of-bounds index is a pass-through.
#[test]
fn passes_through_oob_index() {
    let kav = kav_with("C", array_1d(&[100, 200])); // len 2
    let original = CircuitExpr::ArrayIndex {
        array: "C".to_string(),
        index: Box::new(const_(5)),
    };
    let mut expr = original.clone();
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, original);
}

/// Nested fold: the inner ArrayIndex collapses first, then the outer collapses.
#[test]
fn nested_array_index_folds_bottom_up() {
    let kav = {
        let mut m = HashMap::new();
        m.insert("T".to_string(), array_1d(&[3])); // T[0] = 3
        m.insert("C".to_string(), array_1d(&[10, 20, 30, 40])); // C[3] = 40
        m
    };
    let mut expr = CircuitExpr::ArrayIndex {
        array: "C".to_string(),
        index: Box::new(CircuitExpr::ArrayIndex {
            array: "T".to_string(),
            index: Box::new(const_(0)),
        }),
    };
    fold_expr(&mut expr, &kav, None);
    assert_eq!(expr, const_(40));
}

/// Top-level walker mutates a slice in place.
#[test]
fn slice_walker_folds_let_value_array_index() {
    let kav = kav_with("C", array_1d(&[7, 8, 9, 10, 11, 12]));
    let mut slice = vec![CircuitNode::Let {
        name: "out_2".to_string(),
        value: CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(const_(2)),
                rhs: Box::new(const_(1)),
            }),
        },
        span: None,
    }];
    fold_known_array_indices(&mut slice, &kav, None);
    if let CircuitNode::Let { value, .. } = &slice[0] {
        assert_eq!(*value, const_(10)); // C[2+1] = C[3] = 10
    } else {
        panic!("expected Let after fold");
    }
}

/// Empty `kav` is a no-op.
#[test]
fn empty_kav_is_noop() {
    let kav = HashMap::new();
    let original = vec![CircuitNode::Let {
        name: "x".to_string(),
        value: CircuitExpr::ArrayIndex {
            array: "C".to_string(),
            index: Box::new(const_(0)),
        },
        span: None,
    }];
    let mut slice = original.clone();
    fold_known_array_indices(&mut slice, &kav, None);
    assert_eq!(slice, original);
}

/// Composition contract for R1" Option II.
#[test]
fn substitute_then_fold_matches_hand_unrolled_iter_n() {
    use crate::lowering::loop_var_subst::substitute_loop_var;

    let kav = kav_with("C", array_1d(&[100, 101, 102, 103, 104, 105]));

    let template = vec![CircuitNode::Let {
        name: "out_$LV0$".to_string(),
        value: CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Var("in_$LV0$".to_string())),
            rhs: Box::new(CircuitExpr::ArrayIndex {
                array: "C".to_string(),
                index: Box::new(CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(CircuitExpr::LoopVar(0)),
                    rhs: Box::new(const_(1)),
                }),
            }),
        },
        span: None,
    }];

    let mut composed: Vec<CircuitNode> = Vec::new();
    for n in 0..4u64 {
        let mut iter = template.clone();
        substitute_loop_var(&mut iter, 0, n);
        fold_known_array_indices(&mut iter, &kav, None);
        composed.extend(iter);
    }

    let hand_unrolled: Vec<CircuitNode> = (0..4u64)
        .map(|n| CircuitNode::Let {
            name: format!("out_{n}"),
            value: CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var(format!("in_{n}"))),
                rhs: Box::new(const_(100 + n + 1)),
            },
            span: None,
        })
        .collect();

    assert_eq!(
        composed, hand_unrolled,
        "Option II contract: substitute_loop_var + fold_known_array_indices \
         must produce structurally-identical IR to a hand-unrolled body. \
         Divergence here breaks the byte-identical-constraints invariant \
         that EdDSAPoseidon's cross-mode pin enforces at e2e level."
    );
}
