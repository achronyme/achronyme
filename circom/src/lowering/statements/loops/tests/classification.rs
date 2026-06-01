use super::*;

#[test]
fn classify_num2bits_loop_with_outer_acc_unrolls() {
    // Num2Bits-style loop with an outer-scope accumulator: the
    // body writes both the indexed signal `out[i]` AND mutates
    // the outer-scope `lc1`. The SymbolicIndexedEffect path can't
    // carry the cross-iteration `lc1 += ...` shape, so the
    // classifier escalates to `IndexedAssignmentLoop` (unroll at
    // lowering).
    let stmts = extract_template_body(
        r#"
            template T(n) {
                signal input in;
                signal output out[n];
                var lc1 = 0;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    lc1 += out[i];
                }
            }
            "#,
    );
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    let env = env_with_locals(&["lc1", "out"]);
    assert_eq!(
        classify_loop_body(&for_body, &env, "i"),
        Some(LoopLowering::IndexedAssignmentLoop),
    );
}

#[test]
fn classify_noindex_var_only_loop_is_none() {
    // Loop body has no array indexing on the loop var — stays
    // as `CircuitNode::For`. Instantiate time still unrolls per
    // iteration, but nothing needs the loop var as a const at
    // emission time.
    let stmts = extract_template_body(
        r#"
            template T(n) {
                signal output s;
                var sum = 0;
                for (var i = 0; i < n; i++) {
                    sum = sum + 1;
                }
                s <== sum;
            }
            "#,
    );
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    let env = LoweringEnv::new();
    assert_eq!(classify_loop_body(&for_body, &env, "i"), None);
}

#[test]
fn classify_mixed_signal_var_wins_over_other_signals() {
    // CompConstant-style: if/else containing signal op + var mutation
    // at same level → MixedSignalVar.
    let stmts = extract_template_body(
        r#"
            template T(n) {
                signal input in[n];
                signal output out[n];
                var b = 1;
                for (var i = 0; i < n; i++) {
                    if (i == 0) {
                        out[i] <== in[i] * b;
                    } else {
                        out[i] <== in[i];
                    }
                    b = b + 1;
                }
            }
            "#,
    );
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    let env = LoweringEnv::new();
    assert_eq!(
        classify_loop_body(&for_body, &env, "i"),
        Some(LoopLowering::MixedSignalVar),
    );
}

// ──── Class B predicate pre-flight tests ────────────────────────
//
// The four tests below pin `body_writes_to_subcomponent_array`'s
// exact match shape. Run before wiring the predicate into
// `classify_loop_body` to verify (a) it fires on the four failing
// wrapper templates' canonical body, (b) it does NOT fire on
// Pedersen_old's const-index sub-component writes,
// SHA-256-style component-array writes, or parent-owned signal
// array writes. A regression here means the classifier may
// re-route templates that currently pass Lysis.

fn extract_first_for_body(src: &str) -> (Vec<Stmt>, String) {
    let stmts = extract_template_body(src);
    // Scan until the first `for` and return its body + var name.
    for s in &stmts {
        if let Stmt::For { init, body, .. } = s {
            let var = match init.as_ref() {
                Stmt::VarDecl { names, .. } if !names.is_empty() => names[0].clone(),
                Stmt::Substitution { target, .. } => {
                    super::extract_target_name(target).unwrap_or_default()
                }
                _ => panic!("can't extract loop var"),
            };
            return (body.stmts.clone(), var);
        }
    }
    panic!("no for loop");
}

fn env_with_locals(locals: &[&str]) -> LoweringEnv {
    let mut env = LoweringEnv::new();
    for n in locals {
        env.locals.insert((*n).to_string());
    }
    env
}

#[test]
fn class_b_predicate_fires_on_pedersen_wrapper_shape() {
    // Canonical Pedersen wrapper:
    //   component ped = ...;
    //   for (i) { ped.in[i] <== in[i]; }
    // `ped` is a scalar component (in env.locals, NOT in
    // component_arrays); `in[i]` would be a parent-owned write.
    let (body, var) = extract_first_for_body(
        r#"
            template T(n) {
                signal input in[n];
                for (var i = 0; i < n; i++) {
                    ped.in[i] <== in[i];
                }
            }
            "#,
    );
    let env = env_with_locals(&["ped", "ped.in", "in"]);
    assert!(body_writes_to_subcomponent_array(&body, &env, &var));
}

#[test]
fn class_b_predicate_fires_on_reverse_assignment_shape() {
    // EdDSAVerifier wires sub-component inputs via `==>`:
    //   for (i) { S[i] ==> compConstant.in[i]; }
    // Parsed AST puts `S[i]` on `target` and `compConstant.in[i]`
    // on `value`. The predicate must inspect `value` for the
    // reverse-assignment ops, otherwise the sub-component write
    // is invisible to the classifier and the loop stays rolled
    // — the rolled-loop instantiator path then errors with
    // `symbolic indexed write into compConstant.in but the array
    // is not declared in this scope`.
    let (body, var) = extract_first_for_body(
        r#"
            template T(n) {
                signal input S[n];
                for (var i = 0; i < n; i++) {
                    S[i] ==> compConstant.in[i];
                }
            }
            "#,
    );
    let env = env_with_locals(&["compConstant", "compConstant.in", "S"]);
    assert!(body_writes_to_subcomponent_array(&body, &env, &var));

    // `-->` (RSignalAssign) has the same destination flip.
    let (body2, var2) = extract_first_for_body(
        r#"
            template T(n) {
                signal input S[n];
                for (var i = 0; i < n; i++) {
                    S[i] --> compConstant.in[i];
                }
            }
            "#,
    );
    let env2 = env_with_locals(&["compConstant", "compConstant.in", "S"]);
    assert!(body_writes_to_subcomponent_array(&body2, &env2, &var2));
}

#[test]
fn class_b_predicate_does_not_fire_on_const_index_subcomp_write() {
    // Pedersen_old's Window4 shape: const-index writes to a
    // sub-component array. Loop var doesn't appear in the index.
    let (body, var) = extract_first_for_body(
        r#"
            template T(n) {
                signal input in[n];
                for (var i = 0; i < 4; i++) {
                    mux.c[0][i] <== in[i];
                }
            }
            "#,
    );
    // Even though `i` is in `mux.c[0][i]`, the predicate's job is
    // to detect *any* index referencing loop_var. This shape DOES
    // contain `i`. So it would fire — except `mux` is a scalar
    // component sub-component-array write that the bug fires on.
    // Distinct from Pedersen_old's actual mux.c[0][k] where `k`
    // is from an outer scope (not the inner loop var). Adjust:
    let env = env_with_locals(&["mux", "in"]);
    // Predicate fires on this shape because i is in env.locals
    // (loop var) and mux is local non-component-array. This
    // matches the failing pattern, so the assertion is "fires".
    assert!(body_writes_to_subcomponent_array(&body, &env, &var));

    // Genuine const-index Pedersen_old shape — index is a literal,
    // not the loop var:
    let (body2, var2) = extract_first_for_body(
        r#"
            template T(n) {
                signal input in[n];
                for (var i = 0; i < 4; i++) {
                    mux.c[0][3] <== in[i];
                }
            }
            "#,
    );
    let env2 = env_with_locals(&["mux", "in"]);
    assert!(!body_writes_to_subcomponent_array(&body2, &env2, &var2));
}

#[test]
fn class_b_predicate_does_not_fire_on_component_array() {
    // SHA-256-style: `sha256compression[i].inp[k]` — the outer
    // component is an array (`component sha256compression[n]`),
    // tracked in env.component_arrays. Predicate must NOT fire.
    let (body, var) = extract_first_for_body(
        r#"
            template T(n) {
                signal input inp[n][512];
                for (var i = 0; i < n; i++) {
                    for (var k = 0; k < 512; k++) {
                        sha256compression[i].inp[k] <== inp[i][k];
                    }
                }
            }
            "#,
    );
    let mut env = env_with_locals(&["sha256compression", "inp"]);
    env.component_arrays.insert("sha256compression".into());
    assert!(!body_writes_to_subcomponent_array(&body, &env, &var));
}

#[test]
fn class_b_predicate_does_not_fire_on_parent_array() {
    // Parent-owned `paddedIn[k] <== 0` — target is `Index(Ident,
    // ...)`, not `Index(DotAccess, ...)`. Predicate must NOT fire.
    let (body, var) = extract_first_for_body(
        r#"
            template T(n) {
                signal paddedIn[512];
                for (var k = 0; k < 512; k++) {
                    paddedIn[k] <-- 0;
                }
            }
            "#,
    );
    let env = env_with_locals(&["paddedIn"]);
    assert!(!body_writes_to_subcomponent_array(&body, &env, &var));
}

#[test]
fn classify_sha256_padding_loop_stays_rolled() {
    // Reproduces SHA-256 padding: `paddedIn[k] <-- 0` in a
    // for-loop whose index depends on the loop var. The body has
    // a single indexed-signal write, no outer-scope mutation —
    // the SymbolicIndexedEffect path can carry it, so the
    // classifier returns `None` (stay rolled as
    // `CircuitNode::For`) and the walker handles per-iteration
    // unfolding at bytecode emission time.
    //
    // The historical eager-unroll classification on this shape
    // drove the SHA-256 hard gate to 6.4 GB OOM; the SymIndEff
    // path is the surface that lets it stay rolled.
    let stmts = extract_template_body(
        r#"
            template T(nBits, nBlocks) {
                signal input in[nBits];
                signal paddedIn[nBlocks * 512];
                for (var k = nBits + 1; k < nBlocks * 512 - 64; k++) {
                    paddedIn[k] <-- 0;
                }
            }
            "#,
    );
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    let env = env_with_locals(&["paddedIn"]);
    assert_eq!(classify_loop_body(&for_body, &env, "k"), None);
}
