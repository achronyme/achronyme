//! Integration tests for Movimiento 2 Phase 3E.1 — ProveIR compiler
//! shadow dispatch.
//!
//! These tests mirror `compiler/tests/resolver_shadow_dispatch.rs` but
//! target the ProveIR compiler. They verify that:
//!
//! 1. When a prove block receives an [`OuterResolverState`], walking
//!    identifiers and named calls inside the block records shadow
//!    hits in the compiler's hit trace.
//! 2. The recorded hits' [`SymbolId`]s correspond to the same symbols
//!    the legacy `fn_table`/`lower_builtin` dispatch would pick, as
//!    surfaced through the [`SymbolTable`] lookup.
//! 3. Calls to Both-availability builtins (`poseidon`, `assert`) are
//!    recorded.
//! 4. Captured outer-scope locals produce no hits (they aren't in the
//!    symbol table).
//! 5. The shadow path never breaks compilation of a program that
//!    would have compiled without the resolver state.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use std::collections::HashMap;

use achronyme_parser::ast::{Block, Expr, Program, Stmt};
use ir::prove_ir::{OuterResolverState, OuterScope, OuterScopeEntry, ProveIrCompiler};
use memory::Bn254Fr;
use resolve::{
    build_resolver_state, CallableKind, LoadedModule, ModuleId, ModuleSource, ResolverState,
    SymbolId,
};

/// In-memory `ModuleSource` that serves a single pre-parsed program as
/// the root and refuses any transitive load. Mirrors the pattern
/// `compiler::resolver_adapter::CompilerModuleSource::with_root` uses,
/// but trimmed down for integration tests that never touch a real
/// import graph.
struct InMemoryRoot {
    canonical: PathBuf,
    program: Program,
    exported: Vec<String>,
}

impl ModuleSource for InMemoryRoot {
    fn canonicalize(
        &mut self,
        _importer: Option<&Path>,
        _relative: &str,
    ) -> Result<PathBuf, String> {
        Ok(self.canonical.clone())
    }

    fn load(&mut self, canonical: &Path) -> Result<LoadedModule, String> {
        if canonical != self.canonical {
            return Err(format!(
                "InMemoryRoot was asked for `{}`, only serves `{}`",
                canonical.display(),
                self.canonical.display()
            ));
        }
        Ok(LoadedModule {
            program: self.program.clone(),
            exported_names: self.exported.clone(),
        })
    }
}

/// Parse `source`, build a resolver state against the resulting
/// single-module program, and return `(program, state)`.
fn parse_and_resolve(source: &str) -> (Program, ResolverState) {
    let (program, errors) = achronyme_parser::parse_program(source);
    assert!(errors.is_empty(), "unexpected parse errors: {:?}", errors);
    let mut src = InMemoryRoot {
        canonical: PathBuf::from("<prove-ir-resolver-test>"),
        program: program.clone(),
        exported: Vec::new(),
    };
    let state =
        build_resolver_state("<prove-ir-resolver-test>", &mut src).expect("build_resolver_state");
    (program, state)
}

/// Build the Phase 3F fn_table dispatch maps from a `ResolverState`.
///
/// Mirrors the logic in `compiler::build_dispatch_maps` but scoped
/// to the test's single-module case. We duplicate rather than
/// depend on the compiler crate (which would introduce a crate
/// cycle since `compiler` depends on `ir`). The single-module
/// subset is ~8 lines so the cost of duplication is low.
fn build_dispatch_maps_for_test(
    state: &ResolverState,
) -> (HashMap<SymbolId, String>, HashMap<String, ModuleId>) {
    let mut by_symbol: HashMap<SymbolId, String> = HashMap::new();
    let mut by_key: HashMap<String, ModuleId> = HashMap::new();
    let root = state.root();
    for (sid, kind) in state.table.iter() {
        if let CallableKind::UserFn {
            qualified_name,
            module,
            ..
        } = kind
        {
            // Single-module tests: every user fn lives in the root.
            // Phase 3F's non-root alias prefixing isn't exercised
            // here — the cross-module path is covered end-to-end
            // by the `compiler/tests/gap_24_multi_module.rs`
            // integration test.
            if *module != root {
                continue;
            }
            let key = qualified_name.clone();
            by_symbol.insert(sid, key.clone());
            by_key.insert(key, *module);
        }
    }
    (by_symbol, by_key)
}

/// Build an `OuterScope` that forwards `state` as the resolver
/// handoff. Captures `outer_scalars` as scalar captures so bodies
/// that reference outer-scope names parse cleanly. `functions`
/// forwards top-level fn declarations the same way
/// `compile_prove` does in the VM compiler.
fn outer_scope_with_state(
    state: &ResolverState,
    outer_scalars: &[&str],
    functions: Vec<Stmt>,
) -> OuterScope {
    let mut values = std::collections::HashMap::new();
    for &name in outer_scalars {
        values.insert(name.to_string(), OuterScopeEntry::Scalar);
    }
    let (dispatch_by_symbol, module_by_key) = build_dispatch_maps_for_test(state);
    OuterScope {
        values,
        functions,
        circom_imports: std::collections::HashMap::new(),
        resolver_state: Some(OuterResolverState {
            table: Arc::new(state.table.clone()),
            resolved: Arc::new(state.resolved.clone()),
            root_module: state.root(),
            dispatch_key_by_symbol: Arc::new(dispatch_by_symbol),
            module_by_dispatch_key: Arc::new(module_by_key),
        }),
    }
}

/// Extract the body of the first `Expr::Prove` expression statement
/// in `program`. Panics if the program doesn't have one — tests that
/// need this helper always pass a source with a prove block.
fn extract_prove_body(program: &Program) -> Block {
    for stmt in &program.stmts {
        if let Stmt::Expr(Expr::Prove { body, .. }) = stmt {
            return body.clone();
        }
    }
    panic!("no prove block found in program");
}

/// Collect every top-level `fn` declaration so tests can forward
/// them via `OuterScope::functions` the way `compile_prove` does.
fn extract_top_level_fns(program: &Program) -> Vec<Stmt> {
    program
        .stmts
        .iter()
        .filter(|s| matches!(s, Stmt::FnDecl { .. }))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[test]
fn records_hit_for_both_builtin_in_prove_block() {
    // `poseidon` is an `Availability::Both` builtin — the resolver
    // should annotate the call site, and the ProveIR compiler's
    // shadow hook should record a hit pointing at poseidon's
    // SymbolId.
    let source = "\
        let a = 1\n\
        let b = 2\n\
        prove { public x: Field\n poseidon(a, b) }\n\
    ";
    let (program, state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);
    let outer = outer_scope_with_state(&state, &["a", "b"], Vec::new());

    let (_ir, hits) = ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer)
        .expect("compile prove block with poseidon");

    let poseidon_id = state
        .table
        .lookup("poseidon")
        .expect("poseidon registered in table");
    let sids: Vec<SymbolId> = hits.iter().map(|(_, s)| *s).collect();
    assert!(
        sids.contains(&poseidon_id),
        "expected shadow hit for poseidon, got {:?}",
        sids
    );
}

#[test]
fn captured_outer_local_produces_no_hit() {
    // Outer-scope captures (`a`, `b`) are locals from the resolver's
    // perspective — they live in the walker's scope stack and never
    // land in the symbol table. The shadow trace should NOT contain
    // entries for them. Only the `poseidon` builtin call should
    // produce a hit.
    let source = "\
        let a = 3\n\
        let b = 5\n\
        prove { public x: Field\n poseidon(a, b) }\n\
    ";
    let (program, state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);
    let outer = outer_scope_with_state(&state, &["a", "b"], Vec::new());

    let (_ir, hits) =
        ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer).expect("compile");

    let poseidon_id = state.table.lookup("poseidon").expect("poseidon registered");
    let sids: Vec<SymbolId> = hits.iter().map(|(_, s)| *s).collect();
    assert!(sids.contains(&poseidon_id), "poseidon should be a hit");
    let poseidon_hit_count = sids.iter().filter(|&&s| s == poseidon_id).count();
    assert_eq!(
        poseidon_hit_count, 1,
        "expected exactly one hit for poseidon, got {:?}",
        sids
    );
}

#[test]
fn no_resolver_state_records_no_hits() {
    // Without `OuterResolverState`, the shadow hooks are a silent
    // no-op — the compile still succeeds and the hit trace is
    // empty. This is the path every pre-3E.1 caller took and must
    // keep working unchanged.
    let source = "\
        let a = 1\n\
        let b = 2\n\
        prove { public x: Field\n poseidon(a, b) }\n\
    ";
    let (program, _state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);
    let outer = OuterScope {
        values: [
            ("a", OuterScopeEntry::Scalar),
            ("b", OuterScopeEntry::Scalar),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        ..Default::default()
    };

    let (_ir, hits) =
        ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer).expect("compile");
    assert!(
        hits.is_empty(),
        "expected no shadow hits without resolver state, got {:?}",
        hits
    );
}

#[test]
fn shadow_path_does_not_break_compilation() {
    // Smoke test: a program with captures, a builtin call, and an
    // assert should compile cleanly both with and without the
    // resolver state. The shadow path must be observation-only.
    let source = "\
        let a = 7\n\
        let b = 11\n\
        prove { public out: Field\n\
          assert_eq(out, poseidon(a, b))\n\
        }\n\
    ";
    let (program, state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);

    // With resolver state:
    let outer_with = outer_scope_with_state(&state, &["a", "b"], Vec::new());
    let (ir_with, hits) = ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer_with)
        .expect("compile with resolver state");

    // Without resolver state:
    let outer_without = OuterScope {
        values: [
            ("a", OuterScopeEntry::Scalar),
            ("b", OuterScopeEntry::Scalar),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        ..Default::default()
    };
    let (ir_without, _) = ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer_without)
        .expect("compile without resolver state");

    // Both compilations must produce the same public/witness
    // signature — the shadow path does not alter IR generation.
    assert_eq!(ir_with.public_inputs.len(), ir_without.public_inputs.len());
    assert_eq!(
        ir_with.witness_inputs.len(),
        ir_without.witness_inputs.len()
    );
    assert_eq!(ir_with.body.len(), ir_without.body.len());

    // At least one hit was recorded with state installed.
    assert!(
        !hits.is_empty(),
        "expected at least one shadow hit for the builtin calls"
    );

    // Every recorded hit's key uses the root module id — in Phase
    // 3E.1 we don't yet push sub-module ids onto a stack during
    // inlining, so all observed hits should match the root.
    let root = state.root();
    for &((module_id, _expr_id), _sid) in &hits {
        assert_eq!(
            module_id, root,
            "hits should all be rooted at the root module in 3E.1"
        );
    }
}

// ---------------------------------------------------------------------
// Phase 3E.2/3 — real annotation-driven dispatch tests
// ---------------------------------------------------------------------

#[test]
fn user_fn_call_dispatches_via_annotation() {
    // A top-level `helper` fn forwarded through OuterScope::functions
    // and called from inside a prove block. The annotation map has a
    // UserFn entry keyed by the callee Ident's ExprId; Phase 3E.2 is
    // expected to take the annotation path and dispatch into
    // compile_user_fn_call with the symbol's qualified_name. For a
    // single-module program the qualified name IS the bare fn name,
    // so the fn_table lookup inside compile_user_fn_call succeeds.
    let source = "\
        fn helper(x, y) { x + y }\n\
        prove { public out: Field\n\
          assert_eq(out, helper(out, out))\n\
        }\n\
    ";
    let (program, state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);
    let functions = extract_top_level_fns(&program);
    let outer = outer_scope_with_state(&state, &[], functions);

    let (ir, hits) = ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer)
        .expect("compile prove block with user fn call");

    // The prove block should have compiled cleanly with the user
    // fn inlined — verify the body isn't empty.
    assert!(!ir.body.is_empty(), "expected a non-empty ProveIR body");

    // A hit for `helper` should be present, pointing at the user
    // fn's symbol id. Note: `assert_eq` at statement level never
    // flows through `compile_named_call` — it's intercepted by
    // `compile_expr_stmt` to emit a constraint node directly. That
    // interception happens before the annotation dispatch, so no
    // hit is recorded for assert_eq. We assert only on the helper
    // hit here; the assert_eq shortcut is existing, untouched
    // behavior.
    let helper_id = state
        .table
        .lookup("helper")
        .expect("helper registered in table");
    let sids: Vec<SymbolId> = hits.iter().map(|(_, s)| *s).collect();
    assert!(
        sids.contains(&helper_id),
        "expected annotation-driven hit for helper, got {:?}",
        sids
    );
}

#[test]
fn annotation_dispatch_and_legacy_produce_identical_ir() {
    // With and without an installed resolver state, the ProveIR
    // output must be structurally identical for a program the
    // legacy path already handles. This is the observable-parity
    // guarantee of Phase 3E.2 for single-module programs: the
    // annotation-driven dispatch is cosmetic here (it always
    // points at the same user fn / builtin the legacy path would
    // have picked), so IR generation is unchanged.
    let source = "\
        fn helper(x, y) { x + y }\n\
        prove { public out: Field\n\
          assert_eq(out, helper(out, out))\n\
        }\n\
    ";
    let (program, state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);
    let functions = extract_top_level_fns(&program);

    // With resolver state — annotation path.
    let outer_with = outer_scope_with_state(&state, &[], functions.clone());
    let (ir_with, hits_with) = ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer_with)
        .expect("compile with state");

    // Without resolver state — legacy path.
    let outer_without = OuterScope {
        values: std::collections::HashMap::new(),
        functions,
        circom_imports: std::collections::HashMap::new(),
        resolver_state: None,
    };
    let (ir_without, hits_without) =
        ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer_without)
            .expect("compile without state");

    // Both IRs should have identical public/witness signatures
    // and identical body-node counts.
    assert_eq!(
        ir_with.public_inputs.len(),
        ir_without.public_inputs.len(),
        "public input count diverged"
    );
    assert_eq!(
        ir_with.witness_inputs.len(),
        ir_without.witness_inputs.len(),
        "witness input count diverged"
    );
    assert_eq!(
        ir_with.body.len(),
        ir_without.body.len(),
        "body node count diverged"
    );

    // Hit trace parity: with-state must record hits, without-state
    // must record none. This is the observable difference between
    // the two paths.
    assert!(
        !hits_with.is_empty(),
        "expected annotation-path to record hits"
    );
    assert!(
        hits_without.is_empty(),
        "expected legacy-path to record no hits"
    );
}

#[test]
fn module_stack_empty_after_compile() {
    // After compiling a prove block that calls a user fn through
    // the annotation path, the resolver_module_stack must be empty
    // — every push is matched by a pop. We verify indirectly by
    // compiling twice in a row with the same compiler type and
    // observing that the hit trace for the second compile contains
    // the same symbol ids (no leftover state from compile #1 would
    // drift SymbolIds, but a leaked stack entry would pin
    // `current_resolver_module` to the wrong id and change which
    // annotations resolve).
    //
    // The simpler structural assertion — "the stack is empty at
    // end of compile" — isn't directly observable from outside,
    // but a leaked stack would manifest as corrupted hit traces or
    // compile errors, which the other tests in this file would
    // also catch. This test focuses on cross-compile determinism.
    let source = "\
        fn helper(x, y) { x + y }\n\
        prove { public out: Field\n\
          assert_eq(out, helper(out, out))\n\
        }\n\
    ";
    let (program, state) = parse_and_resolve(source);
    let body = extract_prove_body(&program);
    let functions = extract_top_level_fns(&program);

    let outer1 = outer_scope_with_state(&state, &[], functions.clone());
    let (_, hits1) =
        ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer1).expect("compile 1");

    let outer2 = outer_scope_with_state(&state, &[], functions);
    let (_, hits2) =
        ProveIrCompiler::<Bn254Fr>::compile_with_trace(&body, &outer2).expect("compile 2");

    let sids1: Vec<SymbolId> = hits1.iter().map(|(_, s)| *s).collect();
    let sids2: Vec<SymbolId> = hits2.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        sids1, sids2,
        "cross-compile hit traces diverged — stack leak?"
    );
}
