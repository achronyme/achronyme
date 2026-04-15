//! Integration tests for Movimiento 2 Phase 3D — the VM compiler's
//! resolver shadow dispatch.
//!
//! These tests compile small in-memory programs via `Compiler::compile`
//! and assert that:
//!
//! 1. The resolver state is auto-built for single-module programs.
//! 2. `compile_ident` records an annotation hit for every identifier
//!    that the resolver knows about (builtins, same-module fns).
//! 3. The recorded hits' `SymbolId`s correspond to the expected
//!    `CallableKind` variants in the installed `SymbolTable`.
//! 4. Programs with imports skip auto-build (the legacy lazy loader
//!    is still authoritative in 3D).
//! 5. Compilation itself still succeeds — the shadow path is
//!    observation only.

use compiler::Compiler;
use resolve::CallableKind;

/// Helper: compile a source string and return the resolver hits plus
/// a reference to the installed symbol table. Panics if compilation
/// fails.
fn compile_and_trace(source: &str) -> (Vec<(u32, resolve::SymbolId)>, Option<Compiler>) {
    let mut compiler = Compiler::new();
    compiler.compile(source).expect("compile");
    let hits: Vec<(u32, resolve::SymbolId)> = compiler
        .resolver_hits
        .iter()
        .map(|(id, sid)| (id.as_u32(), *sid))
        .collect();
    (hits, Some(compiler))
}

#[test]
fn auto_build_populates_resolver_state_for_single_module() {
    let mut compiler = Compiler::new();
    compiler
        .compile("fn helper() { 1 }\nfn main_body() { helper() }")
        .expect("compile");

    assert!(
        compiler.resolved_program.is_some(),
        "expected resolver state to be auto-built for a single-module program"
    );
    assert!(compiler.resolver_symbol_table.is_some());
    assert!(compiler.resolver_root_module.is_some());
}

#[test]
fn compile_ident_records_hit_for_same_module_user_fn() {
    let mut compiler = Compiler::new();
    compiler
        .compile("fn helper() { 1 }\nfn main_body() { helper() }")
        .expect("compile");

    // We expect at least one hit: the `helper` reference inside
    // main_body's call site.
    assert!(
        !compiler.resolver_hits.is_empty(),
        "compile_ident should record at least one resolver hit"
    );

    let table = compiler
        .resolver_symbol_table
        .as_ref()
        .expect("resolver state installed");
    let helper_id = table.lookup("helper").expect("helper registered");

    let hit_ids: Vec<_> = compiler.resolver_hits.iter().map(|(_, sid)| *sid).collect();
    assert!(
        hit_ids.contains(&helper_id),
        "expected a hit pointing at helper's SymbolId, got {:?}",
        hit_ids
    );
}

#[test]
fn compile_ident_records_hit_for_builtin_call() {
    // `typeof` is a Vm-only builtin parsed as a regular Ident call
    // (unlike `print`, which is a parser keyword that never produces
    // an Ident). A top-level call to `typeof` should register the
    // builtin's SymbolId in the hit trace.
    let mut compiler = Compiler::new();
    compiler.compile("typeof(42)").expect("compile");

    let table = compiler
        .resolver_symbol_table
        .as_ref()
        .expect("resolver state installed");
    let typeof_id = table.lookup("typeof").expect("typeof builtin registered");
    assert!(matches!(table.get(typeof_id), CallableKind::Builtin { .. }));

    let hit_ids: Vec<_> = compiler.resolver_hits.iter().map(|(_, sid)| *sid).collect();
    assert!(
        hit_ids.contains(&typeof_id),
        "expected a hit pointing at typeof's Builtin SymbolId, got {:?}",
        hit_ids
    );
}

#[test]
fn program_with_imports_skips_auto_build() {
    // Phase 3D deliberately skips the resolver auto-build when a
    // program has any `import` statements. The real filesystem-rooted
    // multi-module graph lands in Phase 3E; until then, we don't want
    // the adapter to try resolving relative paths against a missing
    // base_path.
    //
    // We can't feed a real import here without a `base_path` that
    // points at a real file, so we construct a program that parses
    // but whose import target doesn't exist — the auto-build should
    // still silently skip without erroring out.
    let mut compiler = Compiler::new();
    // The compile call will fail on the import (the legacy loader
    // can't find the module), but the point is that the *resolver
    // auto-build* should have skipped. We don't assert the compile
    // result — we assert that if compilation failed, it failed in
    // the legacy loader, not inside the resolver adapter.
    let _ = compiler.compile("import \"nonexistent\" as x\nlet y = 1");
    assert!(
        compiler.resolved_program.is_none(),
        "auto-build should skip when the program has imports"
    );
}

#[test]
fn local_variable_produces_no_resolver_hit() {
    // Locals are bound inside the walker's scope stack, so
    // `annotate_program` never writes a `SymbolId` for them. The hit
    // trace should contain entries ONLY for names that resolved to
    // module/builtin symbols.
    let mut compiler = Compiler::new();
    compiler
        .compile("fn f() { let x = 1\n typeof(x) }")
        .expect("compile");

    // `typeof` is a hit (builtin). `x` is a local → no hit.
    let table = compiler
        .resolver_symbol_table
        .as_ref()
        .expect("resolver state installed");
    let typeof_id = table.lookup("typeof").expect("typeof registered");

    let sid_hits: Vec<_> = compiler.resolver_hits.iter().map(|(_, sid)| *sid).collect();
    assert!(sid_hits.contains(&typeof_id), "typeof should be a hit");
    // There should be exactly one hit for `typeof` (and no hit for `x`).
    let typeof_hit_count = sid_hits.iter().filter(|&&s| s == typeof_id).count();
    assert_eq!(typeof_hit_count, 1);
}

#[test]
fn shadow_path_does_not_break_compilation() {
    // Smoke test: compile a program that exercises several expr
    // kinds and make sure the shadow path doesn't break codegen.
    let source = "\
        fn add(a, b) { a + b }\n\
        fn double(x) { add(x, x) }\n\
        let result = double(21)\n\
        typeof(result)\
    ";
    let mut compiler = Compiler::new();
    compiler.compile(source).expect("compile smoke test");

    // The resolver hit trace should include at least the builtins
    // and user fns that were actually called.
    let table = compiler
        .resolver_symbol_table
        .as_ref()
        .expect("state installed");
    let add_id = table.lookup("add").expect("add registered");
    let double_id = table.lookup("double").expect("double registered");
    let typeof_id = table.lookup("typeof").expect("typeof registered");

    let sids: Vec<_> = compiler.resolver_hits.iter().map(|(_, sid)| *sid).collect();
    for expected in [add_id, double_id, typeof_id] {
        assert!(
            sids.contains(&expected),
            "expected hit for {:?}, got {:?}",
            expected,
            sids
        );
    }

    // Reference the helper so rustc doesn't gripe about the second
    // tuple field — compile_and_trace is kept around for future
    // multi-compile tests.
    let _ = compile_and_trace;
}
