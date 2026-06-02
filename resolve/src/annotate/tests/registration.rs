use super::*;

#[test]
fn single_module_registers_fn_and_let() {
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn add(a, b) { a + b }\n\
         export let PI = 3\n\
         fn mul(a, b) { a * b }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    register_all(&mut table, &graph).expect("register");

    // Root module → unqualified keys.
    let add_id = table.lookup("add").expect("add registered");
    let mul_id = table.lookup("mul").expect("mul registered");
    let pi_id = table.lookup("PI").expect("PI registered");

    match table.get(add_id) {
        CallableKind::UserFn {
            module, stmt_index, ..
        } => {
            assert_eq!(*module, graph.root());
            assert_eq!(*stmt_index, 0);
        }
        other => panic!("expected UserFn, got {other:?}"),
    }
    match table.get(mul_id) {
        CallableKind::UserFn { stmt_index, .. } => assert_eq!(*stmt_index, 2),
        other => panic!("expected UserFn, got {other:?}"),
    }
    assert!(matches!(
        table.get(pi_id),
        CallableKind::Constant {
            const_kind: ConstKind::Field,
            ..
        }
    ));
}

#[test]
fn private_let_is_not_registered() {
    let mut src = MockSource::default();
    src.add("main", "let private_const = 42\nfn f() { private_const }");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    register_all(&mut table, &graph).expect("register");

    assert!(table.lookup("private_const").is_none());
    assert!(table.lookup("f").is_some());
}

#[test]
fn private_fn_is_registered_same_as_exported() {
    // Private fns still get SymbolTable entries — the resolver
    // needs them to resolve intra-module references. Only
    // non-exported *lets* are skipped.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn helper() { 1 }\n\
         export fn public_api() { helper() }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    register_all(&mut table, &graph).expect("register");

    assert!(table.lookup("helper").is_some());
    assert!(table.lookup("public_api").is_some());
}

#[test]
fn non_root_module_uses_mod_n_prefix() {
    let mut src = MockSource::default();
    src.add("lib", "export fn add(a, b) { a + b }");
    src.add("main", "import \"lib\" as l\nlet x = l::add(1, 2)");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    register_all(&mut table, &graph).expect("register");

    // `lib` was loaded first (reverse topo), so it got ModuleId(0).
    // `main` is the root, so its fns/lets use bare keys. `lib`'s
    // `add` lives under `mod0::add`.
    assert_eq!(graph.root().as_u32(), 1);
    assert!(table.lookup("mod0::add").is_some());
    assert!(table.lookup("add").is_none(), "lib::add should not be bare");
}

#[test]
fn topo_order_registers_dependencies_before_dependents() {
    let mut src = MockSource::default();
    src.add("c", "export fn deep() { 1 }");
    src.add("b", "import \"c\" as c\nexport fn middle() { c::deep() }");
    src.add("a", "import \"b\" as b\nlet top = b::middle()");
    let graph = ModuleGraph::build("a", &mut src).expect("build");
    let mut table = SymbolTable::new();
    register_all(&mut table, &graph).expect("register");

    // c=mod0, b=mod1, a=root. We confirm each module's unique
    // symbol is present.
    assert!(table.lookup("mod0::deep").is_some());
    assert!(table.lookup("mod1::middle").is_some());
    // `top` is a private let in the root module — not registered.
    assert!(table.lookup("top").is_none());
}

#[test]
fn duplicate_top_level_fn_errors() {
    let mut src = MockSource::default();
    src.add("main", "fn dup() { 1 }\nfn dup() { 2 }");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    let err = register_all(&mut table, &graph).unwrap_err();
    match err {
        ResolveError::DuplicateModuleSymbol { name, module } => {
            assert_eq!(name, "dup");
            assert_eq!(module, graph.root().as_u32());
        }
        other => panic!("expected DuplicateModuleSymbol, got {other:?}"),
    }
}

#[test]
fn duplicate_fn_vs_let_errors() {
    let mut src = MockSource::default();
    src.add("main", "fn dup() { 1 }\nexport let dup = 42");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    let err = register_all(&mut table, &graph).unwrap_err();
    assert!(matches!(err, ResolveError::DuplicateModuleSymbol { .. }));
}

#[test]
fn stmt_index_skips_imports_but_counts_position() {
    // The stmt_index field must point at the actual statement
    // inside the original Program.stmts, not a "just fns" slice.
    // If the walker counted wrong, a consumer that dereferences
    // `module.program.stmts[stmt_index]` would get the wrong node.
    let mut src = MockSource::default();
    src.add("lib", "export fn unused() { 0 }");
    src.add(
        "main",
        "import \"lib\" as l\n\
         let junk = 1\n\
         fn target() { 42 }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let mut table = SymbolTable::new();
    register_all(&mut table, &graph).expect("register");

    let target_id = table.lookup("target").expect("target registered");
    match table.get(target_id) {
        CallableKind::UserFn { stmt_index, .. } => {
            // main.ach has: import=0, let=1, fn=2
            assert_eq!(*stmt_index, 2);
        }
        other => panic!("expected UserFn, got {other:?}"),
    }
}
