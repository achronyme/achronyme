use super::*;

#[test]
fn annotates_same_module_fn_call() {
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn helper() { 1 }\n\
         fn entry() { helper() }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let helper_id = table.lookup("helper").expect("helper registered");
    let root = graph.get(graph.root());
    let ident_ids = find_idents(&root.program, "helper");
    assert_eq!(
        ident_ids.len(),
        1,
        "expected one `helper` ident in the call site"
    );
    assert_eq!(
        annotations.get(&(graph.root(), ident_ids[0])),
        Some(&helper_id)
    );
}

#[test]
fn local_param_shadows_module_fn() {
    // fn x is a module symbol; calling `x` inside `fn f(x) { x }`
    // references the *parameter*, not the module fn. The walker
    // must NOT annotate the param reference.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn x() { 0 }\n\
         fn f(x) { x }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let root = graph.get(graph.root());
    // There are two Ident "x" nodes: one in the param position
    // (which isn't an Expr) and one in the return expression `x`.
    // `find_idents` only sees Expr::Ident, so exactly one result.
    let ident_ids = find_idents(&root.program, "x");
    assert_eq!(ident_ids.len(), 1, "expected the `x` in the body");
    assert!(
        !annotations.contains_key(&(graph.root(), ident_ids[0])),
        "shadowed param must not be annotated against the module fn"
    );
}

#[test]
fn selective_import_resolves_to_target_module_symbol() {
    let mut src = MockSource::default();
    src.add("lib", "export fn add(a, b) { a + b }");
    src.add(
        "main",
        "import { add } from \"lib\"\nfn call() { add(1, 2) }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let add_id = table.lookup("mod0::add").expect("add registered");
    let root = graph.get(graph.root());
    let ident_ids = find_idents(&root.program, "add");
    assert_eq!(ident_ids.len(), 1);
    assert_eq!(
        annotations.get(&(graph.root(), ident_ids[0])),
        Some(&add_id)
    );
}

#[test]
fn namespace_import_via_static_access() {
    let mut src = MockSource::default();
    src.add("lib", "export fn add(a, b) { a + b }");
    src.add("main", "import \"lib\" as l\nlet x = l::add(1, 2)");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let add_id = table.lookup("mod0::add").expect("add registered");
    let root = graph.get(graph.root());
    let sa_ids = find_static_accesses(&root.program, "l", "add");
    assert_eq!(sa_ids.len(), 1);
    assert_eq!(annotations.get(&(graph.root(), sa_ids[0])), Some(&add_id));
}

#[test]
fn namespace_import_via_dot_access() {
    let mut src = MockSource::default();
    src.add("lib", "export fn add(a, b) { a + b }");
    src.add("main", "import \"lib\" as l\nlet x = l.add(1, 2)");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let add_id = table.lookup("mod0::add").expect("add registered");
    let root = graph.get(graph.root());
    let dot_ids = find_dot_accesses(&root.program, "l", "add");
    assert_eq!(
        dot_ids.len(),
        1,
        "expected one `l.add` DotAccess in the call site"
    );
    assert_eq!(annotations.get(&(graph.root(), dot_ids[0])), Some(&add_id));
}

#[test]
fn builtin_call_is_annotated_after_register_builtins() {
    let mut src = MockSource::default();
    src.add("main", "fn f(a, b) { poseidon(a, b) }");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let poseidon_id = table.lookup("poseidon").expect("builtin registered");
    // Sanity: it's actually a Builtin kind.
    assert!(matches!(
        table.get(poseidon_id),
        CallableKind::Builtin { .. }
    ));

    let root = graph.get(graph.root());
    let ident_ids = find_idents(&root.program, "poseidon");
    assert_eq!(ident_ids.len(), 1);
    assert_eq!(
        annotations.get(&(graph.root(), ident_ids[0])),
        Some(&poseidon_id)
    );
}

#[test]
fn annotates_against_definer_scope_not_caller_scope() {
    // The `c::deep()` call inside b::middle() must resolve to
    // `mod0::deep` (c's fn) at annotation time, because we walk module
    // `b` against `b`'s own imports. When the ProveIR compiler later
    // inlines `middle` into `a.ach`, the annotation is already
    // attached — `a.ach`'s scope never gets a chance to re-resolve
    // `c::deep` against its own (non-existent) `c` import.
    let mut src = MockSource::default();
    src.add("c", "export fn deep() { 1 }");
    src.add("b", "import \"c\" as c\nexport fn middle() { c::deep() }");
    src.add("a", "import \"b\" as b\nlet top = b::middle()");
    let graph = ModuleGraph::build("a", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    // c::deep lives under mod0::deep; b::middle under mod1::middle.
    let deep_id = table.lookup("mod0::deep").expect("deep registered");
    let middle_id = table.lookup("mod1::middle").expect("middle registered");

    // Check the annotation on `c::deep` inside b's program.
    let b_id = ModuleId::from_raw(1);
    let b_module = graph.get(b_id);
    let c_deep_ids = find_static_accesses(&b_module.program, "c", "deep");
    assert_eq!(c_deep_ids.len(), 1);
    assert_eq!(
        annotations.get(&(b_id, c_deep_ids[0])),
        Some(&deep_id),
        "c::deep inside b should resolve to c's fn at parse time"
    );

    // And the annotation on `b::middle` inside a's program.
    let a_module = graph.get(graph.root());
    let b_middle_ids = find_static_accesses(&a_module.program, "b", "middle");
    assert_eq!(b_middle_ids.len(), 1);
    assert_eq!(
        annotations.get(&(graph.root(), b_middle_ids[0])),
        Some(&middle_id)
    );
}

#[test]
fn nested_block_scope_tracks_shadowing() {
    // The inner `g` let shadows the outer `g`. Both references to
    // `g` are locals, so neither should be annotated.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn g() { 0 }\n\
         fn f() { let g = 1\n { let g = 2\n g } }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let root = graph.get(graph.root());
    let ident_ids = find_idents(&root.program, "g");
    // One Ident `g` appears — the trailing reference inside the
    // nested block. The outer/inner `let g = …` LHS isn't an Expr.
    assert_eq!(ident_ids.len(), 1);
    assert!(
        !annotations.contains_key(&(graph.root(), ident_ids[0])),
        "nested let g should shadow the module-level fn g"
    );
}

#[test]
fn exported_constant_is_resolved_inside_same_module() {
    // The register pass installed `PI` as a Constant. Inside the same
    // module, a bare reference to `PI` should annotate against that
    // Constant (not fall through to "local" — top-level lets are not
    // tracked in the scope stack for exactly this reason).
    let mut src = MockSource::default();
    src.add("main", "export let PI = 3\nfn area(r) { PI }");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let annotations = annotate_program(&graph, &table).annotations;

    let pi_id = table.lookup("PI").expect("PI registered");
    let root = graph.get(graph.root());
    let ident_ids = find_idents(&root.program, "PI");
    assert_eq!(ident_ids.len(), 1);
    assert_eq!(annotations.get(&(graph.root(), ident_ids[0])), Some(&pi_id));
}

#[test]
fn register_builtins_populates_bare_names() {
    // Defensive: register_builtins should insert every default
    // builtin under its bare name, and each should resolve via
    // table.lookup.
    let mut table = SymbolTable::with_registry(BuiltinRegistry::default()).expect("registry audit");
    register_builtins(&mut table);
    for name in ["poseidon", "assert_eq", "range_check", "mux", "print"] {
        let id = table
            .lookup(name)
            .unwrap_or_else(|| panic!("{name} missing after register_builtins"));
        assert!(matches!(table.get(id), CallableKind::Builtin { .. }));
    }
}

// Suppress the unused-import warning for TypedParam — imported to
// document the param-walking contract even though tests use string
// inputs that parse into them.
#[allow(dead_code)]
fn _param_doc_marker(_: TypedParam) {}

#[test]
fn fn_alias_local_resolves_to_target() {
    // `let a = helper; a()` — the call-site `a` is annotated
    // directly to helper's SymbolId, so the downstream compilers
    // dispatch through the alias uniformly.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn helper() { 1 }\n\
         fn caller() { let a = helper\n a() }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);
    assert!(
        resolved.diagnostics.is_empty(),
        "no diagnostics expected, got {:?}",
        resolved.diagnostics
    );

    let helper_id = table.lookup("helper").expect("helper registered");
    let root = graph.get(graph.root());
    let a_idents = find_idents(&root.program, "a");
    assert_eq!(
        a_idents.len(),
        1,
        "expected one `a` Ident in the call-site position"
    );
    assert_eq!(
        resolved.annotations.get(&(graph.root(), a_idents[0])),
        Some(&helper_id),
        "FnAlias should flatten to the target symbol"
    );
}

#[test]
fn fn_alias_cross_module_via_static_access() {
    // `let a = l::helper; a()` — the alias resolves against a
    // namespace import, so the call site annotates to the
    // imported module's symbol.
    let mut src = MockSource::default();
    src.add("lib", "export fn helper() { 1 }");
    src.add(
        "main",
        "import \"lib\" as l\n\
         fn caller() { let a = l::helper\n a() }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    let helper_id = table.lookup("mod0::helper").expect("helper registered");
    let root = graph.get(graph.root());
    let a_idents = find_idents(&root.program, "a");
    assert_eq!(a_idents.len(), 1);
    assert_eq!(
        resolved.annotations.get(&(graph.root(), a_idents[0])),
        Some(&helper_id)
    );
}

#[test]
fn fn_alias_shadows_outer_module_fn() {
    // Inside `f`, `let a = poseidon` binds `a` as an alias to the
    // builtin. The outer `fn a()` is shadowed inside f's body —
    // `a(1, 2)` annotates to poseidon, not to the module's `a`.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn a() { 0 }\n\
         fn f() { let a = poseidon\n a(1, 2) }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    let poseidon_id = table.lookup("poseidon").expect("builtin registered");
    let root = graph.get(graph.root());
    // find_idents returns source order. The first `a` is the let
    // LHS position? No — that's a String, not an Expr. The first
    // Ident `a` is the call-site in `a(1, 2)`. And the let RHS
    // contains Ident("poseidon"), not `a`, so we get exactly one
    // Ident("a") in the program.
    let a_idents = find_idents(&root.program, "a");
    assert_eq!(a_idents.len(), 1);
    assert_eq!(
        resolved.annotations.get(&(graph.root(), a_idents[0])),
        Some(&poseidon_id),
        "inner alias should shadow the outer module fn `a`"
    );
}
