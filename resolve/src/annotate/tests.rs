use super::*;
use crate::module_graph::{LoadedModule, ModuleGraph, ModuleSource};
use achronyme_parser::ast::ExprId;
use achronyme_parser::parse_program;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// In-memory `ModuleSource` mirroring the one in `module_graph::tests`.
/// Duplicated here to keep the two test modules independent; a
/// shared helper would cost more than the 40 lines of copy.
#[derive(Default)]
struct MockSource {
    files: HashMap<String, String>,
}

impl MockSource {
    fn add(&mut self, name: &str, source: &str) {
        self.files.insert(name.to_string(), source.to_string());
    }
}

impl ModuleSource for MockSource {
    fn canonicalize(
        &mut self,
        _importer: Option<&Path>,
        relative: &str,
    ) -> Result<PathBuf, String> {
        if self.files.contains_key(relative) {
            Ok(PathBuf::from(relative))
        } else {
            Err(format!("no such module `{relative}`"))
        }
    }

    fn load(&mut self, canonical: &Path) -> Result<LoadedModule, String> {
        let key = canonical.to_string_lossy().into_owned();
        let source = self
            .files
            .get(&key)
            .ok_or_else(|| format!("missing source for `{key}`"))?;
        let (program, errors) = parse_program(source);
        if !errors.is_empty() {
            return Err(format!("parse errors in `{key}`: {}", errors[0].message));
        }
        // Mirror the ir::ModuleLoader contract: walk top-level
        // exports and flatten to a name list.
        let exported_names = program
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Export { inner, .. } => match inner.as_ref() {
                    Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => {
                        Some(name.clone())
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect();
        Ok(LoadedModule {
            program,
            exported_names,
        })
    }
}

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

// ======================================================================
// annotate_program — Phase 3C.2
// ======================================================================

use crate::builtins::BuiltinRegistry;
use achronyme_parser::ast::{Program, TypedParam};

/// Walk every Expr in a Program, calling `f` on each. Used by the
/// 3C.2 tests to hand-pick specific nodes (by kind + name) and
/// assert on their annotations without building a full visitor.
fn visit_program<F: FnMut(&Expr)>(program: &Program, mut f: F) {
    for stmt in &program.stmts {
        visit_stmt(stmt, &mut f);
    }
}

fn visit_stmt<F: FnMut(&Expr)>(stmt: &Stmt, f: &mut F) {
    match stmt {
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => visit_expr(value, f),
        Stmt::Assignment { target, value, .. } => {
            visit_expr(target, f);
            visit_expr(value, f);
        }
        Stmt::FnDecl { body, .. } | Stmt::CircuitDecl { body, .. } => {
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Stmt::Print { value, .. } => visit_expr(value, f),
        Stmt::Return { value: Some(v), .. } => visit_expr(v, f),
        Stmt::Expr(e) => visit_expr(e, f),
        Stmt::Export { inner, .. } => visit_stmt(inner, f),
        _ => {}
    }
}

fn visit_expr<F: FnMut(&Expr)>(expr: &Expr, f: &mut F) {
    f(expr);
    match expr {
        Expr::BinOp { lhs, rhs, .. } => {
            visit_expr(lhs, f);
            visit_expr(rhs, f);
        }
        Expr::UnaryOp { operand, .. } => visit_expr(operand, f),
        Expr::Call { callee, args, .. } => {
            visit_expr(callee, f);
            for a in args {
                visit_expr(&a.value, f);
            }
        }
        Expr::Index { object, index, .. } => {
            visit_expr(object, f);
            visit_expr(index, f);
        }
        Expr::DotAccess { object, .. } => visit_expr(object, f),
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            visit_expr(condition, f);
            for s in &then_block.stmts {
                visit_stmt(s, f);
            }
            match else_branch {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        visit_stmt(s, f);
                    }
                }
                Some(ElseBranch::If(e)) => visit_expr(e, f),
                None => {}
            }
        }
        Expr::For { iterable, body, .. } => {
            match iterable {
                ForIterable::ExprRange { end, .. } => visit_expr(end, f),
                ForIterable::Expr(e) => visit_expr(e, f),
                _ => {}
            }
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::While {
            condition, body, ..
        } => {
            visit_expr(condition, f);
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::Forever { body, .. } | Expr::FnExpr { body, .. } | Expr::Prove { body, .. } => {
            for s in &body.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::Block { block, .. } => {
            for s in &block.stmts {
                visit_stmt(s, f);
            }
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                visit_expr(e, f);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                visit_expr(v, f);
            }
        }
        _ => {}
    }
}

/// Find every `Expr::Ident { name: expected }` in a module and return
/// their [`ExprId`]s in source order.
fn find_idents(program: &Program, expected: &str) -> Vec<ExprId> {
    let mut out = Vec::new();
    visit_program(program, |e| {
        if let Expr::Ident { id, name, .. } = e {
            if name == expected {
                out.push(*id);
            }
        }
    });
    out
}

fn find_static_accesses(program: &Program, type_name: &str, member: &str) -> Vec<ExprId> {
    let mut out = Vec::new();
    visit_program(program, |e| {
        if let Expr::StaticAccess {
            id,
            type_name: t,
            member: m,
            ..
        } = e
        {
            if t == type_name && m == member {
                out.push(*id);
            }
        }
    });
    out
}

fn find_dot_accesses(program: &Program, object_name: &str, field: &str) -> Vec<ExprId> {
    let mut out = Vec::new();
    visit_program(program, |e| {
        if let Expr::DotAccess {
            id,
            object,
            field: f,
            ..
        } = e
        {
            if f == field {
                if let Expr::Ident { name, .. } = object.as_ref() {
                    if name == object_name {
                        out.push(*id);
                    }
                }
            }
        }
    });
    out
}

/// Build a fresh table with the production builtin registry plus
/// the given graph's module symbols.
fn build_full_table(graph: &ModuleGraph) -> SymbolTable {
    let mut table =
        SymbolTable::with_registry(BuiltinRegistry::default()).expect("registry audit");
    register_builtins(&mut table);
    register_all(&mut table, graph).expect("register_all");
    table
}

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
    // Gap 2.4 preview. The `c::deep()` call inside b::middle()
    // must resolve to `mod0::deep` (c's fn) at annotation time,
    // because we walk module `b` against `b`'s own imports. When
    // Phase 3E inlines `middle` into `a.ach`, the annotation is
    // already attached — `a.ach`'s scope never gets a chance to
    // re-resolve `c::deep` against its own (non-existent) `c`
    // import.
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
    // Phase 3C.1 registered `PI` as a Constant. Inside the same
    // module, a bare reference to `PI` should annotate against
    // that Constant (not fall through to "local" — top-level
    // lets are not tracked in the scope stack for exactly this
    // reason).
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
    let mut table =
        SymbolTable::with_registry(BuiltinRegistry::default()).expect("registry audit");
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

// ======================================================================
// FnAlias + ProveBlockUnsupportedShape — Phase 3C.3
// ======================================================================

use crate::error::UnsupportedShape;

#[test]
fn fn_alias_local_resolves_to_target() {
    // `let a = helper; a()` — the call-site `a` is annotated
    // directly to helper's SymbolId, so Phase 3D/3E dispatch
    // through the alias uniformly.
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

#[test]
fn dynamic_fn_value_emitted_inside_prove_block() {
    // `let a = if true { poseidon } else { mux }; a(1,2,3)` in a
    // prove block. Both branches const-resolve to fn symbols, so
    // `a` is a DynamicFn local, and calling it in prove mode
    // fires the DynamicFnValue diagnostic.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn outer() {\n\
           prove() {\n\
             let a = if true { poseidon } else { mux }\n\
             a(1, 2, 3)\n\
           }\n\
         }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    assert!(
        resolved.diagnostics.iter().any(|d| matches!(
            d,
            ResolveError::ProveBlockUnsupportedShape {
                shape: UnsupportedShape::DynamicFnValue,
                ..
            }
        )),
        "expected DynamicFnValue, got {:?}",
        resolved.diagnostics
    );
}

#[test]
fn dynamic_fn_value_outside_prove_is_silent() {
    // Same pattern as above, without the `prove()` wrapper —
    // VM mode handles dynamic fn values through closures, so no
    // diagnostic should fire.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn outer() {\n\
           let a = if true { poseidon } else { mux }\n\
           a(1, 2, 3)\n\
         }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);
    assert!(
        resolved.diagnostics.is_empty(),
        "no diagnostics expected outside prove block, got {:?}",
        resolved.diagnostics
    );
}

#[test]
fn runtime_map_access_emitted_inside_prove_block() {
    // `let m = { k: 1 }; m.k` inside a prove block. The Map
    // literal is classified as RuntimeMap; any DotAccess on `m`
    // emits RuntimeMapAccess.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn outer() {\n\
           prove() {\n\
             let m = { k: 1 }\n\
             m.k\n\
           }\n\
         }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    assert!(
        resolved.diagnostics.iter().any(|d| matches!(
            d,
            ResolveError::ProveBlockUnsupportedShape {
                shape: UnsupportedShape::RuntimeMapAccess,
                ..
            }
        )),
        "expected RuntimeMapAccess, got {:?}",
        resolved.diagnostics
    );
}

#[test]
fn runtime_method_chain_emitted_inside_prove_block() {
    // `let x = 1; x.foo()` inside a prove block. The callee is a
    // DotAccess whose object is a plain local — not a namespace
    // alias — so walk_call emits RuntimeMethodChain.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn outer() {\n\
           prove() {\n\
             let x = 1\n\
             x.foo()\n\
           }\n\
         }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    assert!(
        resolved.diagnostics.iter().any(|d| matches!(
            d,
            ResolveError::ProveBlockUnsupportedShape {
                shape: UnsupportedShape::RuntimeMethodChain,
                ..
            }
        )),
        "expected RuntimeMethodChain, got {:?}",
        resolved.diagnostics
    );
}

#[test]
fn namespace_dot_call_is_not_method_chain() {
    // `l.helper()` where `l` is a namespace alias — valid in
    // prove mode, no diagnostic.
    let mut src = MockSource::default();
    src.add("lib", "export fn helper() { 1 }");
    src.add(
        "main",
        "import \"lib\" as l\n\
         fn outer() {\n\
           prove() {\n\
             l.helper()\n\
           }\n\
         }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    assert!(
        resolved.diagnostics.is_empty(),
        "namespace dot call should not trigger RuntimeMethodChain, got {:?}",
        resolved.diagnostics
    );
}

#[test]
fn non_static_fn_arg_emitted_inside_prove_block() {
    // `poseidon(if true { poseidon } else { mux }, 2)` inside a
    // prove block. The first arg is an If whose branches both
    // const-resolve to fn symbols — a dynamic fn value in
    // argument position.
    let mut src = MockSource::default();
    src.add(
        "main",
        "fn outer() {\n\
           prove() {\n\
             poseidon(if true { poseidon } else { mux }, 2)\n\
           }\n\
         }",
    );
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let table = build_full_table(&graph);
    let resolved = annotate_program(&graph, &table);

    assert!(
        resolved.diagnostics.iter().any(|d| matches!(
            d,
            ResolveError::ProveBlockUnsupportedShape {
                shape: UnsupportedShape::NonStaticFnArg,
                ..
            }
        )),
        "expected NonStaticFnArg, got {:?}",
        resolved.diagnostics
    );
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
