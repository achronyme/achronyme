use super::*;
use crate::error::UnsupportedShape;

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
