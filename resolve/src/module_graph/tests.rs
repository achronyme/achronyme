use std::collections::HashMap;
use std::path::{Path, PathBuf};

use achronyme_parser::parse_program;

use super::*;

/// In-memory mock. Files are keyed by a logical name ("a", "b",
/// "dir/c") — we bypass real path canonicalization entirely and
/// use the keys verbatim. This keeps the tests hermetic on any
/// filesystem and avoids the Windows/POSIX split over absolute
/// path quirks.
#[derive(Default)]
struct MockSource {
    files: HashMap<String, String>,
    /// Bumped every time `load` is called — used to prove diamond
    /// dedup avoids re-parsing.
    load_count: HashMap<String, u32>,
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
        *self.load_count.entry(key.clone()).or_default() += 1;
        let source = self
            .files
            .get(&key)
            .ok_or_else(|| format!("missing source for `{key}`"))?;
        let (program, errors) = parse_program(source);
        if !errors.is_empty() {
            return Err(format!("parse errors in `{key}`: {}", errors[0].message));
        }
        let exported_names = program
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Export { inner, .. } => match inner.as_ref() {
                    Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => Some(name.clone()),
                    _ => None,
                },
                Stmt::ExportList { names, .. } => Some(names.join(",")),
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
fn single_module_no_imports() {
    let mut src = MockSource::default();
    src.add("main", "let x = 1\nlet y = x + 2");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    assert_eq!(graph.len(), 1);
    assert_eq!(graph.root().as_u32(), 0);
    let root = graph.get(graph.root());
    assert_eq!(root.path, PathBuf::from("main"));
    assert!(root.imports.is_empty());
}

#[test]
fn namespace_import_creates_edge() {
    let mut src = MockSource::default();
    src.add("child", "export fn f() { 42 }");
    src.add("main", "import \"child\" as c\nlet x = c::f()");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    assert_eq!(graph.len(), 2);
    // Children come first in reverse topological order.
    assert_eq!(
        graph.get(ModuleId::from_raw(0)).path,
        PathBuf::from("child")
    );
    assert_eq!(graph.get(ModuleId::from_raw(1)).path, PathBuf::from("main"));
    assert_eq!(graph.root(), ModuleId::from_raw(1));

    let root = graph.get(graph.root());
    assert_eq!(root.imports.len(), 1);
    assert_eq!(root.imports[0].alias, "c");
    assert_eq!(root.imports[0].target, ModuleId::from_raw(0));
    assert!(matches!(root.imports[0].kind, ImportEdgeKind::Namespace));
}

#[test]
fn chained_imports_produce_topo_order() {
    let mut src = MockSource::default();
    src.add("c", "export fn g() { 1 }");
    src.add("b", "import \"c\" as c\nexport fn f() { c::g() }");
    src.add("a", "import \"b\" as b\nlet x = b::f()");
    let graph = ModuleGraph::build("a", &mut src).expect("build");
    assert_eq!(graph.len(), 3);
    // Reverse-topo: c, then b, then a.
    assert_eq!(graph.get(ModuleId::from_raw(0)).path, PathBuf::from("c"));
    assert_eq!(graph.get(ModuleId::from_raw(1)).path, PathBuf::from("b"));
    assert_eq!(graph.get(ModuleId::from_raw(2)).path, PathBuf::from("a"));
}

#[test]
fn diamond_dedups_shared_module() {
    // a → b → d
    // a → c → d
    let mut src = MockSource::default();
    src.add("d", "export fn h() { 7 }");
    src.add("b", "import \"d\" as d\nexport fn f() { d::h() }");
    src.add("c", "import \"d\" as d\nexport fn g() { d::h() }");
    src.add(
        "a",
        "import \"b\" as b\nimport \"c\" as c\nlet x = b::f() + c::g()",
    );
    let graph = ModuleGraph::build("a", &mut src).expect("build");
    // 4 modules, not 5 — d loaded once.
    assert_eq!(graph.len(), 4);
    // d parsed exactly once.
    assert_eq!(*src.load_count.get("d").unwrap(), 1);
    // Root is `a`, with edges to `b` and `c` (different ids), and
    // both of those share a `d` target.
    let root = graph.get(graph.root());
    assert_eq!(root.imports.len(), 2);
    let b_id = root.imports[0].target;
    let c_id = root.imports[1].target;
    let d_id_from_b = graph.get(b_id).imports[0].target;
    let d_id_from_c = graph.get(c_id).imports[0].target;
    assert_eq!(d_id_from_b, d_id_from_c);
}

#[test]
fn direct_cycle_detected() {
    let mut src = MockSource::default();
    src.add("a", "import \"b\" as b");
    src.add("b", "import \"a\" as a");
    let err = ModuleGraph::build("a", &mut src).unwrap_err();
    match err {
        ResolveError::ModuleCycle { path } => {
            assert_eq!(path, PathBuf::from("a"));
        }
        other => panic!("expected ModuleCycle, got {other:?}"),
    }
}

#[test]
fn self_cycle_detected() {
    let mut src = MockSource::default();
    src.add("a", "import \"a\" as a");
    let err = ModuleGraph::build("a", &mut src).unwrap_err();
    assert!(matches!(err, ResolveError::ModuleCycle { .. }));
}

#[test]
fn missing_root_reports_canonicalize_failure() {
    let mut src = MockSource::default();
    let err = ModuleGraph::build("nope", &mut src).unwrap_err();
    match err {
        ResolveError::ModuleCanonicalizeFailed {
            relative, importer, ..
        } => {
            assert_eq!(relative, "nope");
            assert!(importer.is_none(), "root has no importer");
        }
        other => panic!("expected ModuleCanonicalizeFailed, got {other:?}"),
    }
}

#[test]
fn missing_transitive_reports_importer() {
    let mut src = MockSource::default();
    src.add("a", "import \"b\" as b");
    // b intentionally not added.
    let err = ModuleGraph::build("a", &mut src).unwrap_err();
    match err {
        ResolveError::ModuleCanonicalizeFailed {
            relative, importer, ..
        } => {
            assert_eq!(relative, "b");
            assert_eq!(importer, Some(PathBuf::from("a")));
        }
        other => panic!("expected ModuleCanonicalizeFailed, got {other:?}"),
    }
}

#[test]
fn selective_import_preserves_names() {
    let mut src = MockSource::default();
    src.add("lib", "export fn a() { 1 }\nexport fn b() { 2 }");
    src.add("main", "import { a, b } from \"lib\"\nlet x = a() + b()");
    let graph = ModuleGraph::build("main", &mut src).expect("build");
    let root = graph.get(graph.root());
    assert_eq!(root.imports.len(), 1);
    match &root.imports[0].kind {
        ImportEdgeKind::Selective { names } => {
            assert_eq!(names, &vec!["a".to_string(), "b".to_string()]);
        }
        other => panic!("expected Selective, got {other:?}"),
    }
    assert_eq!(root.imports[0].alias, "");
}

#[test]
fn dfs_stack_clears_between_siblings() {
    // Regression guard: after loading `b`, `b` is no longer on the
    // DFS stack when `c` starts loading, so importing `b` again
    // from `c` must dedup (not fire a cycle error). This is the
    // same pattern the diamond test exercises; this test isolates
    // the stack-hygiene invariant from the diamond dedup logic.
    let mut src = MockSource::default();
    src.add("b", "export fn f() { 1 }");
    src.add("c", "import \"b\" as b\nexport fn g() { b::f() }");
    src.add("a", "import \"b\" as b\nimport \"c\" as c");
    let graph = ModuleGraph::build("a", &mut src).expect("build");
    assert_eq!(graph.len(), 3);
    assert_eq!(*src.load_count.get("b").unwrap(), 1);
}
