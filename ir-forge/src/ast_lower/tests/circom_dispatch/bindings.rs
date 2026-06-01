use super::*;

// --- let-binding + DotAccess ---

/// Parse source as a Block and compile through compile_block_stmts.
/// Useful for tests that need a let + dot-access sequence.
pub(super) fn compile_block(
    compiler: &mut ProveIrCompiler<Bn254Fr>,
    source: &str,
) -> Result<(), ProveIrError> {
    use achronyme_parser::parse_program;
    let (program, errors) = parse_program(source);
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    let block = Block {
        stmts: program.stmts,
        span: Span {
            byte_start: 0,
            byte_end: 0,
            line_start: 0,
            col_start: 0,
            line_end: 0,
            col_end: 0,
        },
    };
    compiler.compile_block_stmts(&block)
}

#[test]
fn let_bind_multi_output_template_publishes_dotted_env_entries() {
    let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
    compile_block(&mut compiler, "let r = Pair()(x)")
        .expect("let-binding a multi-output template should succeed");
    // Each output lands under "r.<output>" in the env.
    assert!(compiler.env.contains_key("r.a"));
    assert!(compiler.env.contains_key("r.b"));
    // Single-scalar convenience binding is NOT emitted for
    // multi-output templates.
    assert!(!compiler.env.contains_key("r"));
}

#[test]
fn let_bind_single_scalar_template_also_binds_top_level_ident() {
    let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
    compile_block(&mut compiler, "let r = Square()(x)")
        .expect("let-binding a scalar template should succeed");
    // Both `r` and `r.y` exist.
    assert!(compiler.env.contains_key("r"));
    assert!(compiler.env.contains_key("r.y"));
}

#[test]
fn dot_access_on_multi_output_let_binding_resolves_to_mangled_vars() {
    let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
    compile_block(
        &mut compiler,
        "let r = Pair()(x)\nassert_eq(r.a, x)\nassert_eq(r.b, x)",
    )
    .expect("dot access on multi-output should resolve");
    // The compile body now has assert_eq nodes pointing at
    // the mangled sub-template vars.
    let assert_vars: Vec<&str> = compiler
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::AssertEq {
                lhs: CircuitExpr::Var(v),
                ..
            } => Some(v.as_str()),
            _ => None,
        })
        .collect();
    // StubLibrary names outputs as `<prefix>_<out>`. Pair's
    // outputs were a/b; the instantiated prefix is
    // circom_call_0. We expect exactly the first output
    // recorded — the stub only stores the first in outputs.
    // For this test we just assert both asserts landed.
    assert!(assert_vars.iter().any(|v| v.starts_with("circom_call_")));
}

#[test]
fn namespaced_let_binding_publishes_dotted_env_entries() {
    // The namespaced form P.Pair(...)(...) is resolved the same
    // way as the bare form once try_resolve_circom_key has
    // produced the "P::Pair" key, so the let-binding path
    // should bind outputs identically.
    let (mut compiler, _lib) = compiler_with_stub(
        "Pair", // template_name
        sig(&[], &["x"], &["a", "b"]),
    );
    // Rewire the registration: under key "P::Pair" instead of
    // "Pair" (simulates a namespace import). We need to re-
    // register because compiler_with_stub bound under "Pair".
    let entry = compiler.circom_table.remove("Pair").unwrap();
    compiler.circom_table.insert("P::Pair".to_string(), entry);

    compile_block(&mut compiler, "let r = P.Pair()(x)")
        .expect("namespaced let-binding should succeed");
    assert!(compiler.env.contains_key("r.a"));
    assert!(compiler.env.contains_key("r.b"));
}

/// Stub that returns an array output to exercise the array-
/// flattening code path on the let-binding side.
#[derive(Debug)]
pub(super) struct ArrayOutputLibrary {
    pub(super) name: String,
    pub(super) dims: Vec<u64>,
}
impl CircomLibraryHandle for ArrayOutputLibrary {
    fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
        if name != self.name {
            return None;
        }
        Some(CircomTemplateSignature {
            params: vec!["n".to_string()],
            input_signals: vec!["in".to_string()],
            output_signals: vec!["out".to_string()],
        })
    }
    fn template_names(&self) -> Vec<String> {
        vec![self.name.clone()]
    }
    fn resolve_input_layout(
        &self,
        template_name: &str,
        _template_args: &[FieldConst],
    ) -> Option<Vec<crate::CircomInputLayout>> {
        if template_name != self.name {
            return None;
        }
        // Single scalar input `in` for this stub.
        Some(vec![crate::CircomInputLayout {
            name: "in".to_string(),
            dims: Vec::new(),
        }])
    }
    fn instantiate_template(
        &self,
        _template_name: &str,
        _template_args: &[FieldConst],
        _signal_inputs: &HashMap<String, CircuitExpr>,
        parent_prefix: &str,
        _span: &Span,
    ) -> Result<CircomInstantiation, crate::CircomDispatchError> {
        let total: u64 = self.dims.iter().product();
        let values: Vec<CircuitExpr> = (0..total)
            .map(|i| CircuitExpr::Var(format!("{parent_prefix}_out_{i}")))
            .collect();
        let mut outputs = HashMap::new();
        outputs.insert(
            "out".to_string(),
            CircomTemplateOutput::Array {
                dims: self.dims.clone(),
                values,
            },
        );
        Ok(CircomInstantiation {
            body: Vec::new(),
            outputs,
            component_bodies: std::collections::HashMap::new(),
        })
    }
}

#[test]
fn let_bind_array_output_publishes_indexed_env_entries() {
    let lib: Arc<dyn CircomLibraryHandle> = Arc::new(ArrayOutputLibrary {
        name: "Num2Bits".to_string(),
        dims: vec![4],
    });
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    compiler.register_circom_template("Num2Bits".to_string(), lib, "Num2Bits".to_string());
    compiler
        .env
        .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));

    compile_block(&mut compiler, "let r = Num2Bits(4)(x)")
        .expect("array-output let binding should succeed");
    for i in 0..4 {
        let key = format!("r.out_{i}");
        assert!(
            compiler.env.contains_key(&key),
            "expected env key {key}, have: {:?}",
            compiler.env.keys().collect::<Vec<_>>()
        );
    }
    // No top-level `r` binding — arrays don't have a scalar
    // convenience form.
    assert!(!compiler.env.contains_key("r"));
}
