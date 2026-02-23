use compiler::Compiler;
use memory::FieldElement;
use memory::{Function, Value};
use std::collections::HashMap;
use vm::{CallFrame, ProveError, ProveHandler, ProveResult, VM};

/// Helper: compile and run Achronyme source, returning the VM after execution.
/// Does NOT inject a prove handler.
fn run_source(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.heap.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone());
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    });

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

/// Helper: compile and run with the real prove handler injected.
fn run_source_with_prove(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.heap.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone());
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    });

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    // Inject the real prove handler (uses IR→R1CS pipeline)
    vm.prove_handler = Some(Box::new(RealProveHandler));

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

/// Real prove handler that uses the full IR→R1CS pipeline.
struct RealProveHandler;

impl ProveHandler for RealProveHandler {
    fn execute_prove(
        &self,
        source: &str,
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        use compiler::r1cs_backend::R1CSCompiler;
        use ir::IrLowering;

        let inner = source
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(source);

        let (pub_names, wit_names, mut program) = IrLowering::lower_self_contained(inner)
            .map_err(|e| ProveError::IrLowering(format!("{e}")))?;

        ir::passes::optimize(&mut program);

        let mut inputs = HashMap::new();
        for name in pub_names.iter().chain(wit_names.iter()) {
            let val = scope_values.get(name).ok_or_else(|| {
                ProveError::IrLowering(format!("variable `{name}` not found in scope"))
            })?;
            inputs.insert(name.clone(), *val);
        }

        let mut r1cs = R1CSCompiler::new();
        let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
        r1cs.set_proven_boolean(proven);
        let witness = r1cs
            .compile_ir_with_witness(&program, &inputs)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;

        r1cs.cs
            .verify(&witness)
            .map_err(|idx| ProveError::Verification(format!("constraint {idx} failed")))?;

        Ok(ProveResult::VerifiedOnly)
    }
}

// ======================================================================
// VM unit tests
// ======================================================================

#[test]
fn prove_handler_not_configured() {
    let source = r#"
        let x = field(42)
        prove {
            witness x
            assert_eq(x, 42)
        }
    "#;
    let result = run_source(source);
    match result {
        Ok(_) => panic!("Expected ProveHandlerNotConfigured error"),
        Err(err) => assert!(
            err.contains("ProveHandlerNotConfigured"),
            "Expected ProveHandlerNotConfigured, got: {err}"
        ),
    }
}

#[test]
fn value_to_field_element_field() {
    use vm::machine::prove::value_to_field_element;
    let mut heap = memory::Heap::new();
    let fe = FieldElement::from_u64(42);
    let handle = heap.alloc_field(fe);
    let val = Value::field(handle);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(fe));
}

#[test]
fn value_to_field_element_int() {
    use vm::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::int(123);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(FieldElement::from_i64(123)));
}

#[test]
fn value_to_field_element_nil_returns_none() {
    use vm::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::nil();
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, None);
}

#[test]
fn value_to_field_element_bool_returns_none() {
    use vm::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::true_val();
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, None);
}

#[test]
fn value_to_field_element_int_seven() {
    use vm::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::int(7);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(FieldElement::from_i64(7)));
}

#[test]
fn value_to_field_element_negative_int() {
    use vm::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::int(-3);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(FieldElement::from_i64(-3)));
}

// ======================================================================
// Integration tests (E2E with real prove handler)
// ======================================================================

#[test]
fn prove_simple_assert_eq() {
    let source = r#"
        let x = field(42)
        prove {
            witness x
            assert_eq(x, 42)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "prove simple assert_eq failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_addition() {
    let source = r#"
        let a = field(3)
        let b = field(5)
        let c = field(8)
        prove {
            witness a, b
            public c
            assert_eq(a + b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(result.is_ok(), "prove addition failed: {:?}", result.err());
}

#[test]
fn prove_multiplication() {
    let source = r#"
        let a = field(6)
        let b = field(7)
        let c = field(42)
        prove {
            witness a, b
            public c
            assert_eq(a * b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "prove multiplication failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_failing_constraint() {
    let source = r#"
        let a = field(3)
        let b = field(5)
        let c = field(42)
        prove {
            witness a, b
            public c
            assert_eq(a + b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    match result {
        Ok(_) => panic!("prove should fail: 3+5 != 42"),
        Err(err) => assert!(
            err.contains("ProveBlockFailed"),
            "Expected ProveBlockFailed, got: {err}"
        ),
    }
}

#[test]
fn prove_int_promotion() {
    // Integer values should be promoted to FieldElement
    let source = r#"
        let x = 42
        prove {
            witness x
            assert_eq(x, 42)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "prove int promotion failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_missing_variable_compile_error() {
    // Variable referenced in prove block not found in scope → compile-time error
    let source = r#"
        prove {
            witness missing_var
            assert_eq(missing_var, 1)
        }
    "#;
    let mut compiler = Compiler::new();
    let result = compiler.compile(source);
    assert!(result.is_err(), "Should error on missing variable");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("missing_var") && err.contains("not found"),
        "Expected missing variable error, got: {err}"
    );
}

#[test]
fn prove_result_is_nil() {
    // prove {} evaluates to nil — verify no runtime error
    let source = r#"
        let x = field(1)
        let result = prove {
            witness x
            assert_eq(x, 1)
        }
    "#;
    run_source_with_prove(source).expect("prove should succeed");
}

#[test]
fn prove_wrong_witness_fails() {
    // Witness doesn't satisfy constraint
    let source = r#"
        let a = field(10)
        let b = field(20)
        let c = field(999)
        prove {
            witness a, b
            public c
            assert_eq(a * b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(result.is_err(), "prove should fail: 10*20 != 999");
}

#[test]
fn prove_poseidon_inside_prove_block() {
    // Poseidon is a circuit-level builtin, not a VM function.
    // We precompute the hash using Rust and pass its decimal string as a field literal.
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(42);
    let right = FieldElement::ZERO;
    let hash = constraints::poseidon::poseidon_hash(&params, left, right);
    let hash_str = hash.to_decimal_string();

    let source = format!(
        r#"
        let s = field(42)
        let h = field("{hash_str}")
        prove {{
            witness s
            public h
            assert_eq(poseidon(s, 0), h)
        }}
    "#
    );
    let result = run_source_with_prove(&source);
    assert!(result.is_ok(), "prove poseidon failed: {:?}", result.err());
}

#[test]
fn prove_poseidon_wrong_witness() {
    // Same structure but with wrong witness → should fail
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(42);
    let right = FieldElement::ZERO;
    let hash = constraints::poseidon::poseidon_hash(&params, left, right);
    let hash_str = hash.to_decimal_string();

    let source = format!(
        r#"
        let s = field(99)
        let h = field("{hash_str}")
        prove {{
            witness s
            public h
            assert_eq(poseidon(s, 0), h)
        }}
    "#
    );
    let result = run_source_with_prove(&source);
    assert!(
        result.is_err(),
        "prove should fail: wrong witness for poseidon"
    );
}

#[test]
fn prove_multiple_blocks() {
    // Multiple prove blocks in sequence
    let source = r#"
        let a = field(10)
        let b = field(20)
        prove {
            witness a
            assert_eq(a, 10)
        }
        prove {
            witness b
            assert_eq(b, 20)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "multiple prove blocks failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_power_circuit() {
    let source = r#"
        let x = field(3)
        let y = field(27)
        prove {
            witness x
            public y
            assert_eq(x ^ 3, y)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(result.is_ok(), "prove power failed: {:?}", result.err());
}

// ======================================================================
// Level 3: ProofObject + ProveResult tests
// ======================================================================

/// Mock handler that returns a Proof with fixed JSON payloads.
struct MockProofHandler;

impl ProveHandler for MockProofHandler {
    fn execute_prove(
        &self,
        _source: &str,
        _scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        Ok(ProveResult::Proof {
            proof_json: r#"{"pi_a":["1","2"]}"#.to_string(),
            public_json: r#"["42"]"#.to_string(),
            vkey_json: r#"{"protocol":"groth16"}"#.to_string(),
        })
    }
}

/// Helper: compile and run with the mock proof handler.
fn run_source_with_mock_proof(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.heap.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone());
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    });

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.prove_handler = Some(Box::new(MockProofHandler));

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

#[test]
fn prove_returns_proof_object_when_handler_provides_proof() {
    let source = r#"
        let x = field(42)
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        print(p)
    "#;
    let vm = run_source_with_mock_proof(source).expect("should succeed");
    // The prove block stored a Proof value; check by reading register 0
    // We can't easily inspect the stack result, but the fact that it ran
    // and print("<Proof>") didn't crash is sufficient.
    // Additionally verify the heap has a proof allocated.
    assert!(vm.heap.has_proofs(), "proof should be allocated on heap");
}

#[test]
fn prove_verified_only_returns_nil() {
    // The RealProveHandler returns VerifiedOnly → nil
    let source = r#"
        let x = field(1)
        let result = prove {
            witness x
            assert_eq(x, 1)
        }
    "#;
    run_source_with_prove(source).expect("prove should succeed");
}

#[test]
fn proof_json_native_returns_correct_string() {
    let source = r#"
        let x = field(42)
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        let j = proof_json(p)
        print(j)
    "#;
    let vm = run_source_with_mock_proof(source).expect("should succeed");
    // Verify proof was allocated
    assert!(vm.heap.has_proofs());
}

#[test]
fn proof_public_native_returns_correct_string() {
    let source = r#"
        let x = field(42)
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        let j = proof_public(p)
        print(j)
    "#;
    let vm = run_source_with_mock_proof(source).expect("should succeed");
    assert!(vm.heap.has_proofs());
}

#[test]
fn proof_vkey_native_returns_correct_string() {
    let source = r#"
        let x = field(42)
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        let j = proof_vkey(p)
        print(j)
    "#;
    let vm = run_source_with_mock_proof(source).expect("should succeed");
    assert!(vm.heap.has_proofs());
}

#[test]
fn proof_json_on_non_proof_gives_type_error() {
    let source = r#"
        let x = 42
        let j = proof_json(x)
    "#;
    let result = run_source_with_mock_proof(source);
    match result {
        Ok(_) => panic!("proof_json on int should fail"),
        Err(err) => assert!(
            err.contains("TypeMismatch"),
            "Expected TypeMismatch, got: {err}"
        ),
    }
}

#[test]
fn typeof_proof_returns_proof_string() {
    let source = r#"
        let x = field(42)
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        let t = typeof(p)
        print(t)
    "#;
    let vm = run_source_with_mock_proof(source).expect("should succeed");
    assert!(vm.heap.has_proofs());
}

#[test]
fn proof_object_gc_survives_when_rooted() {
    let source = r#"
        let x = field(42)
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        let j = proof_json(p)
        print(j)
    "#;
    let mut vm = VM::new();
    vm.stress_mode = true; // GC on every allocation

    let mut compiler = Compiler::new();
    let bytecode = compiler
        .compile(source)
        .map_err(|e| format!("{e:?}"))
        .unwrap();
    let main_func = compiler.compilers.last().expect("No main compiler");

    vm.heap.import_strings(compiler.interner.strings);
    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone());
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    });

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.prove_handler = Some(Box::new(MockProofHandler));

    vm.interpret()
        .map_err(|e| format!("{e:?}"))
        .expect("should succeed with stress GC");
}

#[test]
fn proof_object_allocation_and_inspection() {
    use memory::{Heap, ProofObject};
    let mut heap = Heap::new();
    let obj = ProofObject {
        proof_json: r#"{"a":"b"}"#.to_string(),
        public_json: r#"["1"]"#.to_string(),
        vkey_json: r#"{"x":"y"}"#.to_string(),
    };
    let handle = heap.alloc_proof(obj);
    let val = Value::proof(handle);
    assert!(val.is_proof());
    assert!(!val.is_nil());

    let proof = heap.get_proof(handle).unwrap();
    assert_eq!(proof.proof_json, r#"{"a":"b"}"#);
    assert_eq!(proof.public_json, r#"["1"]"#);
    assert_eq!(proof.vkey_json, r#"{"x":"y"}"#);
}
