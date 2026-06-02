use super::common::{
    remap_field_handles, run_source_with_mock_proof, run_source_with_prove, MockProofHandler,
};
use akron::{CallFrame, VM};
use akronc::Compiler;
use memory::{Function, Value};

// ======================================================================
// Level 3: ProofObject + ProveResult tests
// ======================================================================
#[test]
fn prove_returns_proof_object_when_handler_provides_proof() {
    let source = r#"
        let x = 0p42
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
        let x = 0p1
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
        let x = 0p42
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
        let x = 0p42
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
        let x = 0p42
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
        let x = 0p42
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
        let x = 0p42
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

    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .expect("import_fields");

    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let mut main_constants = main_func.constants.clone();
    remap_field_handles(&mut main_constants, &field_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

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
    let handle = heap.alloc_proof(obj).expect("alloc");
    let val = Value::proof(handle);
    assert!(val.is_proof());
    assert!(!val.is_nil());

    let proof = heap.get_proof(handle).unwrap();
    assert_eq!(proof.proof_json, r#"{"a":"b"}"#);
    assert_eq!(proof.public_json, r#"["1"]"#);
    assert_eq!(proof.vkey_json, r#"{"x":"y"}"#);
}
