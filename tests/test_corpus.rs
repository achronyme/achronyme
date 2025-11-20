//! Test all files in tests/corpus/ with both backends

use std::fs;
use std::path::Path;
use achronyme_parser;
use achronyme_eval::Evaluator;
use achronyme_vm::{VM, Compiler};
use achronyme_types::value::Value;

#[test]
fn test_all_corpus_files() {
    let corpus_dir = Path::new("tests/corpus");

    if !corpus_dir.exists() {
        panic!("Corpus directory does not exist: tests/corpus");
    }

    let entries = fs::read_dir(corpus_dir)
        .expect("Failed to read corpus directory");

    let mut file_count = 0;
    let mut pass_count = 0;
    let mut failures = Vec::new();

    for entry in entries {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("ach") {
            continue;
        }

        file_count += 1;
        let filename = path.file_name().unwrap().to_str().unwrap();

        println!("\nTesting: {}", filename);

        let source = fs::read_to_string(&path)
            .expect(&format!("Failed to read {}", filename));

        match test_file(&source, filename) {
            Ok(()) => {
                println!("  PASS");
                pass_count += 1;
            }
            Err(e) => {
                println!("  FAIL: {}", e);
                failures.push(format!("{}: {}", filename, e));
            }
        }
    }

    println!("\n========================================");
    println!("Results: {}/{} tests passed", pass_count, file_count);
    println!("========================================");

    if !failures.is_empty() {
        println!("\nFailures:");
        for failure in &failures {
            println!("  - {}", failure);
        }
    }

    assert_eq!(
        pass_count, file_count,
        "Some corpus tests failed: {}/{} passed",
        pass_count, file_count
    );
}

fn test_file(source: &str, filename: &str) -> Result<(), String> {
    // Parse
    let ast = achronyme_parser::parse(source)
        .map_err(|e| format!("Parse error: {:?}", e))?;

    // Execute with tree-walker
    let mut eval = Evaluator::new();
    let tree_result = eval.eval(&ast)
        .map_err(|e| format!("Tree-walker error: {}", e))?;

    // Execute with VM
    let mut compiler = Compiler::new(filename.to_string());
    let module = compiler.compile(&ast)
        .map_err(|e| format!("Compile error: {}", e))?;

    let mut vm = VM::new();
    let vm_result = vm.execute(module)
        .map_err(|e| format!("VM error: {}", e))?;

    // Compare
    compare_values(&tree_result, &vm_result, filename)
}

fn compare_values(
    tree_val: &Value,
    vm_val: &Value,
    context: &str
) -> Result<(), String> {
    match (tree_val, vm_val) {
        (Value::Number(a), Value::Number(b)) => {
            // Handle NaN
            if a.is_nan() && b.is_nan() {
                return Ok(());
            }
            // Handle infinity
            if a.is_infinite() && b.is_infinite() {
                if a.is_sign_positive() != b.is_sign_positive() {
                    return Err(format!(
                        "Infinity sign mismatch: tree={}, vm={}",
                        a, b
                    ));
                }
                return Ok(());
            }
            // Compare numbers with tolerance
            if (a - b).abs() > 1e-10 {
                return Err(format!("Number mismatch: tree={}, vm={}", a, b));
            }
            Ok(())
        }
        (Value::Boolean(a), Value::Boolean(b)) => {
            if a != b {
                Err(format!("Boolean mismatch: tree={}, vm={}", a, b))
            } else {
                Ok(())
            }
        }
        (Value::String(a), Value::String(b)) => {
            if a != b {
                Err(format!("String mismatch: tree='{}', vm='{}'", a, b))
            } else {
                Ok(())
            }
        }
        (Value::Null, Value::Null) => Ok(()),
        (Value::Vector(a), Value::Vector(b)) => {
            if a.len() != b.len() {
                return Err(format!(
                    "Vector length mismatch: tree={}, vm={}",
                    a.len(), b.len()
                ));
            }
            for (i, (av, bv)) in a.iter().zip(b.iter()).enumerate() {
                compare_values(av, bv, &format!("{}[{}]", context, i))?;
            }
            Ok(())
        }
        (Value::Record(a), Value::Record(b)) => {
            if a.len() != b.len() {
                return Err(format!(
                    "Record size mismatch: tree={}, vm={}",
                    a.len(), b.len()
                ));
            }
            for (key, aval) in a.iter() {
                let bval = b.get(key).ok_or_else(|| {
                    format!("Key '{}' missing in VM result", key)
                })?;
                compare_values(aval, bval, &format!("{}.{}", context, key))?;
            }
            Ok(())
        }
        (Value::Function(_), Value::Function(_)) => {
            // Functions are not directly comparable
            Ok(())
        }
        (Value::MutableRef(a), Value::MutableRef(b)) => {
            compare_values(&a.borrow(), &b.borrow(), context)
        }
        _ => {
            Err(format!(
                "Type mismatch: tree={:?}, vm={:?}",
                value_type_name(tree_val),
                value_type_name(vm_val)
            ))
        }
    }
}

fn value_type_name(val: &Value) -> &str {
    match val {
        Value::Number(_) => "Number",
        Value::Boolean(_) => "Boolean",
        Value::String(_) => "String",
        Value::Null => "Null",
        Value::Vector(_) => "Vector",
        Value::Record(_) => "Record",
        Value::Function(_) => "Function",
        Value::MutableRef(_) => "MutableRef",
        Value::Tensor(_) => "Tensor",
        Value::ComplexTensor(_) => "ComplexTensor",
        Value::Complex(_) => "Complex",
        Value::Edge { .. } => "Edge",
        Value::TailCall(_) => "TailCall",
        Value::EarlyReturn(_) => "EarlyReturn",
        Value::Generator(_) => "Generator",
        Value::GeneratorYield(_) => "GeneratorYield",
        Value::Error { .. } => "Error",
        Value::LoopBreak(_) => "LoopBreak",
        Value::LoopContinue => "LoopContinue",
    }
}
