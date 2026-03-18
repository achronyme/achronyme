#[test]
fn std_modules_count() {
    let modules = achronyme_std::std_modules();
    // conv(4) + math(4) + string_ext(5) + io(3) = 16 with io feature
    #[cfg(feature = "io")]
    assert_eq!(modules.len(), 4);
    #[cfg(not(feature = "io"))]
    assert_eq!(modules.len(), 3);
}

#[test]
fn std_native_table_matches_modules() {
    let table = achronyme_std::std_native_table();
    let modules = achronyme_std::std_modules();

    let mut expected_names: Vec<&str> = Vec::new();
    for module in &modules {
        for def in module.natives() {
            expected_names.push(def.name);
        }
    }

    assert_eq!(table.len(), expected_names.len());
    for (meta, expected) in table.iter().zip(expected_names.iter()) {
        assert_eq!(meta.name, *expected);
    }
}

#[test]
fn register_std_on_vm() {
    let mut vm = vm::VM::new();
    let builtin_count = vm.natives.len();
    assert_eq!(builtin_count, 43); // builtins

    for module in achronyme_std::std_modules() {
        vm.register_module(&*module);
    }

    let std_table = achronyme_std::std_native_table();
    assert_eq!(vm.natives.len(), 43 + std_table.len());

    // Verify each new native is accessible
    for i in 43..vm.natives.len() {
        assert!(vm.globals[i].value.is_native());
    }
}

#[test]
fn compiler_with_std_natives() {
    let table = achronyme_std::std_native_table();
    let compiler = compiler::Compiler::with_extra_natives(&table);

    // Verify std natives are in global_symbols
    assert!(compiler.global_symbols.contains_key("to_string"));
    assert!(compiler.global_symbols.contains_key("parse_int"));
    assert!(compiler.global_symbols.contains_key("abs"));
    assert!(compiler.global_symbols.contains_key("min"));
    assert!(compiler.global_symbols.contains_key("starts_with"));
    assert!(compiler.global_symbols.contains_key("join"));

    #[cfg(feature = "io")]
    {
        assert!(compiler.global_symbols.contains_key("read_line"));
        assert!(compiler.global_symbols.contains_key("read_file"));
    }

    // Std natives should have indices >= 43
    let to_string_idx = compiler.global_symbols["to_string"];
    assert!(to_string_idx >= 43);
}

/// End-to-end: compile code using std natives and run it.
#[test]
fn e2e_std_natives() {
    let table = achronyme_std::std_native_table();
    let mut compiler = compiler::Compiler::with_extra_natives(&table);
    let source = r#"
        let x = abs(-42)
        assert(x == 42)

        let m = min(10, 20)
        assert(m == 10)

        let s = to_string(123)
        assert(s == "123")

        let n = parse_int("99")
        assert(n == 99)

        let p = pow(2, 10)
        assert(p == 1024)

        assert(starts_with("hello", "hel"))
        assert(ends_with("hello", "llo"))
        assert(contains("hello world", "world"))

        let joined = join(["a", "b", "c"], "-")
        assert(joined == "a-b-c")

        let rep = repeat("ab", 3)
        assert(rep == "ababab")
    "#;

    let bytecode = compiler.compile(source).expect("compilation failed");

    let mut vm = vm::VM::new();
    for module in achronyme_std::std_modules() {
        vm.register_module(&*module);
    }

    // Transfer compiler state to VM
    vm.import_strings(compiler.interner.strings);
    let field_map = vm.heap.import_fields(compiler.field_interner.fields);
    let bigint_map = vm.heap.import_bigints(compiler.bigint_interner.bigints);

    for proto in &mut compiler.prototypes {
        remap_handles(&mut proto.constants, &field_map, &bigint_map);
    }
    for proto in &compiler.prototypes {
        let f: memory::Function = proto.clone();
        let handle = vm.heap.alloc_function(f);
        vm.prototypes.push(handle);
    }

    let main_func = compiler.compilers.last().unwrap();
    let mut main_constants = main_func.constants.clone();
    remap_handles(&mut main_constants, &field_map, &bigint_map);

    let func = memory::Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: main_func.line_info.clone(),
    };
    let func_idx = vm.heap.alloc_function(func);
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    });
    vm.frames.push(vm::CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().expect("runtime error");
}

fn remap_handles(constants: &mut [memory::Value], field_map: &[u32], bigint_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_field() {
            let old = val.as_handle().unwrap();
            if let Some(&new) = field_map.get(old as usize) {
                *val = memory::Value::field(new);
            }
        } else if val.is_bigint() {
            let old = val.as_handle().unwrap();
            if let Some(&new) = bigint_map.get(old as usize) {
                *val = memory::Value::bigint(new);
            }
        }
    }
}
