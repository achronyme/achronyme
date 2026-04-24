#[test]
fn std_modules_count() {
    let modules = achronyme_std::std_modules();
    // conv(1) + string_ext(1) + io(3) = 5 with io feature
    #[cfg(feature = "io")]
    assert_eq!(modules.len(), 3);
    #[cfg(not(feature = "io"))]
    assert_eq!(modules.len(), 2);
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
    let native_count = resolve::BuiltinRegistry::default().vm_native_count();

    let mut vm = akron::VM::new();
    let builtin_count = vm.natives.len();
    assert_eq!(builtin_count, native_count);

    for module in achronyme_std::std_modules() {
        vm.register_module(&*module)
            .expect("register_module failed");
    }

    let std_table = achronyme_std::std_native_table();
    assert_eq!(vm.natives.len(), native_count + std_table.len());

    for i in native_count..vm.natives.len() {
        assert!(vm.globals[i].value.is_native());
    }
}

#[test]
fn compiler_with_std_natives() {
    let table = achronyme_std::std_native_table();
    let compiler = akronc::Compiler::with_extra_natives(&table);

    // Verify std natives are in global_symbols
    assert!(compiler.global_symbols.contains_key("parse_int"));
    assert!(compiler.global_symbols.contains_key("join"));

    #[cfg(feature = "io")]
    {
        assert!(compiler.global_symbols.contains_key("read_line"));
        assert!(compiler.global_symbols.contains_key("read_file"));
    }

    // Std natives should have indices >= 14
    let parse_int_idx = compiler.global_symbols["parse_int"].index;
    assert!(parse_int_idx >= 14);
}

/// End-to-end: compile code using std natives and run it.
#[test]
fn e2e_std_natives() {
    let table = achronyme_std::std_native_table();
    let mut compiler = akronc::Compiler::with_extra_natives(&table);
    let source = r#"
        let x = (-42).abs()
        assert(x == 42)

        let m = (10).min(20)
        assert(m == 10)

        let s = (123).to_string()
        assert(s == "123")

        let n = parse_int("99")
        assert(n == 99)

        let p = (2).pow(10)
        assert(p == 1024)

        assert("hello".starts_with("hel"))
        assert("hello".ends_with("llo"))
        assert("hello world".contains("world"))

        let joined = join(["a", "b", "c"], "-")
        assert(joined == "a-b-c")

        let rep = "ab".repeat(3)
        assert(rep == "ababab")
    "#;

    let bytecode = compiler.compile(source).expect("compilation failed");

    let mut vm = akron::VM::new();
    for module in achronyme_std::std_modules() {
        vm.register_module(&*module)
            .expect("register_module failed");
    }

    // Transfer compiler state to VM
    vm.import_strings(compiler.interner.strings);
    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .expect("import_fields");
    let bigint_map = vm
        .heap
        .import_bigints(compiler.bigint_interner.bigints)
        .expect("import_bigints");

    for proto in &mut compiler.prototypes {
        remap_handles(&mut proto.constants, &field_map, &bigint_map);
    }
    for proto in &compiler.prototypes {
        let f: memory::Function = proto.clone();
        let handle = vm.heap.alloc_function(f).expect("alloc");
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
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");
    vm.frames.push(akron::CallFrame {
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
