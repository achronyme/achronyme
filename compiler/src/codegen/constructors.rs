//! Constructors for [`Compiler`]: the zero-arg `new` path and the
//! `with_extra_natives` path used by CLI/server flows that want to
//! expose `#[ach_module]` proc-macro–generated native functions
//! alongside the builtin registry.
//!
//! The `Default` impl defers to `new` — kept here next to the rest
//! of the wiring so the initial struct population lives in one
//! place.

use std::collections::{HashMap, HashSet};

use vm::specs::NativeMeta;

use super::Compiler;
use crate::function_compiler::FunctionCompiler;
use crate::interner::{
    BigIntInterner, BytesInterner, CircomHandleInterner, CircomLibraryRegistry, FieldInterner,
    StringInterner,
};
use crate::module_loader::ModuleLoader;

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self::with_extra_natives(&[])
    }

    /// Create a compiler with additional native functions beyond the builtins.
    ///
    /// `extra` entries are appended after the registry builtins — their
    /// indices continue from the VM native count. The VM must register
    /// the same modules in the same order via `VM::register_module()`.
    pub fn with_extra_natives(extra: &[NativeMeta]) -> Self {
        use crate::types::GlobalEntry;
        let registry = resolve::BuiltinRegistry::default();
        let vm_entries = registry.vm_entries_by_handle();
        let native_count = vm_entries.len();

        let mut global_symbols = HashMap::new();

        for entry in &vm_entries {
            let handle = entry.vm_fn.expect("vm_entries_by_handle guarantees vm_fn");
            global_symbols.insert(
                entry.name.to_string(),
                GlobalEntry {
                    index: handle.as_u32() as u16,
                    type_ann: None,
                    is_mutable: false,
                    param_names: None,
                },
            );
        }

        for (i, meta) in extra.iter().enumerate() {
            let index = native_count + i;
            assert!(
                !global_symbols.contains_key(meta.name),
                "Native name collision: '{}' already defined as builtin",
                meta.name,
            );
            global_symbols.insert(
                meta.name.to_string(),
                GlobalEntry {
                    index: index as u16,
                    type_ann: None,
                    is_mutable: false,
                    param_names: None,
                },
            );
        }

        let next_global_idx = (native_count + extra.len()) as u16;

        // Start with a "main" function compiler (arity=0 for top-level script)
        let main_compiler = FunctionCompiler::new("main".to_string(), 0);

        // Populate known method names from the prototype registry.
        let known_methods: HashSet<String> = vm::known_method_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        Self {
            compilers: vec![main_compiler],
            prototypes: Vec::new(),
            global_symbols,
            next_global_idx,
            native_count: native_count as u16,
            interner: StringInterner::new(),
            field_interner: FieldInterner::new(),
            bigint_interner: BigIntInterner::new(),
            bytes_interner: BytesInterner::new(),
            circom_handle_interner: CircomHandleInterner::new(),
            circom_library_registry: CircomLibraryRegistry::new(),
            base_path: None,
            module_loader: ModuleLoader::new(),
            module_prefix: None,
            imported_aliases: HashMap::new(),
            compiling_modules: HashSet::new(),
            imported_names: HashMap::new(),
            used_imported_names: HashSet::new(),
            circom_lib_dirs: Vec::new(),
            circom_namespaces: HashMap::new(),
            circom_template_aliases: HashMap::new(),
            current_span: None,
            warnings: Vec::new(),
            known_methods,
            fn_decl_asts: Vec::new(),
            resolver_outer_functions: None,
            prime_id: memory::field::PrimeId::Bn254,
            resolved_program: None,
            resolver_symbol_table: None,
            resolver_root_module: None,
            current_expr_id: None,
            resolver_hits: Vec::new(),
            resolver_dispatch_by_symbol: None,
            resolver_module_by_key: None,
            resolver_availability_map: None,
        }
    }
}
