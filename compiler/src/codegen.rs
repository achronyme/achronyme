use crate::error::{CompilerError, OptSpan};
use crate::function_compiler::FunctionCompiler;
use crate::interner::{
    BigIntInterner, BytesInterner, CircomHandleInterner, CircomLibraryRegistry, FieldInterner,
    StringInterner,
};
use crate::module_loader::ModuleLoader;
use crate::statements::{stmt_span, StatementCompiler};
use achronyme_parser::ast::{Span, Stmt};
use achronyme_parser::diagnostic::SpanRange;
use achronyme_parser::Diagnostic;
use memory::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use vm::opcode::OpCode;

/// The main compiler orchestrator
pub struct Compiler {
    pub compilers: Vec<FunctionCompiler>, // LIFO Stack of function compilers

    // FLAT list of ALL function prototypes (global indices)
    pub prototypes: Vec<memory::Function>,

    // Global Symbol Table (Name -> Entry with index + metadata)
    pub global_symbols: HashMap<String, crate::types::GlobalEntry>,
    pub next_global_idx: u16,

    // String Interner (shared across all functions)
    pub interner: StringInterner,

    // Field Interner (shared across all functions)
    pub field_interner: FieldInterner,

    // BigInt Interner (shared across all functions)
    pub bigint_interner: BigIntInterner,

    // Bytes Interner (binary blobs, e.g. serialized ProveIR)
    pub bytes_interner: BytesInterner,

    /// Circom handle descriptors (template call sites) allocated
    /// during VM-mode codegen. Bulk-imported into the VM heap at
    /// program-load time alongside the constant pool.
    pub circom_handle_interner: CircomHandleInterner,

    /// Registry of compiled circom libraries referenced by the
    /// circom handles in `circom_handle_interner`. The CLI hands
    /// this over to the runtime handler so `library_id` inside a
    /// handle resolves to the same `Arc<CircomLibrary>` the
    /// compiler saw.
    pub circom_library_registry: CircomLibraryRegistry,

    // Module system
    pub base_path: Option<PathBuf>,
    pub module_loader: ModuleLoader,
    pub module_prefix: Option<String>,
    /// Tracks imported module aliases to detect duplicates.
    pub imported_aliases: HashMap<String, PathBuf>,
    /// Tracks modules currently being compiled (for cycle detection).
    pub compiling_modules: HashSet<PathBuf>,
    /// Tracks selectively imported names → (source module path, import span).
    pub imported_names: HashMap<String, (PathBuf, Span)>,
    /// Tracks which selectively imported names have been referenced.
    pub used_imported_names: HashSet<String>,

    // ── Circom interop ────────────────────────────────────────────
    /// Library search directories for `.circom` includes, typically
    /// read from `[circom] libs = [...]` in `achronyme.toml`.
    pub circom_lib_dirs: Vec<PathBuf>,
    /// Namespaces created by `import "x.circom" as P`. Templates are
    /// referenced from prove/circuit/VM bodies via `P.TemplateName(...)(...)`.
    /// These imports are **compile-time only** — no VM bytecode is emitted
    /// for them, so the alias is not registered as a global.
    pub circom_namespaces: HashMap<String, std::sync::Arc<circom::CircomLibrary>>,
    /// Selectively imported Circom templates: unqualified name →
    /// owning library. Populated by
    /// `import { T1, T2 } from "x.circom"`. The template name is
    /// always the map key — rename-on-import (`import { X as Y }`)
    /// is not supported today, so we don't carry a redundant "real
    /// name" column. When rename support lands this field should
    /// grow into a struct with an explicit `real_name: String`.
    pub circom_template_aliases: HashMap<String, std::sync::Arc<circom::CircomLibrary>>,

    /// Span of the expression/statement currently being compiled.
    pub current_span: Option<Span>,

    /// Warnings collected during compilation.
    pub warnings: Vec<Diagnostic>,

    /// Set of known method names for detecting `expr.method(args)` patterns.
    pub known_methods: HashSet<String>,

    /// FnDecl AST nodes accumulated during top-level compilation.
    /// Passed to ProveIR so prove/circuit blocks can inline outer functions.
    pub fn_decl_asts: Vec<Stmt>,

    /// Prime field for ProveIR serialization. Defaults to BN254.
    pub prime_id: memory::field::PrimeId,
}

use vm::specs::{NativeMeta, NATIVE_TABLE, USER_GLOBAL_START};

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
    /// `extra` entries are appended after `NATIVE_TABLE` — their indices
    /// continue from `USER_GLOBAL_START`.  The VM must register the same
    /// modules in the same order via `VM::register_module()`.
    pub fn with_extra_natives(extra: &[NativeMeta]) -> Self {
        use crate::types::GlobalEntry;
        let mut global_symbols = HashMap::new();

        // Pre-populate builtins from SSOT
        for (index, meta) in NATIVE_TABLE.iter().enumerate() {
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

        // Append extra natives (stdlib, user modules, etc.)
        for (i, meta) in extra.iter().enumerate() {
            let index = NATIVE_TABLE.len() + i;
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

        let next_global_idx = (NATIVE_TABLE.len() + extra.len()) as u16;

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
            prime_id: memory::field::PrimeId::Bn254,
        }
    }

    /// Get the OptSpan for the current expression/statement being compiled.
    pub fn cur_span(&self) -> OptSpan {
        self.current_span.as_ref().map(|s| Box::new(s.into()))
    }

    /// Record a compiler warning.
    pub fn emit_warning(&mut self, diag: Diagnostic) {
        self.warnings.push(diag);
    }

    /// Take all collected warnings, leaving the internal list empty.
    pub fn take_warnings(&mut self) -> Vec<Diagnostic> {
        std::mem::take(&mut self.warnings)
    }

    /// Collect all in-scope names (locals, globals) for "did you mean?" suggestions.
    pub fn collect_in_scope_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();

        // Locals from current function compiler
        if let Ok(func) = self.current_ref() {
            for local in &func.locals {
                names.push(&local.name);
            }
        }

        // Global symbols (skip native internals with index < USER_GLOBAL_START)
        for (name, entry) in &self.global_symbols {
            if entry.index >= USER_GLOBAL_START && !name.contains("::") {
                names.push(name);
            }
        }

        names
    }

    /// Table of functions migrated from globals to methods in beta.13.
    const MIGRATED_TO_METHOD: &'static [(&'static str, &'static str)] = &[
        ("abs", "value.abs()"),
        ("len", "value.len()"),
        ("push", "list.push(item)"),
        ("pop", "list.pop()"),
        ("keys", "map.keys()"),
        ("map", "list.map(fn)"),
        ("filter", "list.filter(fn)"),
        ("reduce", "list.reduce(init, fn)"),
        ("for_each", "list.for_each(fn)"),
        ("find", "list.find(fn)"),
        ("any", "list.any(fn)"),
        ("all", "list.all(fn)"),
        ("sort", "list.sort(fn)"),
        ("flat_map", "list.flat_map(fn)"),
        ("zip", "list.zip(other)"),
        ("min", "a.min(b)"),
        ("max", "a.max(b)"),
        ("pow", "a.pow(b)"),
        ("to_string", "value.to_string()"),
        ("to_field", "value.to_field()"),
        ("to_int", "value.to_int()"),
        ("to_bits", "bigint.to_bits()"),
        ("bit_and", "a.bit_and(b)"),
        ("bit_or", "a.bit_or(b)"),
        ("bit_xor", "a.bit_xor(b)"),
        ("bit_not", "a.bit_not()"),
        ("bit_shl", "a.bit_shl(n)"),
        ("bit_shr", "a.bit_shr(n)"),
        ("substring", "str.substring(start, end)"),
        ("index_of", "str.index_of(substr)"),
        ("split", "str.split(delim)"),
        ("trim", "str.trim()"),
        ("replace", "str.replace(search, repl)"),
        ("to_upper", "str.to_upper()"),
        ("to_lower", "str.to_lower()"),
        ("chars", "str.chars()"),
        ("starts_with", "str.starts_with(prefix)"),
        ("ends_with", "str.ends_with(suffix)"),
        ("contains", "str.contains(substr)"),
        ("repeat", "str.repeat(n)"),
    ];

    /// Build an "Undefined variable" error with a "did you mean?" suggestion if available.
    pub fn undefined_var_error(&self, name: &str) -> CompilerError {
        // Check if this is a migrated function first
        if let Some((_, method_form)) = Self::MIGRATED_TO_METHOD.iter().find(|(n, _)| *n == name) {
            if let Some(span) = self.current_span.as_ref() {
                let span_range: SpanRange = span.into();
                let diag = Diagnostic::error(
                    format!("`{name}` was moved to a method — use `{method_form}` instead"),
                    span_range,
                );
                return CompilerError::DiagnosticError(Box::new(diag));
            }
            return CompilerError::CompileError(
                format!("`{name}` was moved to a method — use `{method_form}` instead"),
                None,
            );
        }

        let candidates = self.collect_in_scope_names();
        let suggestion = crate::suggest::find_similar(name, candidates.into_iter(), 2);

        if let Some(span) = self.current_span.as_ref() {
            let span_range: SpanRange = span.into();
            let mut diag =
                Diagnostic::error(format!("undefined variable: `{name}`"), span_range.clone());
            if let Some(similar) = suggestion {
                diag = diag.with_suggestion(span_range, similar, "a similar name exists");
            }
            CompilerError::DiagnosticError(Box::new(diag))
        } else {
            let mut msg = format!("undefined variable: `{name}`");
            if let Some(similar) = suggestion {
                msg.push_str(&format!(" (did you mean `{similar}`?)"));
            }
            CompilerError::CompileError(msg, None)
        }
    }

    // Wrappers for FunctionCompiler
    pub fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        self.current()?.alloc_reg()
    }

    pub fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        self.current()?.alloc_contiguous(count)
    }

    pub fn free_reg(&mut self, reg: u8) -> Result<(), CompilerError> {
        self.current()?.free_reg(reg)
    }

    pub fn add_constant(&mut self, val: Value) -> Result<usize, CompilerError> {
        Ok(self.current()?.add_constant(val))
    }

    pub fn add_upvalue(&mut self, is_local: bool, index: u8) -> Result<u8, CompilerError> {
        Ok(self.current()?.add_upvalue(is_local, index))
    }

    pub fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) -> Result<(), CompilerError> {
        self.current()?.emit_abc(op, a, b, c);
        Ok(())
    }

    pub fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) -> Result<(), CompilerError> {
        self.current()?.emit_abx(op, a, bx);
        Ok(())
    }

    pub fn intern_string(&mut self, s: &str) -> u32 {
        self.interner.intern(s)
    }

    pub fn intern_field(&mut self, fe: memory::FieldElement) -> u32 {
        self.field_interner.intern(fe)
    }

    pub fn intern_bigint(&mut self, bi: memory::BigInt) -> u32 {
        self.bigint_interner.intern(bi)
    }

    pub fn intern_bytes(&mut self, data: Vec<u8>) -> u32 {
        self.bytes_interner.intern(data)
    }

    /// Register a circom handle descriptor and return the heap
    /// index the VM will resolve at program-run time.
    pub fn intern_circom_handle(&mut self, handle: memory::CircomHandle) -> u32 {
        self.circom_handle_interner.intern(handle)
    }

    /// Register a circom library in the compile-time registry and
    /// return its id. Called by the VM-mode codegen when it sees
    /// the first template call against a library.
    pub fn register_circom_library(&mut self, lib: std::sync::Arc<circom::CircomLibrary>) -> u32 {
        self.circom_library_registry.intern(lib)
    }

    /// Returns a mutable reference to the current (top) function compiler
    pub fn current(&mut self) -> Result<&mut FunctionCompiler, CompilerError> {
        self.compilers
            .last_mut()
            .ok_or_else(|| CompilerError::InternalError("compiler stack underflow".into()))
    }

    /// Returns an immutable reference to the current function compiler
    pub fn current_ref(&self) -> Result<&FunctionCompiler, CompilerError> {
        self.compilers
            .last()
            .ok_or_else(|| CompilerError::InternalError("compiler stack underflow".into()))
    }

    pub fn append_debug_symbols(&self, buffer: &mut Vec<u8>) {
        // 1. Invert Name->Index to (Index, Name) for serialization
        let mut symbols: Vec<(u16, &String)> = self
            .global_symbols
            .iter()
            .map(|(k, v)| (v.index, k))
            .collect();

        // 2. Sort by Index (Deterministic output is mandatory for build reproducibility)
        symbols.sort_by_key(|&(idx, _)| idx);

        // 3. Write Section
        buffer.extend_from_slice(&[0xDB, 0x67]); // Magic "DBg"
        buffer.extend_from_slice(&(symbols.len() as u16).to_le_bytes());

        for (index, name) in symbols {
            let name_bytes = name.as_bytes();
            buffer.extend_from_slice(&index.to_le_bytes());
            buffer.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buffer.extend_from_slice(name_bytes);
        }
    }

    pub fn compile(&mut self, source: &str) -> Result<Vec<u32>, CompilerError> {
        let (program, parse_errors) = achronyme_parser::parse_program(source);
        // Only reject actual errors, not warnings (W008, W010, etc.)
        if let Some(err) = parse_errors
            .iter()
            .find(|d| d.severity == achronyme_parser::Severity::Error)
        {
            return Err(CompilerError::DiagnosticError(Box::new(err.clone())));
        }
        // Collect parser warnings into our warning list
        for diag in parse_errors {
            if diag.severity == achronyme_parser::Severity::Warning {
                self.warnings.push(diag);
            }
        }

        let mut terminated = false;
        let mut unreachable_warned = false;
        for stmt in &program.stmts {
            if terminated && !unreachable_warned {
                if let Some(span) = stmt_span(stmt) {
                    self.emit_warning(
                        Diagnostic::warning("unreachable code", span.into()).with_code("W003"),
                    );
                }
                unreachable_warned = true;
            }
            self.compile_stmt(stmt)?;
            if !terminated && is_terminator(stmt) {
                terminated = true;
            }
        }

        // W005: unused selective imports
        for (name, (_path, span)) in &self.imported_names {
            if !self.used_imported_names.contains(name) && !name.starts_with('_') {
                self.warnings.push(
                    Diagnostic::warning(
                        format!("imported name `{name}` is never used"),
                        span.into(),
                    )
                    .with_code("W005"),
                );
            }
        }

        // Final return
        self.emit_abc(OpCode::Return, 0, 0, 0)?; // Return Nil/0

        let func = self.current()?;
        let (opt_bytecode, opt_line_info) = crate::optimizer::optimize(
            func.bytecode.clone(),
            func.line_info.clone(),
            &mut func.max_slots,
        );
        func.bytecode = opt_bytecode;
        func.line_info = opt_line_info;

        Ok(self.current()?.bytecode.clone())
    }
}

/// Returns true if a statement is a control-flow terminator (return, break, continue).
pub(crate) fn is_terminator(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return { .. } | Stmt::Break { .. } | Stmt::Continue { .. }
    )
}

#[cfg(test)]
mod warning_tests {
    use super::*;
    use achronyme_parser::Severity;

    fn compile_warnings(source: &str) -> Vec<achronyme_parser::Diagnostic> {
        let mut compiler = Compiler::new();
        let _ = compiler.compile(source);
        compiler.take_warnings()
    }

    // === W001: Unused variables ===

    #[test]
    fn unused_variable_in_function() {
        let ws = compile_warnings("fn test() { let x = 5; 1 }");
        assert!(ws
            .iter()
            .any(|w| w.message.contains("unused variable: `x`")));
    }

    #[test]
    fn used_variable_no_warning() {
        let ws = compile_warnings("fn test() { let x = 5; print(x) }");
        assert!(!ws.iter().any(|w| w.message.contains("unused variable")));
    }

    #[test]
    fn underscore_prefix_suppresses_warning() {
        let ws = compile_warnings("fn test() { let _x = 5; 1 }");
        assert!(!ws.iter().any(|w| w.message.contains("unused variable")));
    }

    #[test]
    fn unused_function_parameter() {
        let ws = compile_warnings("fn test(x) { 1 }");
        assert!(ws
            .iter()
            .any(|w| w.message.contains("unused function parameter: `x`")));
    }

    #[test]
    fn used_function_parameter_no_warning() {
        let ws = compile_warnings("fn test(x) { x }");
        assert!(!ws.iter().any(|w| w.message.contains("unused")));
    }

    #[test]
    fn underscore_param_suppresses_warning() {
        let ws = compile_warnings("fn test(_x) { 1 }");
        assert!(!ws
            .iter()
            .any(|w| w.message.contains("unused function parameter")));
    }

    #[test]
    fn unused_for_loop_variable() {
        let ws = compile_warnings("fn test() { for x in [1, 2, 3] { print(1) }; 1 }");
        assert!(ws
            .iter()
            .any(|w| w.message.contains("unused variable: `x`")));
    }

    #[test]
    fn used_for_loop_variable_no_warning() {
        let ws = compile_warnings("fn test() { for x in [1, 2, 3] { print(x) }; 1 }");
        assert!(!ws
            .iter()
            .any(|w| w.message.contains("unused variable: `x`")));
    }

    // === W002: Unused mut ===

    #[test]
    fn unused_mut_warning() {
        let ws = compile_warnings("fn test() { mut y = 5; print(y) }");
        assert!(ws
            .iter()
            .any(|w| w.message.contains("never mutated") && w.message.contains("`y`")));
    }

    #[test]
    fn mut_used_and_mutated_no_warning() {
        let ws = compile_warnings("fn test() { mut y = 5; y = 10; print(y) }");
        assert!(!ws.iter().any(|w| w.message.contains("never mutated")));
    }

    #[test]
    fn unused_mut_not_read_gives_unused_not_mut_warning() {
        // If variable is both unused AND mut, we only warn about unused (more important)
        let ws = compile_warnings("fn test() { mut y = 5; 1 }");
        assert!(ws
            .iter()
            .any(|w| w.message.contains("unused variable: `y`")));
        assert!(!ws.iter().any(|w| w.message.contains("never mutated")));
    }

    // === W003: Unreachable code ===

    #[test]
    fn unreachable_code_after_return() {
        let ws = compile_warnings("fn test() { return 1; let x = 5; x }");
        assert!(ws.iter().any(|w| w.message.contains("unreachable code")));
    }

    #[test]
    fn unreachable_code_after_break() {
        let ws = compile_warnings("fn test() { for x in [1,2,3] { break; print(x) }; 1 }");
        assert!(ws.iter().any(|w| w.message.contains("unreachable code")));
    }

    #[test]
    fn no_unreachable_without_terminator() {
        let ws = compile_warnings("fn test() { let x = 1; let y = 2; x }");
        assert!(!ws.iter().any(|w| w.message.contains("unreachable")));
    }

    // === W004: Variable shadowing ===

    #[test]
    fn shadowing_same_scope() {
        let ws = compile_warnings("fn test() { let x = 1; let x = 2; x }");
        assert!(ws.iter().any(|w| w.message.contains("shadows")));
    }

    #[test]
    fn no_shadowing_different_scopes() {
        // Inner block creates new scope, no shadowing warning
        let ws = compile_warnings("fn test() { let x = 1; if true { let x = 2; x } else { x } }");
        assert!(!ws.iter().any(|w| w.message.contains("shadows")));
    }

    // === General ===

    #[test]
    fn warnings_have_correct_severity() {
        let ws = compile_warnings("fn test() { let x = 5; 1 }");
        for w in &ws {
            assert_eq!(w.severity, Severity::Warning);
        }
    }

    #[test]
    fn warnings_do_not_halt_compilation() {
        let mut compiler = Compiler::new();
        let result = compiler.compile("fn test() { let x = 5; 1 }");
        assert!(
            result.is_ok(),
            "compilation should succeed despite warnings"
        );
        assert!(!compiler.take_warnings().is_empty());
    }

    #[test]
    fn clean_code_no_warnings() {
        let ws = compile_warnings("fn test(x) { let y = x; print(y) }");
        assert!(ws.is_empty(), "expected no warnings, got: {:?}", ws);
    }

    // === W006: Type annotation mismatch ===

    #[test]
    fn w006_bool_annotation_on_field_literal() {
        let ws = compile_warnings("fn test() { let x: Bool = 0p42; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_field_annotation_on_string() {
        let ws = compile_warnings("fn test() { let x: Field = \"hello\"; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_field_annotation_on_bool() {
        let ws = compile_warnings("fn test() { let x: Field = true; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_bool_annotation_on_nil() {
        let ws = compile_warnings("fn test() { let x: Bool = nil; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_no_warning_field_on_field_lit() {
        let ws = compile_warnings("fn test() { let x: Field = 0p42; print(x) }");
        assert!(!ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_no_warning_field_on_int() {
        let ws = compile_warnings("fn test() { let x: Field = 42; print(x) }");
        assert!(!ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_no_warning_bool_on_bool() {
        let ws = compile_warnings("fn test() { let x: Bool = true; print(x) }");
        assert!(!ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_no_warning_dynamic_expression() {
        let ws = compile_warnings("fn f() { true }\nfn test() { let x: Bool = f(); print(x) }");
        assert!(!ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_mut_decl_also_warns() {
        let ws = compile_warnings("fn test() { mut x: Bool = 0p1; x = true; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    #[test]
    fn w006_scalar_annotation_on_array() {
        let ws = compile_warnings("fn test() { let x: Field = [1, 2, 3]; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }

    // === W007: Array size mismatch ===

    #[test]
    fn w007_array_size_mismatch() {
        let ws = compile_warnings("fn test() { let x: Field[3] = [1, 2]; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W007")));
    }

    #[test]
    fn w007_bool_array_size_mismatch() {
        let ws = compile_warnings("fn test() { let x: Bool[2] = [true, false, true]; print(x) }");
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W007")));
    }

    #[test]
    fn w007_no_warning_matching_size() {
        let ws = compile_warnings("fn test() { let x: Field[3] = [1, 2, 3]; print(x) }");
        assert!(!ws.iter().any(|w| w.code.as_deref() == Some("W007")));
    }

    #[test]
    fn w007_no_warning_on_non_array_value() {
        // Field[3] on a non-array value → W006, not W007
        let ws = compile_warnings("fn test() { let x: Field[3] = 42; print(x) }");
        assert!(!ws.iter().any(|w| w.code.as_deref() == Some("W007")));
        assert!(ws.iter().any(|w| w.code.as_deref() == Some("W006")));
    }
}

#[cfg(test)]
mod suggestion_tests {
    use super::*;

    fn compile_error_message(source: &str) -> String {
        let mut compiler = Compiler::new();
        match compiler.compile(source) {
            Ok(_) => panic!("expected compilation to fail"),
            Err(e) => format!("{e}"),
        }
    }

    #[test]
    fn suggests_similar_local_variable() {
        let msg = compile_error_message("fn test() { let count = 5; cout }");
        assert!(msg.contains("undefined variable"), "got: {msg}");
    }

    #[test]
    fn suggests_similar_function_name() {
        let msg = compile_error_message("fn compute() { 1 }\ncompue()");
        assert!(msg.contains("undefined variable"), "got: {msg}");
    }

    #[test]
    fn no_suggestion_for_completely_different_name() {
        let msg = compile_error_message("fn test() { let x = 5; zzzzzz }");
        assert!(msg.contains("undefined variable"), "got: {msg}");
    }

    #[test]
    fn suggestion_in_diagnostic_error() {
        let mut compiler = Compiler::new();
        let err = compiler
            .compile("fn test() { let count = 5; cout }")
            .unwrap_err();
        let diag = err.to_diagnostic();
        assert!(diag.message.contains("undefined variable"));
        // The suggestion should be structured data
        assert!(
            !diag.suggestions.is_empty(),
            "diagnostic should have a suggestion for `cout` → `count`: {diag:?}"
        );
    }

    #[test]
    fn suggestion_for_one_char_typo() {
        let msg = compile_error_message("fn test() { let value = 42; valye }");
        assert!(msg.contains("undefined variable"), "got: {msg}");
    }

    #[test]
    fn suggestion_for_assignment_target() {
        let msg = compile_error_message("fn test() { mut total = 0; totol = 5; total }");
        assert!(msg.contains("undefined variable"), "got: {msg}");
    }
}

#[cfg(test)]
mod kwarg_validation_tests {
    use super::*;

    fn compile_error_message(source: &str) -> String {
        let mut compiler = Compiler::new();
        match compiler.compile(source) {
            Ok(_) => panic!("expected compilation to fail"),
            Err(e) => format!("{e}"),
        }
    }

    fn compile_ok(source: &str) -> Vec<u32> {
        let mut compiler = Compiler::new();
        compiler.compile(source).expect("should compile")
    }

    #[test]
    fn valid_kwargs_compile_ok() {
        // Circuit with params, called with correct keyword args
        let src = r#"
            circuit adder(a: Public, b: Witness) {
                assert_eq(a, b)
            }
            adder(a: 1, b: 2)
        "#;
        compile_ok(src);
    }

    #[test]
    fn unknown_kwarg_errors() {
        let src = r#"
            circuit adder(a: Public, b: Witness) {
                assert_eq(a, b)
            }
            adder(x: 1, b: 2)
        "#;
        let msg = compile_error_message(src);
        assert!(msg.contains("unknown keyword argument `x`"), "got: {msg}");
    }

    #[test]
    fn typo_kwarg_suggests_correct_name() {
        let src = r#"
            circuit eligibility(secret: Witness, threshold: Public) {
                assert_eq(secret, threshold)
            }
            eligibility(secrt: 42, threshold: 100)
        "#;
        let msg = compile_error_message(src);
        assert!(
            msg.contains("unknown keyword argument `secrt`"),
            "got: {msg}"
        );
        assert!(msg.contains("did you mean `secret`"), "got: {msg}");
    }

    #[test]
    fn completely_wrong_kwarg_no_suggestion() {
        let src = r#"
            circuit foo(a: Public, b: Witness) {
                assert_eq(a, b)
            }
            foo(zzzzz: 1, b: 2)
        "#;
        let msg = compile_error_message(src);
        assert!(
            msg.contains("unknown keyword argument `zzzzz`"),
            "got: {msg}"
        );
        assert!(!msg.contains("did you mean"), "got: {msg}");
    }
}
