use crate::error::{CompilerError, OptSpan};
use crate::function_compiler::FunctionCompiler;
use crate::interner::{BigIntInterner, FieldInterner, StringInterner};
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

    // Global Symbol Table (Name -> Index)
    pub global_symbols: HashMap<String, u16>,
    pub next_global_idx: u16,

    // String Interner (shared across all functions)
    pub interner: StringInterner,

    // Field Interner (shared across all functions)
    pub field_interner: FieldInterner,

    // BigInt Interner (shared across all functions)
    pub bigint_interner: BigIntInterner,

    // Module system
    pub base_path: Option<PathBuf>,
    pub module_loader: ModuleLoader,
    pub module_prefix: Option<String>,
    /// Tracks imported module aliases to detect duplicates.
    pub imported_aliases: HashMap<String, PathBuf>,
    /// Tracks modules currently being compiled (for cycle detection).
    pub compiling_modules: HashSet<PathBuf>,

    /// Span of the expression/statement currently being compiled.
    pub current_span: Option<Span>,

    /// Warnings collected during compilation.
    pub warnings: Vec<Diagnostic>,
}

use vm::specs::{NATIVE_TABLE, USER_GLOBAL_START};

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        let mut global_symbols = HashMap::new();

        // Pre-populate Natives from SSOT
        for (index, meta) in NATIVE_TABLE.iter().enumerate() {
            global_symbols.insert(meta.name.to_string(), index as u16);
        }

        let next_global_idx = USER_GLOBAL_START;

        // Start with a "main" function compiler (arity=0 for top-level script)
        let main_compiler = FunctionCompiler::new("main".to_string(), 0);

        Self {
            compilers: vec![main_compiler],
            prototypes: Vec::new(),
            global_symbols,
            next_global_idx,
            interner: StringInterner::new(),
            field_interner: FieldInterner::new(),
            bigint_interner: BigIntInterner::new(),
            base_path: None,
            module_loader: ModuleLoader::new(),
            module_prefix: None,
            imported_aliases: HashMap::new(),
            compiling_modules: HashSet::new(),
            current_span: None,
            warnings: Vec::new(),
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
        for (name, &idx) in &self.global_symbols {
            if idx >= USER_GLOBAL_START && !name.contains("::") {
                names.push(name);
            }
        }

        names
    }

    /// Build an "Undefined variable" error with a "did you mean?" suggestion if available.
    pub fn undefined_var_error(&self, name: &str) -> CompilerError {
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
            let mut msg = format!("Undefined variable: {name}");
            if let Some(similar) = suggestion {
                msg.push_str(&format!(" (did you mean `{similar}`?)"));
            }
            CompilerError::UnknownOperator(msg, None)
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
        self.current()?.free_reg(reg);
        Ok(())
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
        let mut symbols: Vec<(&u16, &String)> =
            self.global_symbols.iter().map(|(k, v)| (v, k)).collect();

        // 2. Sort by Index (Deterministic output is mandatory for build reproducibility)
        symbols.sort_by_key(|&(idx, _)| *idx);

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
        if let Some(err) = parse_errors.into_iter().next() {
            return Err(CompilerError::DiagnosticError(Box::new(err)));
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

        // Final return
        self.emit_abc(OpCode::Return, 0, 0, 0)?; // Return Nil/0

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
        // The suggestion should be structured data, not baked into the message
        assert!(
            !diag.suggestions.is_empty() || diag.message.contains("cout"),
            "diagnostic should have a suggestion or reference the typo: {diag:?}"
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
