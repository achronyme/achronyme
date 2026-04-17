//! Diagnostic helpers on the top-level `Compiler` orchestrator:
//! span capture, warning emission, in-scope-name collection for
//! "did you mean?" suggestions, and the `undefined_var_error`
//! constructor that wraps all of the above.
//!
//! Kept as a separate `impl Compiler` block so the main `compile`
//! entry and the constructor helpers stay readable. The migration
//! table here is the authoritative "function → method" map used by
//! `undefined_var_error` to upgrade plain "undefined variable" errors
//! into actionable hints whenever the user types the pre-beta.13
//! global form of a now-method.

use achronyme_parser::diagnostic::SpanRange;
use achronyme_parser::Diagnostic;

use super::Compiler;
use crate::error::{CompilerError, OptSpan};

impl Compiler {
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

        // Global symbols (skip native builtins)
        for (name, entry) in &self.global_symbols {
            if entry.index >= self.native_count && !name.contains("::") {
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
}
