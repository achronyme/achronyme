//! Shared test utilities for ProveIR tests.
//!
//! Wraps flat-format circuit source (top-level `public`/`witness` declarations)
//! into `circuit test(...) { body }` syntax so tests continue to work after
//! the flat format was removed from production code.

use memory::Bn254Fr;

use super::compiler::ProveIrCompiler;
use super::error::ProveIrError;
use super::types::ProveIR;

/// Convert a flat declaration like `"arr[3]"` or `"x: Field"` to a circuit param.
fn flat_decl_to_param(decl: &str, vis: &str) -> String {
    if let Some(bracket_pos) = decl.find('[') {
        let name = &decl[..bracket_pos];
        let rest = &decl[bracket_pos..];
        if let Some((size_part, ty)) = rest.split_once(':') {
            format!("{name}: {vis} {}{}", ty.trim(), size_part.trim())
        } else {
            format!("{name}: {vis} Field{rest}")
        }
    } else if let Some((name, ty)) = decl.split_once(':') {
        format!("{}: {vis} {}", name.trim(), ty.trim())
    } else {
        format!("{decl}: {vis}")
    }
}

/// Wrap flat-format source into circuit syntax for testing.
/// If source already starts with `circuit`, returns it as-is.
pub fn wrap_flat_to_circuit(source: &str) -> String {
    let trimmed = source.trim_start();
    if trimmed.starts_with("circuit ") {
        return source.to_string();
    }

    let mut params = Vec::new();
    let mut body_lines = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("public ") {
            for decl in rest.split(',') {
                params.push(flat_decl_to_param(decl.trim(), "Public"));
            }
        } else if let Some(rest) = t.strip_prefix("witness ") {
            for decl in rest.split(',') {
                params.push(flat_decl_to_param(decl.trim(), "Witness"));
            }
        } else {
            body_lines.push(line);
        }
    }

    let params_str = params.join(", ");
    let body_str = body_lines.join("\n");
    format!("circuit test({params_str}) {{\n{body_str}\n}}")
}

/// Compile a flat-format or circuit-format source string as a circuit.
pub fn compile_circuit(source: &str) -> Result<ProveIR, ProveIrError> {
    let wrapped = wrap_flat_to_circuit(source);
    ProveIrCompiler::<Bn254Fr>::compile_circuit(&wrapped, None)
}
