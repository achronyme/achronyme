use achronyme_parser::ast::{Span, TypeAnnotation};

/// Best-effort compile-time type for a register. Used to select specialized
/// opcodes (e.g. `AddInt` instead of `Add`) when both operands are known Int.
///
/// `Unknown` means the compiler can't determine the type — generic opcodes
/// are emitted (always correct, just slower).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegType {
    Int,
    Field,
    Bool,
    String,
    Unknown,
}

impl RegType {
    /// Derive register type from a type annotation (scalars only, arrays → Unknown).
    pub fn from_annotation(ann: &TypeAnnotation) -> Self {
        if ann.is_array() {
            return RegType::Unknown;
        }
        match ann.base {
            achronyme_parser::ast::BaseType::Int => RegType::Int,
            achronyme_parser::ast::BaseType::Field => RegType::Field,
            achronyme_parser::ast::BaseType::Bool => RegType::Bool,
            achronyme_parser::ast::BaseType::String => RegType::String,
        }
    }
}

pub struct Local {
    pub name: String,
    pub depth: u32,
    pub is_captured: bool,
    pub is_mutable: bool,
    pub is_read: bool,
    pub is_mutated: bool,
    pub reg: u8,
    pub span: Option<Span>,
    pub type_ann: Option<TypeAnnotation>,
}

/// Metadata for a global symbol (variable, function, circuit, import).
#[derive(Debug, Clone)]
pub struct GlobalEntry {
    pub index: u16,
    pub type_ann: Option<TypeAnnotation>,
    pub is_mutable: bool,
    /// Parameter names for circuit declarations (used for keyword arg validation).
    pub param_names: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpvalueInfo {
    pub is_local: bool,
    pub index: u8,
}

#[derive(Debug, Clone)]
pub struct LoopContext {
    pub scope_depth: u32,
    pub start_label: usize,
    pub break_jumps: Vec<usize>,
}
