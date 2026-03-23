use achronyme_parser::ast::{Span, TypeAnnotation};

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
