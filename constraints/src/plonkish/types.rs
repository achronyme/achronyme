use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::Expression;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnKind {
    Fixed,
    Advice,
    Instance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Column {
    pub kind: ColumnKind,
    pub index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellRef {
    pub column: Column,
    pub row: usize,
}

// ============================================================================
// Gate, Lookup, CopyConstraint
// ============================================================================

pub struct Gate<F: FieldBackend = Bn254Fr> {
    pub name: String,
    pub poly: Expression<F>,
}

pub struct Lookup<F: FieldBackend = Bn254Fr> {
    pub name: String,
    /// Optional selector expression: when present, only rows where this evaluates
    /// to non-zero are checked. When absent, falls back to the legacy all-zero skip.
    pub selector: Option<Expression<F>>,
    pub input_exprs: Vec<Expression<F>>,
    pub table_exprs: Vec<Expression<F>>,
}

/// A precomputed lookup table stored as a set of value tuples.
pub struct LookupTable<F: FieldBackend = Bn254Fr> {
    pub name: String,
    pub column: Column,
    pub values: Vec<FieldElement<F>>,
}

pub struct CopyConstraint {
    pub left: CellRef,
    pub right: CellRef,
}
