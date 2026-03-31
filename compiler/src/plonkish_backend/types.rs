use constraints::plonkish::CellRef;
use memory::FieldElement;

// ============================================================================
// PlonkVal — lazy representation of SSA values in Plonkish
// ============================================================================

#[derive(Debug, Clone)]
pub enum PlonkVal {
    Cell(CellRef),
    Constant(FieldElement),
    DeferredAdd(Box<PlonkVal>, Box<PlonkVal>),
    DeferredSub(Box<PlonkVal>, Box<PlonkVal>),
    DeferredNeg(Box<PlonkVal>),
}

impl PlonkVal {
    pub(super) fn constant_value(&self) -> Option<FieldElement> {
        match self {
            PlonkVal::Constant(v) => Some(*v),
            _ => None,
        }
    }
}

// ============================================================================
// PlonkWitnessOp — trace for witness generation
// ============================================================================

#[derive(Debug, Clone)]
pub enum PlonkWitnessOp {
    /// Assign a named input value to a cell.
    AssignInput { cell: CellRef, name: String },
    /// Copy value from `from` cell to `to` cell.
    CopyValue { from: CellRef, to: CellRef },
    /// Set a cell to a constant value.
    SetConstant { cell: CellRef, value: FieldElement },
    /// Compute d = a*b + c for a given row.
    ArithRow { row: usize },
    /// Compute b = 1/a for a given row (a is already in col_a).
    /// Errors if a == 0 (used for division).
    InverseRow { row: usize },
    /// IsZero gadget row: if a == 0 then b=0, d=0; else b=1/a, d=1.
    /// Unlike InverseRow, does NOT error when a == 0.
    IsZeroRow { row: usize },
    /// Extract bit `bit_index` from the value in `source` cell and write to `target`.
    /// Field elements are 256 bits (4 × 64-bit limbs), so max bit_index is 255.
    BitExtract {
        target: CellRef,
        source: CellRef,
        bit_index: u32,
    },
    /// Integer division/modulo: q = floor(lhs/rhs), r = lhs - rhs*q.
    IntDivMod {
        q: CellRef,
        r: CellRef,
        lhs: CellRef,
        rhs: CellRef,
    },
}
