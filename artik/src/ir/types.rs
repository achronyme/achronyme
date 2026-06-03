/// Integer width for bit-exact ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntW {
    U8 = 0,
    U32 = 1,
    U64 = 2,
    I64 = 3,
}

impl IntW {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::U8),
            1 => Some(Self::U32),
            2 => Some(Self::U64),
            3 => Some(Self::I64),
            _ => None,
        }
    }

    /// Mask applied to wrapping arithmetic outputs in this width.
    pub fn mask(self) -> u64 {
        match self {
            Self::U8 => 0xFF,
            Self::U32 => 0xFFFF_FFFF,
            Self::U64 | Self::I64 => u64::MAX,
        }
    }
}

/// Element type for arrays allocated inside Artik.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ElemT {
    Field = 0,
    IntU8 = 1,
    IntU32 = 2,
    IntU64 = 3,
    IntI64 = 4,
}

impl ElemT {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Field),
            1 => Some(Self::IntU8),
            2 => Some(Self::IntU32),
            3 => Some(Self::IntU64),
            4 => Some(Self::IntI64),
            _ => None,
        }
    }
}

/// Type category carried by a register. Validation tracks one of these
/// per register and rejects reuse with a different category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegType {
    Field,
    Int(IntW),
    /// Handle to an array. `elem` is the element category; registers of
    /// this type cannot participate in field/int arithmetic.
    Array(ElemT),
}

impl RegType {
    /// Two-byte wire encoding: a kind byte plus a sub-discriminant
    /// (the int width or the array element category; unused for
    /// `Field`). Used in the subprogram parameter / return lists.
    pub fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Field => [0, 0],
            Self::Int(w) => [1, w as u8],
            Self::Array(e) => [2, e as u8],
        }
    }

    /// Inverse of [`Self::to_bytes`]. Returns `None` if either byte is
    /// out of range for its position.
    pub fn from_bytes(kind: u8, sub: u8) -> Option<Self> {
        match kind {
            0 => Some(Self::Field),
            1 => Some(Self::Int(IntW::from_u8(sub)?)),
            2 => Some(Self::Array(ElemT::from_u8(sub)?)),
            _ => None,
        }
    }
}

/// Integer binary operation subcategory. Used with `Instr::IBin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntBinOp {
    Add = 0,
    Sub = 1,
    Mul = 2,
    And = 3,
    Or = 4,
    Xor = 5,
    Shl = 6,
    Shr = 7,
    CmpLt = 8,
    CmpEq = 9,
}

impl IntBinOp {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Add),
            1 => Some(Self::Sub),
            2 => Some(Self::Mul),
            3 => Some(Self::And),
            4 => Some(Self::Or),
            5 => Some(Self::Xor),
            6 => Some(Self::Shl),
            7 => Some(Self::Shr),
            8 => Some(Self::CmpLt),
            9 => Some(Self::CmpEq),
            _ => None,
        }
    }

    /// Does this op produce a boolean (0 or 1) regardless of operand width?
    pub fn is_boolean(self) -> bool {
        matches!(self, Self::CmpLt | Self::CmpEq)
    }
}
