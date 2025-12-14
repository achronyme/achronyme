//! OpCode definitions for the Achronyme VM
//!
//! This module defines the complete instruction set for the VM.
//! Instructions are encoded as 32-bit values with the following formats:
//!
//! Format ABC: [8-bit opcode][8-bit A][8-bit B][8-bit C]
//! Format ABx: [8-bit opcode][8-bit A][16-bit Bx]
//!
//! Register-based instructions use A, B, C as register indices (0-255).

use std::fmt;

/// Virtual machine instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    // ===== Constants & Moves =====
    /// Load constant from pool: R[A] = K[Bx]
    LoadConst = 0,
    /// Load null: R[A] = null
    LoadNull = 1,
    /// Load true: R[A] = true
    LoadTrue = 2,
    /// Load false: R[A] = false
    LoadFalse = 3,
    /// Load immediate 8-bit integer: R[A] = Bx (as f64)
    LoadImmI8 = 4,
    /// Move register: R[A] = R[B]
    Move = 5,

    // ===== Arithmetic =====
    /// Addition: R[A] = R[B] + R[C]
    Add = 10,
    /// Subtraction: R[A] = R[B] - R[C]
    Sub = 11,
    /// Multiplication: R[A] = R[B] * R[C]
    Mul = 12,
    /// Division: R[A] = R[B] / R[C]
    Div = 13,
    /// Modulo: R[A] = R[B] % R[C]
    Mod = 14,
    /// Power: R[A] = R[B] ^ R[C]
    Pow = 15,
    /// Negation: R[A] = -R[B]
    Neg = 16,

    // ===== Comparison =====
    /// Equal: R[A] = R[B] == R[C]
    Eq = 20,
    /// Not equal: R[A] = R[B] != R[C]
    Ne = 21,
    /// Less than: R[A] = R[B] < R[C]
    Lt = 22,
    /// Less or equal: R[A] = R[B] <= R[C]
    Le = 23,
    /// Greater than: R[A] = R[B] > R[C]
    Gt = 24,
    /// Greater or equal: R[A] = R[B] >= R[C]
    Ge = 25,

    // ===== Logical =====
    /// Logical NOT: R[A] = !R[B]
    Not = 30,
    /// Logical AND (short-circuit): R[A] = R[B] && R[C]
    And = 31,
    /// Logical OR (short-circuit): R[A] = R[B] || R[C]
    Or = 32,

    // ===== Jumps & Branches =====
    /// Unconditional jump: IP += sBx (signed)
    Jump = 40,
    /// Jump if true: if R[A] then IP += sBx
    JumpIfTrue = 41,
    /// Jump if false: if !R[A] then IP += sBx
    JumpIfFalse = 42,
    /// Jump if null: if R[A] == null then IP += sBx
    JumpIfNull = 43,

    // ===== Functions =====
    /// Create closure: R[A] = closure(proto[Bx])
    Closure = 50,
    /// Call function: R[A] = R[B](R[B+1], ..., R[B+C])
    Call = 51,
    /// Call method: R[A] = R[B]:method(R[B+1], ..., R[B+C])
    CallMethod = 52,
    /// Tail call: replace current frame with R[B](R[B+1], ..., R[B+C])
    TailCall = 53,
    /// Return: return R[A]
    Return = 54,
    /// Return null: return null
    ReturnNull = 55,

    // ===== Records =====
    /// New empty record: R[A] = {}
    NewRecord = 60,
    /// Get field: R[A] = R[B][K[C]]
    GetField = 61,
    /// Set field: R[A][K[B]] = R[C]
    SetField = 62,
    /// Set mutable field: R[A][K[B]] = R[C] (mutable)
    SetFieldMut = 63,
    /// Spread record: spread R[B] into R[A]
    RecordSpread = 64,

    // ===== Vectors/Arrays =====
    /// New empty vector: R[A] = []
    NewVector = 70,
    /// Push to vector: R[A].push(R[B])
    VecPush = 71,
    /// Get element: R[A] = R[B][R[C]]
    VecGet = 72,
    /// Set element: R[A][R[B]] = R[C]
    VecSet = 73,
    /// Spread vector: spread R[B] into R[A]
    VecSpread = 74,
    /// Slice vector: R[A] = R[B][R[C]..R[D]]
    VecSlice = 75,

    // ===== Tensors =====
    /// New tensor: R[A] = tensor(rank, dims...)
    NewTensor = 80,
    /// Get tensor element: R[A] = R[B][indices...]
    TensorGet = 81,
    /// Set tensor element: R[A][indices...] = R[B]
    TensorSet = 82,
    /// Slice tensor: R[A] = R[B][ranges...]
    TensorSlice = 83,

    // ===== Variables =====
    /// Get global: R[A] = globals[K[Bx]]
    GetGlobal = 90,
    /// Set global: globals[K[Bx]] = R[A]
    SetGlobal = 91,
    /// Get upvalue: R[A] = upvalues[B]
    GetUpvalue = 92,
    /// Set upvalue: upvalues[B] = R[A]
    SetUpvalue = 93,
    /// Get local: R[A] = locals[B]
    GetLocal = 94,
    /// Set local: locals[B] = R[A]
    SetLocal = 95,
    /// Make mutable reference: R[A] = MutableRef(R[B])
    MakeMutRef = 96,
    /// Dereference: R[A] = *R[B]
    Deref = 97,

    // ===== Pattern Matching =====
    /// Match type: R[A] = typeof(R[B]) == K[C]
    MatchType = 100,
    /// Match literal: R[A] = R[B] == K[C]
    MatchLit = 101,
    /// Destructure record: destructure R[B] to R[A].. using pattern K[C]
    DestructureRec = 102,
    /// Destructure vector: destructure R[B] to R[A].. using pattern K[C]
    DestructureVec = 103,

    // ===== Generators =====
    /// Create generator: R[A] = Generator(proto[Bx])
    CreateGen = 110,
    /// Yield value: suspend and return R[A]
    Yield = 111,
    /// Resume generator: R[A] = R[B].next()
    ResumeGen = 112,
    /// Make iterator: R[A] = MakeIterator(R[B])
    /// Wraps vectors/strings in native iterators, passes generators through
    MakeIterator = 113,
    /// Await future: R[A] = await R[B]
    Await = 114,

    // ===== Error Handling =====
    /// Throw error: throw R[A]
    Throw = 120,
    /// Push exception handler: push handler at IP + sBx
    PushHandler = 121,
    /// Pop exception handler
    PopHandler = 122,
    /// Make error: R[A] = Error{msg: R[B], kind: R[C]}
    MakeError = 123,

    // ===== Control Flow =====
    /// Break loop: break with optional value R[A]
    Break = 130,
    /// Continue loop
    Continue = 131,

    // ===== Complex Numbers =====
    /// New complex: R[A] = Complex(R[B], R[C])
    NewComplex = 140,
    /// Get real part: R[A] = R[B].re
    ComplexRe = 141,
    /// Get imaginary part: R[A] = R[B].im
    ComplexIm = 142,

    // ===== Edges (Graph) =====
    /// New edge: R[A] = Edge{from: R[B], to: R[C], directed: K[D]}
    NewEdge = 150,
    /// Set edge property: R[A].props[K[B]] = R[C]
    EdgeSetProp = 151,

    // ===== Ranges =====
    /// Exclusive range: R[A] = R[B]..R[C]
    RangeEx = 160,
    /// Inclusive range: R[A] = R[B]..=R[C]
    RangeIn = 161,

    // ===== Built-in Functions =====
    /// Call built-in: R[A] = builtin[Bx](R[B], ..., R[B+C])
    CallBuiltin = 170,

    // ===== Higher-Order Functions (HOF) =====
    /// Initialize iterator: R[A] = Iterator(R[B])
    IterInit = 200,
    /// Get next from iterator: R[A] = R[B].next(), jump if exhausted
    IterNext = 201,
    /// Initialize builder: R[A] = Builder(hint: R[B])
    BuildInit = 202,
    /// Push to builder: R[A].push(R[B])
    BuildPush = 203,
    /// Finalize builder: R[A] = R[B].finalize()
    BuildEnd = 204,

    // ===== Type Operations =====
    /// Type check: R[A] = check_type(R[B], K[C])
    TypeCheck = 180,
    /// Type assert: assert_type(R[A], K[B]) or throw
    TypeAssert = 181,

    // ===== String Operations =====
    /// String concatenation: R[A] = R[B] + R[C]
    StrConcat = 190,
    /// String interpolation: R[A] = interpolate(R[B]...)
    StrInterp = 191,

    // ===== Debugging =====
    /// Debug print: print R[A]
    DebugPrint = 250,
    /// Breakpoint for debugger
    Breakpoint = 251,

    // ===== Special =====
    /// No operation
    Nop = 255,
}

impl OpCode {
    /// Get opcode from byte value
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(OpCode::LoadConst),
            1 => Some(OpCode::LoadNull),
            2 => Some(OpCode::LoadTrue),
            3 => Some(OpCode::LoadFalse),
            4 => Some(OpCode::LoadImmI8),
            5 => Some(OpCode::Move),
            10 => Some(OpCode::Add),
            11 => Some(OpCode::Sub),
            12 => Some(OpCode::Mul),
            13 => Some(OpCode::Div),
            14 => Some(OpCode::Mod),
            15 => Some(OpCode::Pow),
            16 => Some(OpCode::Neg),
            20 => Some(OpCode::Eq),
            21 => Some(OpCode::Ne),
            22 => Some(OpCode::Lt),
            23 => Some(OpCode::Le),
            24 => Some(OpCode::Gt),
            25 => Some(OpCode::Ge),
            30 => Some(OpCode::Not),
            31 => Some(OpCode::And),
            32 => Some(OpCode::Or),
            40 => Some(OpCode::Jump),
            41 => Some(OpCode::JumpIfTrue),
            42 => Some(OpCode::JumpIfFalse),
            43 => Some(OpCode::JumpIfNull),
            50 => Some(OpCode::Closure),
            51 => Some(OpCode::Call),
            52 => Some(OpCode::CallMethod),
            53 => Some(OpCode::TailCall),
            54 => Some(OpCode::Return),
            55 => Some(OpCode::ReturnNull),
            60 => Some(OpCode::NewRecord),
            61 => Some(OpCode::GetField),
            62 => Some(OpCode::SetField),
            63 => Some(OpCode::SetFieldMut),
            64 => Some(OpCode::RecordSpread),
            70 => Some(OpCode::NewVector),
            71 => Some(OpCode::VecPush),
            72 => Some(OpCode::VecGet),
            73 => Some(OpCode::VecSet),
            74 => Some(OpCode::VecSpread),
            75 => Some(OpCode::VecSlice),
            80 => Some(OpCode::NewTensor),
            81 => Some(OpCode::TensorGet),
            82 => Some(OpCode::TensorSet),
            83 => Some(OpCode::TensorSlice),
            90 => Some(OpCode::GetGlobal),
            91 => Some(OpCode::SetGlobal),
            92 => Some(OpCode::GetUpvalue),
            93 => Some(OpCode::SetUpvalue),
            94 => Some(OpCode::GetLocal),
            95 => Some(OpCode::SetLocal),
            96 => Some(OpCode::MakeMutRef),
            97 => Some(OpCode::Deref),
            100 => Some(OpCode::MatchType),
            101 => Some(OpCode::MatchLit),
            102 => Some(OpCode::DestructureRec),
            103 => Some(OpCode::DestructureVec),
            110 => Some(OpCode::CreateGen),
            111 => Some(OpCode::Yield),
            112 => Some(OpCode::ResumeGen),
            113 => Some(OpCode::MakeIterator),
            114 => Some(OpCode::Await),
            120 => Some(OpCode::Throw),
            121 => Some(OpCode::PushHandler),
            122 => Some(OpCode::PopHandler),
            123 => Some(OpCode::MakeError),
            130 => Some(OpCode::Break),
            131 => Some(OpCode::Continue),
            140 => Some(OpCode::NewComplex),
            141 => Some(OpCode::ComplexRe),
            142 => Some(OpCode::ComplexIm),
            150 => Some(OpCode::NewEdge),
            151 => Some(OpCode::EdgeSetProp),
            160 => Some(OpCode::RangeEx),
            161 => Some(OpCode::RangeIn),
            170 => Some(OpCode::CallBuiltin),
            180 => Some(OpCode::TypeCheck),
            181 => Some(OpCode::TypeAssert),
            190 => Some(OpCode::StrConcat),
            191 => Some(OpCode::StrInterp),
            200 => Some(OpCode::IterInit),
            201 => Some(OpCode::IterNext),
            202 => Some(OpCode::BuildInit),
            203 => Some(OpCode::BuildPush),
            204 => Some(OpCode::BuildEnd),
            250 => Some(OpCode::DebugPrint),
            251 => Some(OpCode::Breakpoint),
            255 => Some(OpCode::Nop),
            _ => None,
        }
    }

    /// Convert opcode to byte value
    #[inline]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Get human-readable name
    pub fn name(self) -> &'static str {
        match self {
            OpCode::LoadConst => "LOAD_CONST",
            OpCode::LoadNull => "LOAD_NULL",
            OpCode::LoadTrue => "LOAD_TRUE",
            OpCode::LoadFalse => "LOAD_FALSE",
            OpCode::LoadImmI8 => "LOAD_IMM_I8",
            OpCode::Move => "MOVE",
            OpCode::Add => "ADD",
            OpCode::Sub => "SUB",
            OpCode::Mul => "MUL",
            OpCode::Div => "DIV",
            OpCode::Mod => "MOD",
            OpCode::Pow => "POW",
            OpCode::Neg => "NEG",
            OpCode::Eq => "EQ",
            OpCode::Ne => "NE",
            OpCode::Lt => "LT",
            OpCode::Le => "LE",
            OpCode::Gt => "GT",
            OpCode::Ge => "GE",
            OpCode::Not => "NOT",
            OpCode::And => "AND",
            OpCode::Or => "OR",
            OpCode::Jump => "JUMP",
            OpCode::JumpIfTrue => "JUMP_IF_TRUE",
            OpCode::JumpIfFalse => "JUMP_IF_FALSE",
            OpCode::JumpIfNull => "JUMP_IF_NULL",
            OpCode::Closure => "CLOSURE",
            OpCode::Call => "CALL",
            OpCode::CallMethod => "CALL_METHOD",
            OpCode::TailCall => "TAIL_CALL",
            OpCode::Return => "RETURN",
            OpCode::ReturnNull => "RETURN_NULL",
            OpCode::NewRecord => "NEW_RECORD",
            OpCode::GetField => "GET_FIELD",
            OpCode::SetField => "SET_FIELD",
            OpCode::SetFieldMut => "SET_FIELD_MUT",
            OpCode::RecordSpread => "RECORD_SPREAD",
            OpCode::NewVector => "NEW_VECTOR",
            OpCode::VecPush => "VEC_PUSH",
            OpCode::VecGet => "VEC_GET",
            OpCode::VecSet => "VEC_SET",
            OpCode::VecSpread => "VEC_SPREAD",
            OpCode::VecSlice => "VEC_SLICE",
            OpCode::NewTensor => "NEW_TENSOR",
            OpCode::TensorGet => "TENSOR_GET",
            OpCode::TensorSet => "TENSOR_SET",
            OpCode::TensorSlice => "TENSOR_SLICE",
            OpCode::GetGlobal => "GET_GLOBAL",
            OpCode::SetGlobal => "SET_GLOBAL",
            OpCode::GetUpvalue => "GET_UPVALUE",
            OpCode::SetUpvalue => "SET_UPVALUE",
            OpCode::GetLocal => "GET_LOCAL",
            OpCode::SetLocal => "SET_LOCAL",
            OpCode::MakeMutRef => "MAKE_MUT_REF",
            OpCode::Deref => "DEREF",
            OpCode::MatchType => "MATCH_TYPE",
            OpCode::MatchLit => "MATCH_LIT",
            OpCode::DestructureRec => "DESTRUCTURE_REC",
            OpCode::DestructureVec => "DESTRUCTURE_VEC",
            OpCode::CreateGen => "CREATE_GEN",
            OpCode::Yield => "YIELD",
            OpCode::ResumeGen => "RESUME_GEN",
            OpCode::MakeIterator => "MAKE_ITERATOR",
            OpCode::Await => "AWAIT",
            OpCode::Throw => "THROW",
            OpCode::PushHandler => "PUSH_HANDLER",
            OpCode::PopHandler => "POP_HANDLER",
            OpCode::MakeError => "MAKE_ERROR",
            OpCode::Break => "BREAK",
            OpCode::Continue => "CONTINUE",
            OpCode::NewComplex => "NEW_COMPLEX",
            OpCode::ComplexRe => "COMPLEX_RE",
            OpCode::ComplexIm => "COMPLEX_IM",
            OpCode::NewEdge => "NEW_EDGE",
            OpCode::EdgeSetProp => "EDGE_SET_PROP",
            OpCode::RangeEx => "RANGE_EX",
            OpCode::RangeIn => "RANGE_IN",
            OpCode::CallBuiltin => "CALL_BUILTIN",
            OpCode::IterInit => "ITER_INIT",
            OpCode::IterNext => "ITER_NEXT",
            OpCode::BuildInit => "BUILD_INIT",
            OpCode::BuildPush => "BUILD_PUSH",
            OpCode::BuildEnd => "BUILD_END",
            OpCode::TypeCheck => "TYPE_CHECK",
            OpCode::TypeAssert => "TYPE_ASSERT",
            OpCode::StrConcat => "STR_CONCAT",
            OpCode::StrInterp => "STR_INTERP",
            OpCode::DebugPrint => "DEBUG_PRINT",
            OpCode::Breakpoint => "BREAKPOINT",
            OpCode::Nop => "NOP",
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Instruction encoding/decoding utilities
pub mod instruction {
    /// Encode instruction in ABC format
    #[inline]
    pub fn encode_abc(opcode: u8, a: u8, b: u8, c: u8) -> u32 {
        ((opcode as u32) << 24) | ((a as u32) << 16) | ((b as u32) << 8) | (c as u32)
    }

    /// Encode instruction in ABx format
    #[inline]
    pub fn encode_abx(opcode: u8, a: u8, bx: u16) -> u32 {
        ((opcode as u32) << 24) | ((a as u32) << 16) | (bx as u32)
    }

    /// Decode instruction opcode
    #[inline]
    pub fn decode_opcode(instruction: u32) -> u8 {
        (instruction >> 24) as u8
    }

    /// Decode A operand
    #[inline]
    pub fn decode_a(instruction: u32) -> u8 {
        ((instruction >> 16) & 0xFF) as u8
    }

    /// Decode B operand
    #[inline]
    pub fn decode_b(instruction: u32) -> u8 {
        ((instruction >> 8) & 0xFF) as u8
    }

    /// Decode C operand
    #[inline]
    pub fn decode_c(instruction: u32) -> u8 {
        (instruction & 0xFF) as u8
    }

    /// Decode Bx operand (16-bit)
    #[inline]
    pub fn decode_bx(instruction: u32) -> u16 {
        (instruction & 0xFFFF) as u16
    }

    /// Decode signed Bx operand
    #[inline]
    pub fn decode_sbx(instruction: u32) -> i16 {
        decode_bx(instruction) as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use instruction::*;

    #[test]
    fn test_opcode_conversion() {
        assert_eq!(OpCode::Add.as_u8(), 10);
        assert_eq!(OpCode::from_u8(10), Some(OpCode::Add));
        assert_eq!(OpCode::from_u8(200), Some(OpCode::IterInit)); // 200 is now assigned
        assert_eq!(OpCode::from_u8(205), None); // 205 is not assigned
    }

    #[test]
    fn test_instruction_encoding() {
        let inst = encode_abc(OpCode::Add.as_u8(), 1, 2, 3);
        assert_eq!(decode_opcode(inst), OpCode::Add.as_u8());
        assert_eq!(decode_a(inst), 1);
        assert_eq!(decode_b(inst), 2);
        assert_eq!(decode_c(inst), 3);
    }

    #[test]
    fn test_instruction_encoding_abx() {
        let inst = encode_abx(OpCode::LoadConst.as_u8(), 5, 1000);
        assert_eq!(decode_opcode(inst), OpCode::LoadConst.as_u8());
        assert_eq!(decode_a(inst), 5);
        assert_eq!(decode_bx(inst), 1000);
    }
}
