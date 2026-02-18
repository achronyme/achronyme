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
    /// Load True: R[A] = true
    LoadTrue = 1,
    /// Load False: R[A] = false
    LoadFalse = 2,
    /// Load Nil: R[A] = nil
    LoadNil = 3,
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
    /// Square root: R[A] = sqrt(R[B])
    Sqrt = 17,

    // ===== Comparison =====
    /// Equal: R[A] = R[B] == R[C]
    Eq = 20,
    /// Less Than: R[A] = R[B] < R[C]
    Lt = 21,
    /// Greater Than: R[A] = R[B] > R[C]
    Gt = 22,
    /// Not Equal: R[A] = R[B] != R[C]
    NotEq = 23,
    /// Less Than or Equal: R[A] = R[B] <= R[C]
    Le = 24,
    /// Greater Than or Equal: R[A] = R[B] >= R[C]
    Ge = 25,
    /// Logical Not: R[A] = !R[B]
    LogNot = 26,

    // ===== Closures =====
    GetUpvalue = 34,
    SetUpvalue = 35,
    CloseUpvalue = 36,

    // ===== Functions =====
    /// Return: return R[A]
    Return = 54,
    /// Call: R[A] = Call(R[B], R[B+1]...R[B+C-1])
    Call = 55,
    /// Closure: R[A] = Closure(K[Bx]) - Load function from constant pool
    Closure = 56,

    // ===== Global Variables =====
    /// Define mutable global: Global[K[Bx]] = R[A]
    DefGlobalVar = 98,
    /// Define immutable global: Global[K[Bx]] = R[A]
    DefGlobalLet = 99,
    /// Get global: R[A] = Global[K[Bx]]
    GetGlobal = 100,
    /// Set global: Global[K[Bx]] = R[A]
    SetGlobal = 101,
    /// Print: print R[A]
    Print = 102,

    // ===== Data Structures =====
    /// Build List: R[A] = [ R[B], ..., R[B+C-1] ]
    BuildList = 150,
    /// Build Map: R[A] = { R[B]: R[B+1], ... }
    BuildMap = 151,
    /// Get Index: R[A] = R[B][R[C]]
    GetIndex = 152,
    /// Set Index: R[A][R[B]] = R[C]
    SetIndex = 153,

    // ===== Flow Control =====
    /// Unconditional Jump: IP = Bx
    Jump = 60,
    /// Jump if False: If !R[A] then IP = Bx
    JumpIfFalse = 61,
    /// Get Iterator: R[A] = Iter(R[B])
    GetIter = 65,
    /// For Loop Iterator: R[A].. = Next(R[A]) or Jump Bx
    ForIter = 66,

    // ===== Special =====
    /// No operation
    Nop = 255,
}

impl OpCode {
    /// Get opcode from byte value
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(OpCode::LoadConst),
            1 => Some(OpCode::LoadTrue),
            2 => Some(OpCode::LoadFalse),
            3 => Some(OpCode::LoadNil),
            5 => Some(OpCode::Move),
            10 => Some(OpCode::Add),
            11 => Some(OpCode::Sub),
            12 => Some(OpCode::Mul),
            13 => Some(OpCode::Div),
            14 => Some(OpCode::Mod),
            15 => Some(OpCode::Pow),
            16 => Some(OpCode::Neg),
            17 => Some(OpCode::Sqrt),
            20 => Some(OpCode::Eq),
            21 => Some(OpCode::Lt),
            22 => Some(OpCode::Gt),
            23 => Some(OpCode::NotEq),
            24 => Some(OpCode::Le),
            25 => Some(OpCode::Ge),
            26 => Some(OpCode::LogNot),
            34 => Some(OpCode::GetUpvalue),
            35 => Some(OpCode::SetUpvalue),
            36 => Some(OpCode::CloseUpvalue),
            54 => Some(OpCode::Return),
            55 => Some(OpCode::Call),
            56 => Some(OpCode::Closure),
            60 => Some(OpCode::Jump),
            61 => Some(OpCode::JumpIfFalse),
            65 => Some(OpCode::GetIter),
            66 => Some(OpCode::ForIter),
            98 => Some(OpCode::DefGlobalVar),
            99 => Some(OpCode::DefGlobalLet),
            100 => Some(OpCode::GetGlobal),
            101 => Some(OpCode::SetGlobal),
            102 => Some(OpCode::Print),
            150 => Some(OpCode::BuildList),
            151 => Some(OpCode::BuildMap),
            152 => Some(OpCode::GetIndex),
            153 => Some(OpCode::SetIndex),
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
            OpCode::LoadTrue => "LOAD_TRUE",
            OpCode::LoadFalse => "LOAD_FALSE",
            OpCode::LoadNil => "LOAD_NIL",
            OpCode::Move => "MOVE",
            OpCode::Add => "ADD",
            OpCode::Sub => "SUB",
            OpCode::Mul => "MUL",
            OpCode::Div => "DIV",
            OpCode::Mod => "MOD",
            OpCode::Pow => "POW",
            OpCode::Neg => "NEG",
            OpCode::Sqrt => "SQRT",
            OpCode::Eq => "EQ",
            OpCode::Lt => "LT",
            OpCode::Gt => "GT",
            OpCode::NotEq => "NOT_EQ",
            OpCode::Le => "LE",
            OpCode::Ge => "GE",
            OpCode::LogNot => "LOG_NOT",
            OpCode::GetUpvalue => "GET_UPVALUE",
            OpCode::SetUpvalue => "SET_UPVALUE",
            OpCode::CloseUpvalue => "CLOSE_UPVALUE",
            OpCode::Return => "RETURN",
            OpCode::Call => "CALL",
            OpCode::Closure => "CLOSURE",
            OpCode::Jump => "JUMP",
            OpCode::JumpIfFalse => "JUMP_IF_FALSE",
            OpCode::GetIter => "GET_ITER",
            OpCode::ForIter => "FOR_ITER",
            OpCode::DefGlobalVar => "DEF_GLOBAL_VAR",
            OpCode::DefGlobalLet => "DEF_GLOBAL_LET",
            OpCode::GetGlobal => "GET_GLOBAL",
            OpCode::SetGlobal => "SET_GLOBAL",
            OpCode::Print => "PRINT",
            OpCode::BuildList => "BUILD_LIST",
            OpCode::BuildMap => "BUILD_MAP",
            OpCode::GetIndex => "GET_INDEX",
            OpCode::SetIndex => "SET_INDEX",
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
        assert_eq!(OpCode::from_u8(255), Some(OpCode::Nop));
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
