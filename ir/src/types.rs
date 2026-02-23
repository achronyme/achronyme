use std::collections::HashMap;

use memory::FieldElement;

/// An SSA variable — defined exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaVar(pub u32);

/// Whether a circuit input is public (instance) or private (witness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Witness,
}

/// A single SSA instruction.
///
/// Each instruction defines exactly one `result` variable. The program is a
/// flat list of these instructions — no phi-nodes needed because circuits have
/// no dynamic branching.
#[derive(Debug, Clone)]
pub enum Instruction {
    /// A compile-time constant field element.
    Const { result: SsaVar, value: FieldElement },
    /// A circuit input (public or witness).
    Input {
        result: SsaVar,
        name: String,
        visibility: Visibility,
    },
    /// result = lhs + rhs
    Add {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = lhs - rhs
    Sub {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = lhs * rhs
    Mul {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = lhs / rhs
    Div {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = -operand
    Neg { result: SsaVar, operand: SsaVar },
    /// result = cond ? if_true : if_false (boolean MUX)
    Mux {
        result: SsaVar,
        cond: SsaVar,
        if_true: SsaVar,
        if_false: SsaVar,
    },
    /// Constraint: lhs == rhs. Result is an alias for lhs.
    AssertEq {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = poseidon(left, right)
    PoseidonHash {
        result: SsaVar,
        left: SsaVar,
        right: SsaVar,
    },
    /// Range check: asserts operand fits in `bits` bits (0 ≤ operand < 2^bits).
    /// Result is an alias for operand.
    RangeCheck {
        result: SsaVar,
        operand: SsaVar,
        bits: u32,
    },
    /// Logical NOT: result = 1 - operand (operand must be boolean).
    Not { result: SsaVar, operand: SsaVar },
    /// Logical AND: result = lhs * rhs (both must be boolean).
    And {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Logical OR: result = lhs + rhs - lhs*rhs (both must be boolean).
    Or {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Equality check: result = 1 if lhs == rhs, 0 otherwise.
    IsEq {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Not-equal check: result = 1 if lhs != rhs, 0 otherwise.
    IsNeq {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Less-than check: result = 1 if lhs < rhs, 0 otherwise.
    IsLt {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Less-or-equal check: result = 1 if lhs <= rhs, 0 otherwise.
    IsLe {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Assertion: enforces operand == 1 (boolean). Side-effecting.
    Assert { result: SsaVar, operand: SsaVar },
}

impl Instruction {
    /// The SSA variable defined by this instruction.
    pub fn result_var(&self) -> SsaVar {
        match self {
            Instruction::Const { result, .. }
            | Instruction::Input { result, .. }
            | Instruction::Add { result, .. }
            | Instruction::Sub { result, .. }
            | Instruction::Mul { result, .. }
            | Instruction::Div { result, .. }
            | Instruction::Neg { result, .. }
            | Instruction::Mux { result, .. }
            | Instruction::AssertEq { result, .. }
            | Instruction::PoseidonHash { result, .. }
            | Instruction::RangeCheck { result, .. }
            | Instruction::Not { result, .. }
            | Instruction::And { result, .. }
            | Instruction::Or { result, .. }
            | Instruction::IsEq { result, .. }
            | Instruction::IsNeq { result, .. }
            | Instruction::IsLt { result, .. }
            | Instruction::IsLe { result, .. }
            | Instruction::Assert { result, .. } => *result,
        }
    }

    /// Returns true if this instruction has side effects (cannot be eliminated).
    pub fn has_side_effects(&self) -> bool {
        matches!(
            self,
            Instruction::AssertEq { .. }
                | Instruction::Input { .. }
                | Instruction::RangeCheck { .. }
                | Instruction::Assert { .. }
        )
    }

    /// Returns the SSA variables used (read) by this instruction.
    pub fn operands(&self) -> Vec<SsaVar> {
        match self {
            Instruction::Const { .. } | Instruction::Input { .. } => vec![],
            Instruction::Add { lhs, rhs, .. }
            | Instruction::Sub { lhs, rhs, .. }
            | Instruction::Mul { lhs, rhs, .. }
            | Instruction::Div { lhs, rhs, .. } => vec![*lhs, *rhs],
            Instruction::Neg { operand, .. }
            | Instruction::Not { operand, .. }
            | Instruction::Assert { operand, .. } => vec![*operand],
            Instruction::And { lhs, rhs, .. }
            | Instruction::Or { lhs, rhs, .. }
            | Instruction::IsEq { lhs, rhs, .. }
            | Instruction::IsNeq { lhs, rhs, .. }
            | Instruction::IsLt { lhs, rhs, .. }
            | Instruction::IsLe { lhs, rhs, .. } => vec![*lhs, *rhs],
            Instruction::Mux {
                cond,
                if_true,
                if_false,
                ..
            } => vec![*cond, *if_true, *if_false],
            Instruction::AssertEq { lhs, rhs, .. } => vec![*lhs, *rhs],
            Instruction::PoseidonHash { left, right, .. } => vec![*left, *right],
            Instruction::RangeCheck { operand, .. } => vec![*operand],
        }
    }
}

/// The IR-level type of an SSA variable (for gradual type checking).
///
/// ```
/// use ir::types::IrType;
///
/// let t = IrType::Field;
/// assert_eq!(format!("{t}"), "Field");
/// assert_eq!(t, IrType::Field);
/// assert_ne!(t, IrType::Bool);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrType {
    Field,
    Bool,
}

impl std::fmt::Display for IrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrType::Field => write!(f, "Field"),
            IrType::Bool => write!(f, "Bool"),
        }
    }
}

/// A flat SSA program — a sequence of instructions.
///
/// ```
/// use ir::types::{IrProgram, IrType, Instruction, SsaVar};
/// use memory::FieldElement;
///
/// let mut prog = IrProgram::new();
/// let v = prog.fresh_var();
/// prog.push(Instruction::Const { result: v, value: FieldElement::from_u64(42) });
/// assert_eq!(prog.instructions.len(), 1);
/// assert_eq!(v, SsaVar(0));
///
/// // Type metadata starts empty
/// assert!(prog.get_type(v).is_none());
/// prog.set_type(v, IrType::Field);
/// assert_eq!(prog.get_type(v), Some(IrType::Field));
/// ```
#[derive(Debug)]
pub struct IrProgram {
    pub instructions: Vec<Instruction>,
    pub next_var: u32,
    /// Maps SSA variables to their source-level names (for error messages).
    pub var_names: HashMap<SsaVar, String>,
    /// Maps SSA variables to their IR types (set by type annotations and inference).
    pub var_types: HashMap<SsaVar, IrType>,
}

impl Default for IrProgram {
    fn default() -> Self {
        Self::new()
    }
}

impl IrProgram {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            next_var: 0,
            var_names: HashMap::new(),
            var_types: HashMap::new(),
        }
    }

    /// Allocate a fresh SSA variable.
    pub fn fresh_var(&mut self) -> SsaVar {
        let v = SsaVar(self.next_var);
        self.next_var += 1;
        v
    }

    /// Append an instruction and return its result variable.
    pub fn push(&mut self, inst: Instruction) -> SsaVar {
        let v = inst.result_var();
        self.instructions.push(inst);
        v
    }

    /// Associate a source-level name with an SSA variable (for error messages).
    pub fn set_name(&mut self, var: SsaVar, name: String) {
        self.var_names.insert(var, name);
    }

    /// Look up the source-level name for an SSA variable.
    pub fn get_name(&self, var: SsaVar) -> Option<&str> {
        self.var_names.get(&var).map(|s| s.as_str())
    }

    /// Associate an IR type with an SSA variable.
    pub fn set_type(&mut self, var: SsaVar, ty: IrType) {
        self.var_types.insert(var, ty);
    }

    /// Look up the IR type for an SSA variable.
    pub fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.var_types.get(&var).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_var_increments() {
        let mut p = IrProgram::new();
        assert_eq!(p.fresh_var(), SsaVar(0));
        assert_eq!(p.fresh_var(), SsaVar(1));
        assert_eq!(p.fresh_var(), SsaVar(2));
        assert_eq!(p.next_var, 3);
    }

    #[test]
    fn result_var_extracts_correctly() {
        let inst = Instruction::Add {
            result: SsaVar(42),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
        };
        assert_eq!(inst.result_var(), SsaVar(42));
    }

    #[test]
    fn push_appends_and_returns_result() {
        let mut p = IrProgram::new();
        let v = p.fresh_var();
        let r = p.push(Instruction::Const {
            result: v,
            value: FieldElement::from_u64(99),
        });
        assert_eq!(r, SsaVar(0));
        assert_eq!(p.instructions.len(), 1);
    }

    #[test]
    fn has_side_effects() {
        let assert_inst = Instruction::AssertEq {
            result: SsaVar(0),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
        };
        assert!(assert_inst.has_side_effects());

        let add_inst = Instruction::Add {
            result: SsaVar(0),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
        };
        assert!(!add_inst.has_side_effects());
    }

    #[test]
    fn set_get_type_round_trip() {
        let mut p = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        assert!(p.get_type(v0).is_none());
        p.set_type(v0, IrType::Field);
        p.set_type(v1, IrType::Bool);
        assert_eq!(p.get_type(v0), Some(IrType::Field));
        assert_eq!(p.get_type(v1), Some(IrType::Bool));
    }

    #[test]
    fn ir_type_display() {
        assert_eq!(format!("{}", IrType::Field), "Field");
        assert_eq!(format!("{}", IrType::Bool), "Bool");
    }

    #[test]
    fn operands_returns_correct_vars() {
        let mux = Instruction::Mux {
            result: SsaVar(10),
            cond: SsaVar(1),
            if_true: SsaVar(2),
            if_false: SsaVar(3),
        };
        assert_eq!(mux.operands(), vec![SsaVar(1), SsaVar(2), SsaVar(3)]);

        let c = Instruction::Const {
            result: SsaVar(0),
            value: FieldElement::ZERO,
        };
        assert!(c.operands().is_empty());
    }
}
