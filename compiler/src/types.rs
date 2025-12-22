use vm::opcode::OpCode;

pub struct Local {
    pub name: String,
    pub depth: u32,
    pub is_captured: bool,
    pub reg: u8,
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
