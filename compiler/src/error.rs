use std::fmt;

#[derive(Debug, Clone)]
pub enum CompilerError {
    ParseError(String),
    UnknownOperator(String),
    InvalidNumber,
    TooManyConstants,
    UnexpectedRule(String),
    MissingOperand,
    RegisterOverflow,
    CompilerLimitation(String),
    CompileError(String),
    ModuleNotFound(String),
    CircularImport(String),
    ModuleLoadError(String),
    DuplicateModuleAlias(String),
    InternalError(String),
}

impl fmt::Display for CompilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompilerError::ParseError(msg) => write!(f, "parse error: {msg}"),
            CompilerError::UnknownOperator(msg) => write!(f, "{msg}"),
            CompilerError::InvalidNumber => write!(f, "invalid number literal"),
            CompilerError::TooManyConstants => write!(f, "too many constants (limit 65536)"),
            CompilerError::UnexpectedRule(msg) => write!(f, "unexpected rule: {msg}"),
            CompilerError::MissingOperand => write!(f, "missing operand"),
            CompilerError::RegisterOverflow => write!(f, "register overflow (too many locals)"),
            CompilerError::CompilerLimitation(msg) => write!(f, "compiler limitation: {msg}"),
            CompilerError::CompileError(msg) => write!(f, "{msg}"),
            CompilerError::ModuleNotFound(path) => write!(f, "module not found: {path}"),
            CompilerError::CircularImport(path) => write!(f, "circular import: {path}"),
            CompilerError::ModuleLoadError(msg) => write!(f, "module load error: {msg}"),
            CompilerError::DuplicateModuleAlias(name) => {
                write!(f, "duplicate module alias: {name}")
            }
            CompilerError::InternalError(msg) => write!(f, "internal compiler error: {msg}"),
        }
    }
}

impl std::error::Error for CompilerError {}
