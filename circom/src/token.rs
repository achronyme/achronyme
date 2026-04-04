//! Token types for the Circom lexer.

use diagnostics::Span;

/// A single token produced by the Circom lexer.
#[derive(Clone, Debug)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub lexeme: String,
}

/// All token variants recognized by the Circom lexer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    // ── Literals ──────────────────────────────────────────────────────
    /// Decimal number: `[0-9]+`
    DecNumber,
    /// Hexadecimal number: `0x[0-9A-Fa-f]+`
    HexNumber,
    /// String literal (double-quoted, for `include` and `log`)
    StringLit,

    // ── Keywords ─────────────────────────────────────────────────────
    Signal,
    Input,
    Output,
    Public,
    Template,
    Component,
    Var,
    Function,
    Return,
    If,
    Else,
    For,
    While,
    Do,
    Log,
    Assert,
    Include,
    Pragma,
    Parallel,
    Bus,
    Custom,
    MainKw,

    // ── Identifier ───────────────────────────────────────────────────
    Ident,

    // ── Circom-specific signal operators ─────────────────────────────
    /// `<==` — constrained signal assignment
    ConstraintAssign,
    /// `==>` — reverse constrained signal assignment
    RConstraintAssign,
    /// `<--` — unconstrained signal assignment (witness hint)
    SignalAssign,
    /// `-->` — reverse unconstrained signal assignment
    RSignalAssign,
    /// `===` — constraint equality
    ConstraintEq,

    // ── Arithmetic operators ─────────────────────────────────────────
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `\` — integer division
    IntDiv,
    /// `%`
    Percent,
    /// `**` — exponentiation
    Power,

    // ── Comparison operators ─────────────────────────────────────────
    /// `==`
    Eq,
    /// `!=`
    Neq,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,

    // ── Logical operators ────────────────────────────────────────────
    /// `&&`
    And,
    /// `||`
    Or,
    /// `!`
    Not,

    // ── Bitwise operators ────────────────────────────────────────────
    /// `&`
    BitAnd,
    /// `|`
    BitOr,
    /// `^`
    BitXor,
    /// `~`
    BitNot,
    /// `<<`
    ShiftL,
    /// `>>`
    ShiftR,

    // ── Assignment operators ─────────────────────────────────────────
    /// `=`
    Assign,
    /// `+=`
    PlusAssign,
    /// `-=`
    MinusAssign,
    /// `*=`
    StarAssign,
    /// `/=`
    SlashAssign,
    /// `\=`
    IntDivAssign,
    /// `%=`
    PercentAssign,
    /// `**=`
    PowerAssign,
    /// `<<=`
    ShiftLAssign,
    /// `>>=`
    ShiftRAssign,
    /// `&=`
    BitAndAssign,
    /// `|=`
    BitOrAssign,
    /// `^=`
    BitXorAssign,

    // ── Increment / decrement ────────────────────────────────────────
    /// `++`
    Increment,
    /// `--`
    Decrement,

    // ── Ternary ──────────────────────────────────────────────────────
    /// `?`
    Question,

    // ── Delimiters ───────────────────────────────────────────────────
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Colon,
    Semicolon,
    Dot,
    Underscore,

    // ── End of file ──────────────────────────────────────────────────
    Eof,
}

impl TokenKind {
    /// Human-readable name for error messages.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DecNumber => "decimal number",
            Self::HexNumber => "hex number",
            Self::StringLit => "string literal",
            Self::Signal => "signal",
            Self::Input => "input",
            Self::Output => "output",
            Self::Public => "public",
            Self::Template => "template",
            Self::Component => "component",
            Self::Var => "var",
            Self::Function => "function",
            Self::Return => "return",
            Self::If => "if",
            Self::Else => "else",
            Self::For => "for",
            Self::While => "while",
            Self::Do => "do",
            Self::Log => "log",
            Self::Assert => "assert",
            Self::Include => "include",
            Self::Pragma => "pragma",
            Self::Parallel => "parallel",
            Self::Bus => "bus",
            Self::Custom => "custom",
            Self::MainKw => "main",
            Self::Ident => "identifier",
            Self::ConstraintAssign => "'<=='",
            Self::RConstraintAssign => "'==>'",
            Self::SignalAssign => "'<--'",
            Self::RSignalAssign => "'-->'",
            Self::ConstraintEq => "'==='",
            Self::Plus => "'+'",
            Self::Minus => "'-'",
            Self::Star => "'*'",
            Self::Slash => "'/'",
            Self::IntDiv => "'\\'",
            Self::Percent => "'%'",
            Self::Power => "'**'",
            Self::Eq => "'=='",
            Self::Neq => "'!='",
            Self::Lt => "'<'",
            Self::Le => "'<='",
            Self::Gt => "'>'",
            Self::Ge => "'>='",
            Self::And => "'&&'",
            Self::Or => "'||'",
            Self::Not => "'!'",
            Self::BitAnd => "'&'",
            Self::BitOr => "'|'",
            Self::BitXor => "'^'",
            Self::BitNot => "'~'",
            Self::ShiftL => "'<<'",
            Self::ShiftR => "'>>'",
            Self::Assign => "'='",
            Self::PlusAssign => "'+='",
            Self::MinusAssign => "'-='",
            Self::StarAssign => "'*='",
            Self::SlashAssign => "'/='",
            Self::IntDivAssign => "'\\='",
            Self::PercentAssign => "'%='",
            Self::PowerAssign => "'**='",
            Self::ShiftLAssign => "'<<='",
            Self::ShiftRAssign => "'>>='",
            Self::BitAndAssign => "'&='",
            Self::BitOrAssign => "'|='",
            Self::BitXorAssign => "'^='",
            Self::Increment => "'++'",
            Self::Decrement => "'--'",
            Self::Question => "'?'",
            Self::LParen => "'('",
            Self::RParen => "')'",
            Self::LBracket => "'['",
            Self::RBracket => "']'",
            Self::LBrace => "'{'",
            Self::RBrace => "'}'",
            Self::Comma => "','",
            Self::Colon => "':'",
            Self::Semicolon => "';'",
            Self::Dot => "'.'",
            Self::Underscore => "'_'",
            Self::Eof => "end of file",
        }
    }
}

/// Look up a keyword from an identifier string.
pub fn lookup_keyword(ident: &str) -> Option<TokenKind> {
    match ident {
        "signal" => Some(TokenKind::Signal),
        "input" => Some(TokenKind::Input),
        "output" => Some(TokenKind::Output),
        "public" => Some(TokenKind::Public),
        "template" => Some(TokenKind::Template),
        "component" => Some(TokenKind::Component),
        "var" => Some(TokenKind::Var),
        "function" => Some(TokenKind::Function),
        "return" => Some(TokenKind::Return),
        "if" => Some(TokenKind::If),
        "else" => Some(TokenKind::Else),
        "for" => Some(TokenKind::For),
        "while" => Some(TokenKind::While),
        "do" => Some(TokenKind::Do),
        "log" => Some(TokenKind::Log),
        "assert" => Some(TokenKind::Assert),
        "include" => Some(TokenKind::Include),
        "pragma" => Some(TokenKind::Pragma),
        "parallel" => Some(TokenKind::Parallel),
        "bus" => Some(TokenKind::Bus),
        "custom" => Some(TokenKind::Custom),
        "main" => Some(TokenKind::MainKw),
        _ => None,
    }
}
