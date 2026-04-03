//! Circom AST types.
//!
//! Represents the parsed structure of a Circom 2.x program. Every node
//! carries a [`Span`] for precise source location tracking in diagnostics.

use achronyme_parser::ast::Span;

// ---------------------------------------------------------------------------
// Top-level program
// ---------------------------------------------------------------------------

/// A complete Circom file after parsing.
#[derive(Clone, Debug)]
pub struct CircomProgram {
    /// `pragma circom X.Y.Z;` — compiler version requirement.
    pub version: Option<Version>,
    /// `pragma custom_templates;` — enables custom template declarations.
    pub custom_templates: bool,
    /// `include "path";` directives.
    pub includes: Vec<Include>,
    /// Top-level definitions: templates, functions, buses.
    pub definitions: Vec<Definition>,
    /// `component main {public [...]} = Template(args);`
    pub main_component: Option<MainComponent>,
}

/// Parsed version from `pragma circom X.Y.Z;`.
#[derive(Clone, Debug)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub span: Span,
}

/// `include "path/to/file.circom";`
#[derive(Clone, Debug)]
pub struct Include {
    pub path: String,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

/// A top-level definition.
#[derive(Clone, Debug)]
pub enum Definition {
    Template(TemplateDef),
    Function(FunctionDef),
    Bus(BusDef),
}

/// Template modifiers.
#[derive(Clone, Debug, Default)]
pub struct TemplateModifiers {
    pub custom: bool,
    pub parallel: bool,
}

/// `template [custom] [parallel] Name(params) { body }`
#[derive(Clone, Debug)]
pub struct TemplateDef {
    pub name: String,
    pub params: Vec<String>,
    pub modifiers: TemplateModifiers,
    pub body: Block,
    pub span: Span,
}

/// `function name(params) { body }`
#[derive(Clone, Debug)]
pub struct FunctionDef {
    pub name: String,
    pub params: Vec<String>,
    pub body: Block,
    pub span: Span,
}

/// `bus Name(params) { body }` (Circom 2.2.0+)
#[derive(Clone, Debug)]
pub struct BusDef {
    pub name: String,
    pub params: Vec<String>,
    pub body: Block,
    pub span: Span,
}

/// `component main {public [sig1, sig2]} = Template(args);`
#[derive(Clone, Debug)]
pub struct MainComponent {
    pub public_signals: Vec<String>,
    pub template_name: String,
    pub template_args: Vec<Expr>,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Blocks and statements
// ---------------------------------------------------------------------------

/// A brace-delimited block of statements.
#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

/// Statement variants.
#[derive(Clone, Debug)]
pub enum Stmt {
    /// `signal [input|output] [{tags}] name[size] [<== expr];`
    SignalDecl {
        signal_type: SignalType,
        tags: Vec<String>,
        declarations: Vec<SignalName>,
        /// Optional initialization: `<==` or `<--` with expression.
        init: Option<(AssignOp, Expr)>,
        span: Span,
    },
    /// `var name [= expr];` or `var (a, b) = expr;`
    VarDecl {
        names: Vec<String>,
        init: Option<Expr>,
        span: Span,
    },
    /// `component name [= expr];` or `component name[size];`
    ComponentDecl {
        names: Vec<ComponentName>,
        init: Option<Expr>,
        span: Span,
    },
    /// `target op expr;` where op is `=`, `<==`, `<--`, `==>`, `-->`
    Substitution {
        target: Expr,
        op: AssignOp,
        value: Expr,
        span: Span,
    },
    /// Compound assignment: `target op= expr;`
    CompoundAssign {
        target: Expr,
        op: CompoundOp,
        value: Expr,
        span: Span,
    },
    /// `expr === expr;`
    ConstraintEq {
        lhs: Expr,
        rhs: Expr,
        span: Span,
    },
    /// `if (cond) { ... } [else { ... }]`
    IfElse {
        condition: Expr,
        then_body: Block,
        else_body: Option<ElseBranch>,
        span: Span,
    },
    /// `for (init; cond; step) { body }`
    For {
        init: Box<Stmt>,
        condition: Expr,
        step: Box<Stmt>,
        body: Block,
        span: Span,
    },
    /// `while (cond) { body }`
    While {
        condition: Expr,
        body: Block,
        span: Span,
    },
    /// `return expr;`
    Return {
        value: Expr,
        span: Span,
    },
    /// `assert(expr);`
    Assert {
        arg: Expr,
        span: Span,
    },
    /// `log(args...);`
    Log {
        args: Vec<LogArg>,
        span: Span,
    },
    /// `{ stmts }` — bare block
    Block(Block),
    /// Bare expression statement (e.g., `i++`)
    Expr {
        expr: Expr,
        span: Span,
    },
    /// Placeholder for error recovery.
    Error { span: Span },
}

/// Else branch: either a block or chained if-else.
#[derive(Clone, Debug)]
pub enum ElseBranch {
    Block(Block),
    IfElse(Box<Stmt>),
}

/// A signal name with optional array size.
#[derive(Clone, Debug)]
pub struct SignalName {
    pub name: String,
    pub dimensions: Vec<Expr>,
    pub span: Span,
}

/// A component name with optional array dimensions.
#[derive(Clone, Debug)]
pub struct ComponentName {
    pub name: String,
    pub dimensions: Vec<Expr>,
    pub span: Span,
}

/// `log()` argument: either an expression or a string literal.
#[derive(Clone, Debug)]
pub enum LogArg {
    Expr(Expr),
    String(String, Span),
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

/// Expression variants.
#[derive(Clone, Debug)]
pub enum Expr {
    /// Decimal number literal.
    Number { value: String, span: Span },
    /// Hex number literal (`0x...`).
    HexNumber { value: String, span: Span },
    /// Identifier reference.
    Ident { name: String, span: Span },
    /// Binary operation.
    BinOp {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        span: Span,
    },
    /// Unary prefix operation.
    UnaryOp {
        op: UnaryOp,
        operand: Box<Expr>,
        span: Span,
    },
    /// Postfix increment/decrement.
    PostfixOp {
        op: PostfixOp,
        operand: Box<Expr>,
        span: Span,
    },
    /// Ternary conditional: `cond ? if_true : if_false`
    Ternary {
        condition: Box<Expr>,
        if_true: Box<Expr>,
        if_false: Box<Expr>,
        span: Span,
    },
    /// Function or template call: `name(args)`
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
        span: Span,
    },
    /// Anonymous component: `Template(params)(inputs)`
    AnonComponent {
        callee: Box<Expr>,
        template_args: Vec<Expr>,
        signal_args: Vec<AnonSignalArg>,
        span: Span,
    },
    /// Array index: `expr[index]`
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    /// Member access: `expr.field`
    DotAccess {
        object: Box<Expr>,
        field: String,
        span: Span,
    },
    /// Array literal: `[e0, e1, ...]`
    ArrayLit {
        elements: Vec<Expr>,
        span: Span,
    },
    /// Tuple: `(e0, e1, ...)`
    Tuple {
        elements: Vec<Expr>,
        span: Span,
    },
    /// `parallel expr`
    ParallelOp {
        operand: Box<Expr>,
        span: Span,
    },
    /// Underscore `_` (signal discard).
    Underscore { span: Span },
    /// Placeholder for error recovery.
    Error { span: Span },
}

impl Expr {
    /// Get the span of any expression variant.
    pub fn span(&self) -> &Span {
        match self {
            Self::Number { span, .. }
            | Self::HexNumber { span, .. }
            | Self::Ident { span, .. }
            | Self::BinOp { span, .. }
            | Self::UnaryOp { span, .. }
            | Self::PostfixOp { span, .. }
            | Self::Ternary { span, .. }
            | Self::Call { span, .. }
            | Self::AnonComponent { span, .. }
            | Self::Index { span, .. }
            | Self::DotAccess { span, .. }
            | Self::ArrayLit { span, .. }
            | Self::Tuple { span, .. }
            | Self::ParallelOp { span, .. }
            | Self::Underscore { span }
            | Self::Error { span } => span,
        }
    }
}

/// Anonymous component signal argument (may be named).
#[derive(Clone, Debug)]
pub struct AnonSignalArg {
    /// Named input: `input_name <== expr`.
    pub name: Option<String>,
    pub value: Expr,
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

/// Signal type for declarations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalType {
    Input,
    Output,
    Intermediate,
}

/// Assignment operators (signal-level).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssignOp {
    /// `=` — variable assignment
    Assign,
    /// `<==` — constrained signal assignment
    ConstraintAssign,
    /// `<--` — unconstrained signal assignment (witness hint)
    SignalAssign,
    /// `==>` — reverse constrained signal assignment
    RConstraintAssign,
    /// `-->` — reverse unconstrained signal assignment
    RSignalAssign,
}

/// Compound assignment operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompoundOp {
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
    Mod,
    Pow,
    ShiftL,
    ShiftR,
    BitAnd,
    BitOr,
    BitXor,
}

/// Binary operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
    Mod,
    Pow,
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    ShiftL,
    ShiftR,
}

/// Unary prefix operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
}

/// Postfix operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostfixOp {
    Increment,
    Decrement,
}
