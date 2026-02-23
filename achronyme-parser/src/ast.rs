/// Owned AST types for the Achronyme language.
///
/// These types represent the parsed structure of an Achronyme program,
/// independent of the pest parser. All types are `Clone + Debug`.
/// Source location for error reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

/// A complete program: a sequence of statements.
#[derive(Clone, Debug)]
pub struct Program {
    pub stmts: Vec<Stmt>,
}

/// Statement variants.
#[derive(Clone, Debug)]
pub enum Stmt {
    LetDecl {
        name: String,
        type_ann: Option<TypeAnnotation>,
        value: Expr,
        span: Span,
    },
    MutDecl {
        name: String,
        type_ann: Option<TypeAnnotation>,
        value: Expr,
        span: Span,
    },
    Assignment {
        target: Expr,
        value: Expr,
        span: Span,
    },
    PublicDecl {
        names: Vec<InputDecl>,
        span: Span,
    },
    WitnessDecl {
        names: Vec<InputDecl>,
        span: Span,
    },
    FnDecl {
        name: String,
        params: Vec<TypedParam>,
        return_type: Option<TypeAnnotation>,
        body: Block,
        span: Span,
    },
    Print {
        value: Expr,
        span: Span,
    },
    Return {
        value: Option<Expr>,
        span: Span,
    },
    Break {
        span: Span,
    },
    Continue {
        span: Span,
    },
    Expr(Expr),
}

/// A public/witness input declaration with optional array size.
#[derive(Clone, Debug)]
pub struct InputDecl {
    pub name: String,
    pub array_size: Option<usize>,
    pub type_ann: Option<TypeAnnotation>,
}

/// A block of statements (e.g., `{ ... }`).
#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

/// Expression variants.
#[derive(Clone, Debug)]
pub enum Expr {
    Number {
        value: String,
        span: Span,
    },
    Bool {
        value: bool,
        span: Span,
    },
    StringLit {
        value: String,
        span: Span,
    },
    Nil {
        span: Span,
    },
    Ident {
        name: String,
        span: Span,
    },
    BinOp {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        span: Span,
    },
    UnaryOp {
        op: UnaryOp,
        operand: Box<Expr>,
        span: Span,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
        span: Span,
    },
    Index {
        object: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    DotAccess {
        object: Box<Expr>,
        field: String,
        span: Span,
    },
    If {
        condition: Box<Expr>,
        then_block: Block,
        else_branch: Option<ElseBranch>,
        span: Span,
    },
    For {
        var: String,
        iterable: ForIterable,
        body: Block,
        span: Span,
    },
    While {
        condition: Box<Expr>,
        body: Block,
        span: Span,
    },
    Forever {
        body: Block,
        span: Span,
    },
    Block(Block),
    FnExpr {
        name: Option<String>,
        params: Vec<TypedParam>,
        return_type: Option<TypeAnnotation>,
        body: Block,
        span: Span,
    },
    Prove {
        body: Block,
        source: String,
        span: Span,
    },
    Array {
        elements: Vec<Expr>,
        span: Span,
    },
    Map {
        pairs: Vec<(MapKey, Expr)>,
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> &Span {
        match self {
            Expr::Number { span, .. }
            | Expr::Bool { span, .. }
            | Expr::StringLit { span, .. }
            | Expr::Nil { span }
            | Expr::Ident { span, .. }
            | Expr::BinOp { span, .. }
            | Expr::UnaryOp { span, .. }
            | Expr::Call { span, .. }
            | Expr::Index { span, .. }
            | Expr::DotAccess { span, .. }
            | Expr::If { span, .. }
            | Expr::For { span, .. }
            | Expr::While { span, .. }
            | Expr::Forever { span, .. }
            | Expr::FnExpr { span, .. }
            | Expr::Prove { span, .. }
            | Expr::Array { span, .. }
            | Expr::Map { span, .. } => span,
            Expr::Block(block) => &block.span,
        }
    }
}

/// Map key: either an identifier or a string literal.
#[derive(Clone, Debug)]
pub enum MapKey {
    Ident(String),
    StringLit(String),
}

/// Else branch: either a block or a chained `if`.
#[derive(Clone, Debug)]
pub enum ElseBranch {
    Block(Block),
    If(Box<Expr>),
}

/// For-loop iterable: either a range or an expression.
#[derive(Clone, Debug)]
pub enum ForIterable {
    Range { start: u64, end: u64 },
    Expr(Box<Expr>),
}

/// Binary operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
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
}

/// Unary operators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
}

/// A type annotation for circuit variables and function parameters.
///
/// ```
/// use achronyme_parser::ast::TypeAnnotation;
///
/// let t = TypeAnnotation::Field;
/// assert_eq!(format!("{t}"), "Field");
///
/// let arr = TypeAnnotation::BoolArray(4);
/// assert_eq!(format!("{arr}"), "Bool[4]");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeAnnotation {
    Field,
    Bool,
    FieldArray(usize),
    BoolArray(usize),
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeAnnotation::Field => write!(f, "Field"),
            TypeAnnotation::Bool => write!(f, "Bool"),
            TypeAnnotation::FieldArray(n) => write!(f, "Field[{n}]"),
            TypeAnnotation::BoolArray(n) => write!(f, "Bool[{n}]"),
        }
    }
}

/// A function parameter with an optional type annotation.
///
/// ```
/// use achronyme_parser::ast::TypedParam;
///
/// let p = TypedParam { name: "x".into(), type_ann: None };
/// assert_eq!(p.name, "x");
/// assert!(p.type_ann.is_none());
/// ```
#[derive(Clone, Debug)]
pub struct TypedParam {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,
}
