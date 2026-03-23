/// Owned AST types for the Achronyme language.
///
/// These types represent the parsed structure of an Achronyme program,
/// independent of the pest parser. All types are `Clone + Debug`.
/// Source location for error reporting.
///
/// Tracks byte-range and line/column start and end positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: usize,
    pub col_start: usize,
    pub line_end: usize,
    pub col_end: usize,
}

impl Span {
    /// Create a span covering from `start` to `end`.
    pub fn from_to(start: &Span, end: &Span) -> Self {
        Self {
            byte_start: start.byte_start,
            byte_end: end.byte_end,
            line_start: start.line_start,
            col_start: start.col_start,
            line_end: end.line_end,
            col_end: end.col_end,
        }
    }
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
    Import {
        path: String,
        alias: String,
        span: Span,
    },
    Export {
        inner: Box<Stmt>,
        span: Span,
    },
    SelectiveImport {
        names: Vec<String>,
        path: String,
        span: Span,
    },
    ExportList {
        names: Vec<String>,
        span: Span,
    },
    /// Reusable circuit definition: `circuit name(x: Public, y: Witness) { body }`
    CircuitDecl {
        name: String,
        params: Vec<TypedParam>,
        body: Block,
        span: Span,
    },
    /// Circuit import: `import circuit "path" as name`
    ImportCircuit {
        path: String,
        alias: String,
        span: Span,
    },
    Expr(Expr),
    /// Placeholder for a statement that failed to parse (error recovery).
    Error {
        span: Span,
    },
}

/// A public/witness input declaration with optional type annotation.
///
/// Array size now lives inside `TypeAnnotation.array_size`.
#[derive(Clone, Debug)]
pub struct InputDecl {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,
}

impl InputDecl {
    /// Get the array size from the type annotation, if any.
    pub fn array_size(&self) -> Option<usize> {
        self.type_ann.as_ref().and_then(|ann| ann.array_size)
    }
}

/// A block of statements (e.g., `{ ... }`).
#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub span: Span,
}

/// Radix for field element literals (`0p` prefix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldRadix {
    Decimal,
    Hex,
    Binary,
}

/// Radix for BigInt literals (`0i` prefix).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BigIntRadix {
    Hex,
    Decimal,
    Binary,
}

/// Expression variants.
#[derive(Clone, Debug)]
pub enum Expr {
    Number {
        value: String,
        span: Span,
    },
    FieldLit {
        value: String,
        radix: FieldRadix,
        span: Span,
    },
    BigIntLit {
        value: String,
        width: u16,
        radix: BigIntRadix,
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
        /// Optional name: `prove vote(hash: Public) { ... }`
        name: Option<String>,
        body: Block,
        /// Public params with visibility types: `prove(hash: Public, flag: Public Bool) { ... }`
        /// Empty vec means no params (old-style or all-witness).
        /// Witnesses are auto-inferred from outer scope.
        params: Vec<TypedParam>,
        span: Span,
    },
    /// Circuit call with keyword arguments: `name(key: val, ...)`
    CircuitCall {
        name: String,
        args: Vec<(String, Expr)>,
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
    /// Static access: `Type::MEMBER` (e.g., `Int::MAX`, `Field::ORDER`).
    StaticAccess {
        type_name: String,
        member: String,
        span: Span,
    },
    /// Placeholder for an expression that failed to parse (error recovery).
    Error {
        span: Span,
    },
}

impl Expr {
    pub fn span(&self) -> &Span {
        match self {
            Expr::Number { span, .. }
            | Expr::FieldLit { span, .. }
            | Expr::BigIntLit { span, .. }
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
            | Expr::CircuitCall { span, .. }
            | Expr::Array { span, .. }
            | Expr::Map { span, .. }
            | Expr::StaticAccess { span, .. }
            | Expr::Error { span } => span,
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

/// Visibility of a ZK input (circuit/prove parameter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Witness,
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "Public"),
            Visibility::Witness => write!(f, "Witness"),
        }
    }
}

/// Base type in a type annotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseType {
    Field,
    Bool,
}

impl std::fmt::Display for BaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseType::Field => write!(f, "Field"),
            BaseType::Bool => write!(f, "Bool"),
        }
    }
}

/// A type annotation for circuit variables and function parameters.
///
/// Carries optional visibility (for circuit/prove params), a base type,
/// and an optional array size.
///
/// ```
/// use achronyme_parser::ast::{TypeAnnotation, BaseType};
///
/// let t = TypeAnnotation::scalar(BaseType::Field);
/// assert_eq!(format!("{t}"), "Field");
///
/// let arr = TypeAnnotation::array(BaseType::Bool, 4);
/// assert_eq!(format!("{arr}"), "Bool[4]");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeAnnotation {
    pub visibility: Option<Visibility>,
    pub base: BaseType,
    pub array_size: Option<usize>,
}

impl TypeAnnotation {
    /// Scalar type without visibility: `Field` or `Bool`.
    pub fn scalar(base: BaseType) -> Self {
        Self {
            visibility: None,
            base,
            array_size: None,
        }
    }

    /// Array type without visibility: `Field[N]` or `Bool[N]`.
    pub fn array(base: BaseType, size: usize) -> Self {
        Self {
            visibility: None,
            base,
            array_size: Some(size),
        }
    }

    /// Whether this annotation is an array type.
    pub fn is_array(&self) -> bool {
        self.array_size.is_some()
    }

    /// Whether this annotation is a `Bool` or `Bool[N]`.
    pub fn is_bool(&self) -> bool {
        self.base == BaseType::Bool
    }
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vis) = &self.visibility {
            write!(f, "{vis} ")?;
        }
        write!(f, "{}", self.base)?;
        if let Some(n) = self.array_size {
            write!(f, "[{n}]")?;
        }
        Ok(())
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
