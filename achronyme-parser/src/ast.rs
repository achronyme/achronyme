// Owned AST types for the Achronyme language.
//
// These types represent the parsed structure of an Achronyme program,
// independent of the pest parser. All types are `Clone + Debug`.

// Re-export Span from the shared diagnostics crate.
pub use diagnostics::Span;

/// Dense, unique identifier assigned to every `Expr` at parse time.
///
/// `ExprId` is the key used by the resolver pass to attach a
/// `SymbolId` to each call site and identifier via a parallel
/// `HashMap<ExprId, SymbolId>` inside `resolve::SymbolTable`. Every
/// parser-allocated id is unique within one `Program`; clones of an
/// `Expr` preserve the original id (cloning is never a source of new
/// parse-time state).
///
/// The reserved value [`ExprId::SYNTHETIC`] marks `Expr` nodes constructed
/// outside the parser (e.g. by the IR or circom compilers for internal
/// lowering). Synthetic nodes are not resolved, so the resolver pass
/// skips them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExprId(u32);

impl ExprId {
    /// Sentinel id for `Expr` nodes constructed outside the parser.
    ///
    /// Never collides with a parser-allocated id because the parser's
    /// counter starts at 1 (see `Parser::alloc_expr_id`).
    pub const SYNTHETIC: Self = Self(0);

    /// Construct an id from a raw `u32`. `0` is reserved for
    /// [`SYNTHETIC`](Self::SYNTHETIC); callers that need a parse-time
    /// id should use the parser's allocator instead.
    pub const fn from_raw(n: u32) -> Self {
        Self(n)
    }

    /// Raw underlying `u32`, suitable for stable hashing or indexing.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns `true` if this id is the reserved synthetic sentinel.
    pub const fn is_synthetic(self) -> bool {
        self.0 == Self::SYNTHETIC.0
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
    /// Reusable circuit definition: `circuit name(root: Public, secret: Witness) { body }`
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

/// A call argument — positional or keyword.
#[derive(Clone, Debug)]
pub struct CallArg {
    /// `None` = positional, `Some("x")` = keyword (`x: expr`).
    pub name: Option<String>,
    pub value: Expr,
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
///
/// Every variant carries an [`ExprId`] assigned by the parser (or
/// [`ExprId::SYNTHETIC`] for nodes constructed outside the parser).
/// The resolver pass uses this id to attach a `SymbolId` via a
/// parallel `HashMap<ExprId, SymbolId>`.
#[derive(Clone, Debug)]
pub enum Expr {
    Number {
        id: ExprId,
        value: String,
        span: Span,
    },
    FieldLit {
        id: ExprId,
        value: String,
        radix: FieldRadix,
        span: Span,
    },
    BigIntLit {
        id: ExprId,
        value: String,
        width: u16,
        radix: BigIntRadix,
        span: Span,
    },
    Bool {
        id: ExprId,
        value: bool,
        span: Span,
    },
    StringLit {
        id: ExprId,
        value: String,
        span: Span,
    },
    Nil {
        id: ExprId,
        span: Span,
    },
    Ident {
        id: ExprId,
        name: String,
        span: Span,
    },
    BinOp {
        id: ExprId,
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        span: Span,
    },
    UnaryOp {
        id: ExprId,
        op: UnaryOp,
        operand: Box<Expr>,
        span: Span,
    },
    Call {
        id: ExprId,
        callee: Box<Expr>,
        args: Vec<CallArg>,
        span: Span,
    },
    Index {
        id: ExprId,
        object: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    DotAccess {
        id: ExprId,
        object: Box<Expr>,
        field: String,
        span: Span,
    },
    If {
        id: ExprId,
        condition: Box<Expr>,
        then_block: Block,
        else_branch: Option<ElseBranch>,
        span: Span,
    },
    For {
        id: ExprId,
        var: String,
        iterable: ForIterable,
        body: Block,
        span: Span,
    },
    While {
        id: ExprId,
        condition: Box<Expr>,
        body: Block,
        span: Span,
    },
    Forever {
        id: ExprId,
        body: Block,
        span: Span,
    },
    /// Block expression. The [`ExprId`] is attached to the expression
    /// wrapper; the inner [`Block`] carries its own span but no id.
    Block {
        id: ExprId,
        block: Block,
    },
    FnExpr {
        id: ExprId,
        name: Option<String>,
        params: Vec<TypedParam>,
        return_type: Option<TypeAnnotation>,
        body: Block,
        span: Span,
    },
    Prove {
        id: ExprId,
        /// Optional name: `prove eligibility(hash: Public) { ... }`
        name: Option<String>,
        body: Block,
        /// Typed params with visibility: `prove(hash: Public, flag: Public Bool) { ... }`
        /// When non-empty, witnesses are auto-inferred from outer scope.
        /// Also supports deprecated `prove(public: [x, y])` (converted to params).
        params: Vec<TypedParam>,
        span: Span,
    },
    // CircuitCall removed — unified into Call with keyword CallArgs.
    Array {
        id: ExprId,
        elements: Vec<Expr>,
        span: Span,
    },
    Map {
        id: ExprId,
        pairs: Vec<(MapKey, Expr)>,
        span: Span,
    },
    /// Static access: `Type::MEMBER` (e.g., `Int::MAX`, `Field::ORDER`).
    StaticAccess {
        id: ExprId,
        type_name: String,
        member: String,
        span: Span,
    },
    /// Placeholder for an expression that failed to parse (error recovery).
    Error {
        id: ExprId,
        span: Span,
    },
}

impl Expr {
    /// Borrow the source span covering this expression.
    pub fn span(&self) -> &Span {
        match self {
            Expr::Number { span, .. }
            | Expr::FieldLit { span, .. }
            | Expr::BigIntLit { span, .. }
            | Expr::Bool { span, .. }
            | Expr::StringLit { span, .. }
            | Expr::Nil { span, .. }
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
            | Expr::Map { span, .. }
            | Expr::StaticAccess { span, .. }
            | Expr::Error { span, .. } => span,
            Expr::Block { block, .. } => &block.span,
        }
    }

    /// Return the [`ExprId`] assigned to this expression.
    ///
    /// For parser-produced nodes this id is dense and unique within the
    /// enclosing `Program`. Nodes constructed outside the parser carry
    /// [`ExprId::SYNTHETIC`].
    pub fn id(&self) -> ExprId {
        match self {
            Expr::Number { id, .. }
            | Expr::FieldLit { id, .. }
            | Expr::BigIntLit { id, .. }
            | Expr::Bool { id, .. }
            | Expr::StringLit { id, .. }
            | Expr::Nil { id, .. }
            | Expr::Ident { id, .. }
            | Expr::BinOp { id, .. }
            | Expr::UnaryOp { id, .. }
            | Expr::Call { id, .. }
            | Expr::Index { id, .. }
            | Expr::DotAccess { id, .. }
            | Expr::If { id, .. }
            | Expr::For { id, .. }
            | Expr::While { id, .. }
            | Expr::Forever { id, .. }
            | Expr::Block { id, .. }
            | Expr::FnExpr { id, .. }
            | Expr::Prove { id, .. }
            | Expr::Array { id, .. }
            | Expr::Map { id, .. }
            | Expr::StaticAccess { id, .. }
            | Expr::Error { id, .. } => *id,
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
    Range {
        start: u64,
        end: u64,
    },
    /// Dynamic end bound: `0..n` or `0..(n+1)`.
    /// Start is a literal, end is an expression resolved at instantiation.
    /// Only valid in circuit/prove contexts; VM mode rejects this variant.
    ExprRange {
        start: u64,
        end: Box<Expr>,
    },
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

/// Visibility qualifier for circuit/prove parameters.
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

/// Base type for type annotations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseType {
    Field,
    Bool,
    Int,
    String,
}

impl std::fmt::Display for BaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaseType::Field => write!(f, "Field"),
            BaseType::Bool => write!(f, "Bool"),
            BaseType::Int => write!(f, "Int"),
            BaseType::String => write!(f, "String"),
        }
    }
}

impl BaseType {
    /// Returns true if this type is valid in circuit/prove context (R1CS/Plonkish).
    pub fn is_circuit_type(&self) -> bool {
        matches!(self, BaseType::Field | BaseType::Bool)
    }
}

/// A type annotation for circuit variables, prove parameters, and function parameters.
///
/// ```
/// use achronyme_parser::ast::{TypeAnnotation, BaseType, Visibility};
///
/// let t = TypeAnnotation::field();
/// assert_eq!(format!("{t}"), "Field");
///
/// let arr = TypeAnnotation::bool_array(4);
/// assert_eq!(format!("{arr}"), "Bool[4]");
///
/// let pub_field = TypeAnnotation::public();
/// assert_eq!(format!("{pub_field}"), "Public");
///
/// let wit_arr = TypeAnnotation::new(Some(Visibility::Witness), BaseType::Field, Some(3));
/// assert_eq!(format!("{wit_arr}"), "Witness Field[3]");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeAnnotation {
    pub visibility: Option<Visibility>,
    pub base: BaseType,
    pub array_size: Option<usize>,
}

impl TypeAnnotation {
    pub fn new(visibility: Option<Visibility>, base: BaseType, array_size: Option<usize>) -> Self {
        Self {
            visibility,
            base,
            array_size,
        }
    }

    pub fn field() -> Self {
        Self {
            visibility: None,
            base: BaseType::Field,
            array_size: None,
        }
    }

    pub fn bool() -> Self {
        Self {
            visibility: None,
            base: BaseType::Bool,
            array_size: None,
        }
    }

    pub fn field_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::Field,
            array_size: Some(n),
        }
    }

    pub fn bool_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::Bool,
            array_size: Some(n),
        }
    }

    pub fn int() -> Self {
        Self {
            visibility: None,
            base: BaseType::Int,
            array_size: None,
        }
    }

    pub fn string() -> Self {
        Self {
            visibility: None,
            base: BaseType::String,
            array_size: None,
        }
    }

    pub fn int_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::Int,
            array_size: Some(n),
        }
    }

    pub fn string_array(n: usize) -> Self {
        Self {
            visibility: None,
            base: BaseType::String,
            array_size: Some(n),
        }
    }

    pub fn public() -> Self {
        Self {
            visibility: Some(Visibility::Public),
            base: BaseType::Field,
            array_size: None,
        }
    }

    pub fn witness() -> Self {
        Self {
            visibility: Some(Visibility::Witness),
            base: BaseType::Field,
            array_size: None,
        }
    }

    /// Returns the array size if this is an array type.
    pub fn array_len(&self) -> Option<usize> {
        self.array_size
    }

    /// Returns true if this is an array type.
    pub fn is_array(&self) -> bool {
        self.array_size.is_some()
    }
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vis) = &self.visibility {
            write!(f, "{vis}")?;
            // Only show base type if it's Bool or if there's an array size
            // (Public alone = Public Field, so skip "Field" for brevity)
            if self.base == BaseType::Bool || self.array_size.is_some() {
                write!(f, " {}", self.base)?;
            }
        } else {
            write!(f, "{}", self.base)?;
        }
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
