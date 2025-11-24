#[derive(Debug, Clone, PartialEq)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Subtract,
    Multiply,
    Divide,
    Power,
    Modulo,

    // Comparison
    Gt,  // >
    Lt,  // <
    Gte, // >=
    Lte, // <=
    Eq,  // ==
    Neq, // !=

    // Logical
    And, // &&
    Or,  // ||
}

#[derive(Debug, Clone, PartialEq)]
pub enum UnaryOp {
    Negate, // -x
    Not,    // !x
}

/// Compound assignment operators: +=, -=, *=, /=, %=, ^=
#[derive(Debug, Clone, PartialEq)]
pub enum CompoundOp {
    AddAssign, // +=
    SubAssign, // -=
    MulAssign, // *=
    DivAssign, // /=
    ModAssign, // %=
    PowAssign, // ^=
}

// Import TypeAnnotation from local module (avoids circular dependency)
use crate::type_annotation::TypeAnnotation;

#[derive(Debug, Clone, PartialEq)]
pub enum AstNode {
    Number(f64),
    Boolean(bool),
    StringLiteral(String),
    /// Null literal (for optional types)
    Null,
    BinaryOp {
        op: BinaryOp,
        left: Box<AstNode>,
        right: Box<AstNode>,
    },
    UnaryOp {
        op: UnaryOp,
        operand: Box<AstNode>,
    },
    If {
        condition: Box<AstNode>,
        then_expr: Box<AstNode>,
        else_expr: Box<AstNode>,
    },
    Piecewise {
        cases: Vec<(Box<AstNode>, Box<AstNode>)>,
        default: Option<Box<AstNode>>,
    },
    FunctionCall {
        name: String,
        args: Vec<AstNode>,
    },
    CallExpression {
        callee: Box<AstNode>, // Expression that evaluates to a function (for IIFE)
        args: Vec<AstNode>,
    },
    ComplexLiteral {
        re: f64,
        im: f64,
    },
    ArrayLiteral(Vec<ArrayElement>), // Array elements can be single values or spread expressions
    RecordLiteral(Vec<RecordFieldOrSpread>), // Record fields or spread expressions
    FieldAccess {
        record: Box<AstNode>,
        field: String,
    },
    VariableDecl {
        name: String,
        type_annotation: Option<TypeAnnotation>, // Optional type annotation
        initializer: Box<AstNode>,
    },
    MutableDecl {
        name: String,
        type_annotation: Option<TypeAnnotation>, // Optional type annotation
        initializer: Box<AstNode>,
    },
    /// Destructuring let binding: let { x, y } = value or let [a, b] = value
    LetDestructuring {
        pattern: Pattern,
        type_annotation: Option<TypeAnnotation>, // Optional type annotation
        initializer: Box<AstNode>,
    },
    /// Mutable destructuring binding: mut { x, y } = value or mut [a, b] = value
    MutableDestructuring {
        pattern: Pattern,
        type_annotation: Option<TypeAnnotation>, // Optional type annotation
        initializer: Box<AstNode>,
    },
    Assignment {
        target: Box<AstNode>, // postfix_expression (variable, field access, index)
        value: Box<AstNode>,
    },
    /// Compound assignment: x += 5, obj.field -= 3, arr[0] *= 2
    CompoundAssignment {
        target: Box<AstNode>, // identifier, field access, or index
        operator: CompoundOp, // +=, -=, *=, /=, %=, ^=
        value: Box<AstNode>,  // expression to apply
    },
    Return {
        value: Box<AstNode>, // Expression to return
    },
    VariableRef(String),
    SelfReference, // 'self' keyword for use in records
    RecReference,  // 'rec' keyword for recursive function calls
    /// Lambda with optional type annotations (gradual typing)
    /// params: list of (param_name, optional_type_annotation, optional_default_value)
    /// return_type: optional return type annotation
    Lambda {
        params: Vec<(String, Option<TypeAnnotation>, Option<Box<AstNode>>)>,
        return_type: Option<TypeAnnotation>,
        body: Box<AstNode>,
    },
    // Indexing and slicing
    IndexAccess {
        object: Box<AstNode>,
        indices: Vec<IndexArg>,
    },
    // Sequence: multiple statements separated by semicolons
    // Example: let a = 1; let b = 2; a + b
    // The last statement is the value of the sequence
    Sequence {
        statements: Vec<AstNode>,
    },
    // DoBlock: do { statements }
    // Similar to Sequence but explicitly wrapped in a do { } block
    // Used in lambda bodies: x => do { let a = x * 2; a + 10 }
    DoBlock {
        statements: Vec<AstNode>,
    },
    // While loop: while(condition) { body }
    // Executes body repeatedly while condition is true
    // Returns the value of the last iteration, or 0 if never executed
    WhileLoop {
        condition: Box<AstNode>,
        body: Box<AstNode>,
    },
    // Import statement: import { sin, cos } from "math"
    // Supports aliasing: import { mean as average } from "stats"
    Import {
        items: Vec<ImportItem>,
        module_path: String,
    },
    // Export statement: export { foo, bar }
    // For future use when we support user-defined modules
    Export {
        items: Vec<ImportItem>,
    },
    // Type alias statement: type Name = TypeAnnotation
    // Creates a named alias for a type
    TypeAlias {
        name: String,
        type_definition: TypeAnnotation,
    },
    // Yield statement: yield expr
    // Suspends generator execution and returns the value
    Yield {
        value: Box<AstNode>,
    },
    // Generate block: generate { statements }
    // Creates a generator function that can be paused and resumed
    GenerateBlock {
        statements: Vec<AstNode>,
    },
    // For-in loop: for(variable in iterable) { body }
    // Iterates over an iterator (object with next() method)
    ForInLoop {
        variable: String,
        iterable: Box<AstNode>,
        body: Box<AstNode>,
    },
    // Throw statement: throw expr
    // Throws an error that can be caught by try/catch
    Throw {
        value: Box<AstNode>,
    },
    // Try-catch expression: try { block } catch(error) { block }
    // Error handling with scoped error binding
    TryCatch {
        try_block: Box<AstNode>,
        error_param: String,
        catch_block: Box<AstNode>,
    },
    // Match expression: match value { pattern => expr, ... }
    // Pattern matching with destructuring and guards
    Match {
        value: Box<AstNode>,
        arms: Vec<MatchArm>,
    },
    // Break statement: break [expr]
    // Exits the current loop, optionally returning a value
    // Only valid inside while/for loops
    Break {
        value: Option<Box<AstNode>>,
    },
    // Continue statement: continue
    // Skips to the next iteration of the current loop
    // Only valid inside while/for loops
    Continue,
    // Interpolated string: 'Hello, ${name}!'
    // Parts are literals or expressions to be evaluated
    InterpolatedString {
        parts: Vec<StringPart>,
    },
    // Range expression: 1..5 (exclusive) or 1..=5 (inclusive)
    // Generates a vector of integers from start to end
    // Only valid for integer ranges (floats will be truncated)
    RangeExpr {
        start: Box<AstNode>,
        end: Box<AstNode>,
        inclusive: bool, // true for ..=, false for ..
    },
}

/// Represents a part of an interpolated string
#[derive(Debug, Clone, PartialEq)]
pub enum StringPart {
    /// Literal text portion
    Literal(String),
    /// Expression to be evaluated and converted to string: ${expr}
    Expression(Box<AstNode>),
}

/// Represents an array element - can be a single expression or a spread expression
#[derive(Debug, Clone, PartialEq)]
pub enum ArrayElement {
    Single(AstNode),      // Regular element: expr
    Spread(Box<AstNode>), // Spread element: ...expr
}

/// Represents a record field or spread expression
#[derive(Debug, Clone, PartialEq)]
pub enum RecordFieldOrSpread {
    Field { name: String, value: AstNode }, // Immutable field: key: value
    MutableField { name: String, value: AstNode }, // Mutable field: mut key: value
    Spread(Box<AstNode>),                   // Spread: ...expr
}

/// Represents an indexing argument - can be a single expression or a range
#[derive(Debug, Clone, PartialEq)]
pub enum IndexArg {
    Single(Box<AstNode>), // Single index: tensor[5]
    Range {
        // Range slice: tensor[1..5], tensor[..5], tensor[1..], tensor[..]
        start: Option<Box<AstNode>>,
        end: Option<Box<AstNode>>,
    },
}

/// Represents an import item - can be a simple identifier or an aliased import
/// Examples: foo, foo as bar
#[derive(Debug, Clone, PartialEq)]
pub struct ImportItem {
    pub name: String,          // The original name in the module
    pub alias: Option<String>, // Optional alias (for "as" imports)
}

impl ImportItem {
    /// Get the local name (alias if present, otherwise original name)
    pub fn local_name(&self) -> &str {
        self.alias.as_deref().unwrap_or(&self.name)
    }
}

/// Pattern for pattern matching
/// Used in match expressions to destructure and test values
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Literal pattern: matches exact values (42, "hello", true)
    Literal(LiteralPattern),

    /// Variable pattern: binds the matched value to a name (x, name)
    Variable(String),

    /// Wildcard pattern: matches anything, ignores the value (_)
    Wildcard,

    /// Record pattern: destructures record fields ({ name: n, age: a })
    /// Now with optional default values: { name, age = 25 }
    Record {
        fields: Vec<(String, Pattern, Option<Box<AstNode>>)>, // (field_name, pattern, optional_default)
    },

    /// Vector pattern: matches array structure ([x, y, ...rest])
    /// Now with optional default values: [first = 0, second = 0]
    Vector { elements: Vec<VectorPatternElement> },

    /// Type pattern: matches by runtime type (Number, String, Error)
    Type(String),
}

/// Literal pattern variants
#[derive(Debug, Clone, PartialEq)]
pub enum LiteralPattern {
    Number(f64),
    String(String),
    Boolean(bool),
    Null,
}

/// Vector pattern element: either a pattern or a rest pattern
/// Now with optional default values: [first = 0, second = 0]
#[derive(Debug, Clone, PartialEq)]
pub enum VectorPatternElement {
    /// Regular pattern element with optional default value
    Pattern(Pattern, Option<Box<AstNode>>),
    /// Rest pattern: ...identifier (captures remaining elements)
    Rest(String),
}

/// Match arm: a single case in a match expression
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Box<AstNode>>, // Optional if condition
    pub body: Box<AstNode>,
}
