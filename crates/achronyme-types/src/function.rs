use crate::environment::Environment;
use achronyme_parser::ast::AstNode;
use achronyme_parser::type_annotation::TypeAnnotation;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Function representation - can be either a user-defined lambda or a built-in function
///
/// User-defined lambda example:
/// ```text
/// let x = 10;
/// let f = y => x + y;  // Captures 'x' from outer scope
/// f(5)  // Returns 15
/// ```
///
/// Built-in function example:
/// ```text
/// let f = sin;  // References built-in sin function
/// f(0)  // Returns 0
/// ```
///
/// PERFORMANCE OPTIMIZATION: The UserDefined variant now captures an Rc<RefCell<Environment>>
/// instead of a HashMap. This makes closure creation O(1) instead of O(n) where n
/// is the number of variables in scope. This is a MAJOR performance improvement for
/// recursive functions and deeply nested scopes.
///
/// The RefCell wrapper allows mutation of captured variables declared with `mut`.
#[derive(Clone)]
pub enum Function {
    /// User-defined lambda with closure
    UserDefined {
        params: Vec<String>,
        /// Type annotations for parameters (None means no type checking)
        param_types: Vec<Option<TypeAnnotation>>,
        /// Default values for parameters (None means no default)
        /// The AstNode is evaluated at call time with access to closure environment
        param_defaults: Vec<Option<Rc<AstNode>>>,
        /// Return type annotation (None means no type checking)
        return_type: Option<TypeAnnotation>,
        body: Rc<AstNode>,
        /// Captured environment - using Rc<RefCell> makes this cheap to clone
        /// and allows mutation of mutable captured variables
        closure_env: Rc<RefCell<Environment>>,
    },
    /// Built-in function by name
    Builtin(String),
    /// VM-compiled closure (bytecode)
    /// Uses Rc<dyn Any> to avoid circular dependency with achronyme-vm
    VmClosure(Rc<dyn Any>),
}

impl std::fmt::Debug for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Function::UserDefined { params, .. } => {
                write!(f, "UserDefined {{ params: {:?}, ... }}", params)
            }
            Function::Builtin(name) => write!(f, "Builtin({:?})", name),
            Function::VmClosure(_) => write!(f, "VmClosure(..)"),
        }
    }
}

impl Function {
    /// Create a new user-defined lambda function (DEPRECATED - use new_with_env)
    ///
    /// This method is kept for backward compatibility but creates an Environment
    /// from the HashMap which is less efficient. Prefer `new_with_env`.
    pub fn new(
        params: Vec<String>,
        body: AstNode,
        captured_vars: HashMap<String, crate::value::Value>,
    ) -> Self {
        let env = Environment::from_snapshot(captured_vars);
        let param_count = params.len();
        Function::UserDefined {
            params,
            param_types: vec![None; param_count], // No type checking for legacy API
            param_defaults: vec![None; param_count], // No defaults for legacy API
            return_type: None,
            body: Rc::new(body),
            closure_env: Rc::new(RefCell::new(env)),
        }
    }

    /// Create a new user-defined lambda function with an environment (PREFERRED)
    ///
    /// This is the optimized way to create closures - it just increments the Rc counter
    /// instead of copying all variables.
    pub fn new_with_env(
        params: Vec<String>,
        body: AstNode,
        closure_env: Rc<RefCell<Environment>>,
    ) -> Self {
        let param_count = params.len();
        Function::UserDefined {
            params,
            param_types: vec![None; param_count], // No type checking
            param_defaults: vec![None; param_count], // No defaults
            return_type: None,
            body: Rc::new(body),
            closure_env,
        }
    }

    /// Create a new user-defined lambda function with type annotations (PREFERRED)
    ///
    /// This is the full-featured way to create typed closures.
    pub fn new_typed(
        params: Vec<String>,
        param_types: Vec<Option<TypeAnnotation>>,
        return_type: Option<TypeAnnotation>,
        body: AstNode,
        closure_env: Rc<RefCell<Environment>>,
    ) -> Self {
        let param_count = params.len();
        Function::UserDefined {
            params,
            param_types,
            param_defaults: vec![None; param_count], // No defaults (legacy compatibility)
            return_type,
            body: Rc::new(body),
            closure_env,
        }
    }

    /// Create a new user-defined lambda function with type annotations AND default values
    ///
    /// This is the full-featured way to create typed closures with parameter defaults.
    pub fn new_typed_with_defaults(
        params: Vec<String>,
        param_types: Vec<Option<TypeAnnotation>>,
        param_defaults: Vec<Option<Rc<AstNode>>>,
        return_type: Option<TypeAnnotation>,
        body: AstNode,
        closure_env: Rc<RefCell<Environment>>,
    ) -> Self {
        Function::UserDefined {
            params,
            param_types,
            param_defaults,
            return_type,
            body: Rc::new(body),
            closure_env,
        }
    }

    /// Create a reference to a built-in function
    pub fn builtin(name: String) -> Self {
        Function::Builtin(name)
    }

    /// Get arity (number of parameters)
    /// Returns None for built-in functions (arity depends on the specific function)
    pub fn arity(&self) -> usize {
        match self {
            Function::UserDefined { params, .. } => params.len(),
            Function::Builtin(_) => 0, // Built-in functions handle their own arity checking
            Function::VmClosure(_) => 0, // VM closures handle their own arity checking
        }
    }

    /// Check if this is a built-in function
    pub fn is_builtin(&self) -> bool {
        matches!(self, Function::Builtin(_))
    }

    /// Get the name of a built-in function, if applicable
    pub fn builtin_name(&self) -> Option<&str> {
        match self {
            Function::Builtin(name) => Some(name),
            _ => None,
        }
    }
}

impl PartialEq for Function {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Function::UserDefined {
                    params: p1,
                    param_types: pt1,
                    param_defaults: pd1,
                    return_type: rt1,
                    body: b1,
                    closure_env: e1,
                },
                Function::UserDefined {
                    params: p2,
                    param_types: pt2,
                    param_defaults: pd2,
                    return_type: rt2,
                    body: b2,
                    closure_env: e2,
                },
            ) => {
                p1 == p2
                    && pt1 == pt2
                    && pd1.len() == pd2.len()
                    && rt1 == rt2
                    && Rc::ptr_eq(b1, b2)
                    && Rc::ptr_eq(e1, e2)
            }
            (Function::Builtin(n1), Function::Builtin(n2)) => n1 == n2,
            (Function::VmClosure(c1), Function::VmClosure(c2)) => Rc::ptr_eq(c1, c2),
            _ => false,
        }
    }
}
