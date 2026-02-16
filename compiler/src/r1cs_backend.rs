use constraints::r1cs::{ConstraintSystem, Variable};
use std::collections::HashMap;

use crate::r1cs_error::R1CSError;

/// Compiles an Achronyme circuit block into an R1CS constraint system.
///
/// The R1CSCompiler walks the pest AST and emits R1CS constraints instead of
/// bytecode. Each expression evaluates to a `LinearCombination`, and only
/// multiplications / materializations generate actual constraints.
pub struct R1CSCompiler {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem,
    /// Map from Achronyme variable name → R1CS wire.
    pub bindings: HashMap<String, Variable>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
}

impl R1CSCompiler {
    /// Create an empty R1CS compiler with a fresh constraint system.
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
            bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
        }
    }

    /// Declare a public input variable and bind it to `name`.
    ///
    /// Public inputs must be declared before witnesses to maintain the
    /// snarkjs-compatible wire layout.
    pub fn declare_public(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_input();
        self.bindings.insert(name.to_string(), var);
        self.public_inputs.push(name.to_string());
        var
    }

    /// Declare a private witness variable and bind it to `name`.
    pub fn declare_witness(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_witness();
        self.bindings.insert(name.to_string(), var);
        self.witnesses.push(name.to_string());
        var
    }

    /// Look up a previously declared variable by name.
    pub fn lookup(&self, name: &str) -> Result<Variable, R1CSError> {
        self.bindings
            .get(name)
            .copied()
            .ok_or_else(|| R1CSError::UndeclaredVariable(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_compiler_is_empty() {
        let rc = R1CSCompiler::new();
        assert_eq!(rc.cs.num_variables(), 1); // only ONE wire
        assert_eq!(rc.cs.num_pub_inputs(), 0);
        assert_eq!(rc.cs.num_constraints(), 0);
        assert!(rc.bindings.is_empty());
        assert!(rc.public_inputs.is_empty());
        assert!(rc.witnesses.is_empty());
    }

    #[test]
    fn test_declare_public() {
        let mut rc = R1CSCompiler::new();
        let var = rc.declare_public("root");

        assert_eq!(var.index(), 1); // first public after ONE
        assert_eq!(rc.cs.num_pub_inputs(), 1);
        assert_eq!(rc.public_inputs, vec!["root"]);
        assert_eq!(rc.lookup("root").unwrap(), var);
    }

    #[test]
    fn test_declare_witness() {
        let mut rc = R1CSCompiler::new();
        // Declare a public first to test ordering
        let pub_var = rc.declare_public("out");
        let wit_var = rc.declare_witness("secret");

        assert_eq!(pub_var.index(), 1);
        assert_eq!(wit_var.index(), 2);
        assert_eq!(rc.witnesses, vec!["secret"]);
        assert_eq!(rc.lookup("secret").unwrap(), wit_var);
    }

    #[test]
    fn test_declare_multiple() {
        let mut rc = R1CSCompiler::new();
        let a = rc.declare_public("a");
        let b = rc.declare_public("b");
        let c = rc.declare_witness("c");
        let d = rc.declare_witness("d");

        assert_eq!(a.index(), 1);
        assert_eq!(b.index(), 2);
        assert_eq!(c.index(), 3);
        assert_eq!(d.index(), 4);
        assert_eq!(rc.cs.num_variables(), 5);
        assert_eq!(rc.cs.num_pub_inputs(), 2);
        assert_eq!(rc.public_inputs, vec!["a", "b"]);
        assert_eq!(rc.witnesses, vec!["c", "d"]);
    }

    #[test]
    fn test_lookup_undeclared() {
        let rc = R1CSCompiler::new();
        let err = rc.lookup("nonexistent").unwrap_err();
        match err {
            R1CSError::UndeclaredVariable(name) => assert_eq!(name, "nonexistent"),
            _ => panic!("expected UndeclaredVariable"),
        }
    }

    #[test]
    fn test_lookup_returns_correct_variable() {
        let mut rc = R1CSCompiler::new();
        let x = rc.declare_witness("x");
        let y = rc.declare_witness("y");

        assert_eq!(rc.lookup("x").unwrap(), x);
        assert_eq!(rc.lookup("y").unwrap(), y);
        assert!(rc.lookup("z").is_err());
    }

    #[test]
    fn test_rebinding_overwrites() {
        let mut rc = R1CSCompiler::new();
        let v1 = rc.declare_witness("x");
        let v2 = rc.declare_witness("x"); // rebind same name

        // The binding should point to the latest variable
        assert_eq!(rc.lookup("x").unwrap(), v2);
        assert_ne!(v1, v2);
    }
}
