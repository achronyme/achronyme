use std::collections::HashMap;
use std::fmt;

use memory::{FieldElement, Heap, ProofObject, Value};

use crate::error::RuntimeError;
use crate::opcode::instruction::{decode_a, decode_bx};

use super::stack::StackOps;
use super::vm::VM;

/// Result of executing a `prove { }` block.
pub enum ProveResult {
    /// Verify-only mode (proof generation not requested)
    VerifiedOnly,
    /// Groth16 proof generated
    Proof {
        proof_json: String,
        public_json: String,
        vkey_json: String,
    },
}

/// Typed error for prove block failures, categorized by pipeline phase.
#[derive(Debug, Clone, PartialEq)]
pub enum ProveError {
    /// IR lowering failed (parsing / AST → IR conversion)
    IrLowering(String),
    /// Constraint compilation failed (IR → R1CS/Plonkish)
    Compilation(String),
    /// Constraint verification failed
    Verification(String),
    /// Proof generation failed (Groth16 / halo2)
    ProofGeneration(String),
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProveError::IrLowering(msg) => write!(f, "IR lowering: {msg}"),
            ProveError::Compilation(msg) => write!(f, "compilation: {msg}"),
            ProveError::Verification(msg) => write!(f, "verification: {msg}"),
            ProveError::ProofGeneration(msg) => write!(f, "proof generation: {msg}"),
        }
    }
}

/// Trait for handling `prove { }` blocks at runtime.
///
/// The VM calls this when it encounters a `Prove` opcode.
/// The implementation is responsible for compiling the circuit source,
/// generating constraints, computing the witness, and verifying.
pub trait ProveHandler {
    fn execute_prove(
        &self,
        source: &str,
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError>;
}

/// Convert a VM `Value` to a `FieldElement` for prove block capture.
///
/// Supports:
/// - `field(...)` values → direct copy
/// - integer values → `FieldElement::from_i64`
/// - everything else → `None`
pub fn value_to_field_element(heap: &Heap, val: Value) -> Option<FieldElement> {
    if val.is_field() {
        let handle = val.as_handle()?;
        heap.get_field(handle).copied()
    } else if val.is_int() {
        let i = val.as_int()?;
        Some(FieldElement::from_i64(i))
    } else {
        None
    }
}

impl VM {
    /// Handle the `Prove` opcode: extract capture map + source, delegate to handler.
    pub fn handle_prove(
        &mut self,
        instruction: u32,
        base: usize,
        closure_idx: u32,
    ) -> Result<(), RuntimeError> {
        // 0. Check handler is configured before doing any work
        if self.prove_handler.is_none() {
            return Err(RuntimeError::ProveHandlerNotConfigured);
        }

        let a = decode_a(instruction) as usize;
        let bx = decode_bx(instruction) as usize;

        // 1. Get the source string from the constant pool
        let source = {
            let closure = self
                .heap
                .get_closure(closure_idx)
                .ok_or(RuntimeError::FunctionNotFound)?;
            let func = self
                .heap
                .get_function(closure.function)
                .ok_or(RuntimeError::FunctionNotFound)?;
            let val = func
                .constants
                .get(bx)
                .ok_or(RuntimeError::OutOfBounds("prove source constant".into()))?;
            let handle = val
                .as_handle()
                .ok_or(RuntimeError::TypeMismatch("prove source not a string".into()))?;
            self.heap
                .get_string(handle)
                .cloned()
                .ok_or(RuntimeError::SystemError("prove source string missing".into()))?
        };

        // 2. Read the capture map from R[A]
        let map_val = self.get_reg(base, a)?;
        let map_handle = map_val
            .as_handle()
            .ok_or(RuntimeError::TypeMismatch("prove capture not a map".into()))?;

        let scope_values = {
            let map = self
                .heap
                .get_map(map_handle)
                .ok_or(RuntimeError::SystemError("prove capture map missing".into()))?;

            let mut field_map = HashMap::new();
            for (key, val) in map.iter() {
                let fe = value_to_field_element(&self.heap, *val).ok_or_else(|| {
                    RuntimeError::TypeMismatch(format!(
                        "prove: variable `{key}` is not a numeric/field type"
                    ))
                })?;
                field_map.insert(key.clone(), fe);
            }
            field_map
        };

        // 3. Delegate to the handler (unwrap safe: checked at step 0)
        let handler = self.prove_handler.as_ref().unwrap();

        let result = handler
            .execute_prove(&source, &scope_values)
            .map_err(RuntimeError::ProveBlockFailed)?;

        // 4. Set result based on handler response
        match result {
            ProveResult::VerifiedOnly => {
                self.set_reg(base, a, Value::nil())?;
            }
            ProveResult::Proof {
                proof_json,
                public_json,
                vkey_json,
            } => {
                let obj = ProofObject {
                    proof_json,
                    public_json,
                    vkey_json,
                };
                let handle = self.heap.alloc_proof(obj);
                self.set_reg(base, a, Value::proof(handle))?;
            }
        }

        Ok(())
    }
}
