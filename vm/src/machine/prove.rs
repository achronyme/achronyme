use std::collections::HashMap;

use memory::{FieldElement, Heap, Value};

use crate::error::RuntimeError;
use crate::opcode::instruction::{decode_a, decode_bx};

use super::stack::StackOps;
use super::vm::VM;

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
    ) -> Result<(), String>;
}

/// Convert a VM `Value` to a `FieldElement` for prove block capture.
///
/// Supports:
/// - `field(...)` values → direct copy
/// - integer values → `FieldElement::from_i64`
/// - number (f64) values that are whole → `FieldElement::from_i64`
/// - everything else → `None`
pub fn value_to_field_element(heap: &Heap, val: Value) -> Option<FieldElement> {
    if val.is_field() {
        let handle = val.as_handle()?;
        heap.get_field(handle).copied()
    } else if val.is_int() {
        let i = val.as_int()?;
        Some(FieldElement::from_i64(i as i64))
    } else if val.is_number() {
        let n = val.as_number()?;
        // Only convert whole numbers
        if n.fract() == 0.0 && n.abs() < (i64::MAX as f64) {
            Some(FieldElement::from_i64(n as i64))
        } else {
            None
        }
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
        let map_val = self.get_reg(base, a);
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

        // 3. Delegate to the handler
        let handler = self
            .prove_handler
            .as_ref()
            .ok_or(RuntimeError::ProveHandlerNotConfigured)?;

        handler
            .execute_prove(&source, &scope_values)
            .map_err(RuntimeError::ProveBlockFailed)?;

        // 4. Result is nil
        self.set_reg(base, a, Value::nil());

        Ok(())
    }
}
