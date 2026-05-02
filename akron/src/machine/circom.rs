//! Runtime dispatch for circom template calls.
//!
//! The `CallCircomTemplate` opcode needs to invoke a real circom
//! template at VM execution time — but `vm` sits below the `circom`
//! crate in the dependency graph, so the actual instantiation has
//! to happen through an injected handler the CLI wires up at
//! program-run time. Same shape as `prove_handler` / `verify_handler`.
//!
//! This file defines:
//!
//! - [`CircomCallError`]: typed error reasons the handler can
//!   surface back to the VM (handler missing, unknown library id,
//!   witness evaluation failure, output-to-Value marshalling
//!   failure).
//! - [`CircomWitnessHandler`]: trait the compiler crate will
//!   implement with `Arc<CircomLibrary>` handles, evaluating the
//!   template via `circom::evaluate_template_witness` and returning
//!   a [`CircomCallResult`] with output field elements ready for
//!   the VM to marshal into `Value`s.
//! - [`VM::handle_call_circom_template`]: the opcode dispatcher —
//!   reads the `CircomHandle` out of R[B-1], collects the signal
//!   inputs from R[B..B+C], calls the handler, and writes the
//!   projected result into R[A].

use std::collections::HashMap;
use std::fmt;

use memory::{CircomHandle, FieldElement, Value};

use crate::error::RuntimeError;
use crate::opcode::instruction::{decode_a, decode_b, decode_c};

use super::stack::StackOps;
use super::vm::VM;

// ---------------------------------------------------------------------------
// Result + error types
// ---------------------------------------------------------------------------

/// A single declared output of an instantiated circom template as
/// it flows back from the handler into the VM.
///
/// Mirrors `ir_forge::CircomTemplateOutput` / the circom
/// library's `TemplateOutputValue`, but with field elements
/// materialized into a form the VM can marshal into `Value`s
/// without circular dependencies on the ir crate.
#[derive(Debug, Clone)]
pub enum CircomOutputValue {
    /// Single scalar output — one field element.
    Scalar(FieldElement),
    /// Array output in row-major order. `dims` records the shape
    /// so the dispatcher can build a nested list if needed;
    /// multi-dimensional outputs flatten into a single list of
    /// field elements.
    Array {
        dims: Vec<u64>,
        values: Vec<FieldElement>,
    },
}

/// Result of a handler-side circom template invocation.
///
/// `outputs` is keyed by the original declared output signal name
/// (not mangled). Templates with a single output have a single
/// entry; multi-output templates have one per declared output.
#[derive(Debug, Clone)]
pub struct CircomCallResult {
    pub outputs: HashMap<String, CircomOutputValue>,
}

/// Typed error for circom template dispatch at runtime.
#[derive(Debug, Clone, PartialEq)]
pub enum CircomCallError {
    /// No handler was injected before `vm.interpret()` was called.
    HandlerNotConfigured,
    /// The compile-time library id does not map to any entry in
    /// the handler's registry. Usually means the compiler-side
    /// registry diverged from the run-time one.
    UnknownLibraryId(u32),
    /// A signal input arrived as a VM value the handler does not
    /// know how to marshal (e.g. a string where a field was
    /// expected). Carries the signal index for diagnostics.
    InvalidSignalInput { index: usize, reason: String },
    /// Underlying witness evaluation returned an error.
    WitnessEvaluation(String),
    /// Template returned an output the handler could not marshal
    /// back into a VM value.
    OutputMarshalling(String),
}

impl fmt::Display for CircomCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandlerNotConfigured => write!(
                f,
                "circom template handler not configured — call `vm.circom_handler = Some(...)` \
                 before running programs that import circom templates"
            ),
            Self::UnknownLibraryId(id) => write!(
                f,
                "circom library id {id} is not registered in the handler — \
                 compiler-side registry is out of sync with the VM"
            ),
            Self::InvalidSignalInput { index, reason } => write!(
                f,
                "invalid circom signal input at position {index}: {reason}"
            ),
            Self::WitnessEvaluation(msg) => write!(f, "circom witness evaluation: {msg}"),
            Self::OutputMarshalling(msg) => write!(f, "circom output marshalling: {msg}"),
        }
    }
}

impl std::error::Error for CircomCallError {}

// ---------------------------------------------------------------------------
// Handler trait
// ---------------------------------------------------------------------------

/// Runtime dispatcher for circom template calls.
///
/// The compiler crate implements this with a registry of
/// `Arc<CircomLibrary>` entries — the same Arcs it seeded
/// `OuterScope.circom_imports` with at compile time. The VM owns
/// the trait object via `vm.circom_handler` and calls
/// [`invoke`](CircomWitnessHandler::invoke) every time a
/// `CallCircomTemplate` opcode fires.
///
/// The trait takes `&self` (not `&mut`) on purpose: handlers are
/// logically stateless with respect to the VM — they hold shared
/// Arcs to compiled libraries and do not need per-call mutation.
/// This also keeps the VM's borrow flow simple at the opcode site.
pub trait CircomWitnessHandler: Send + Sync {
    /// Evaluate `handle.template_name` from library `handle.library_id`
    /// against `signal_inputs` in the library's declared-order.
    ///
    /// The handler is responsible for:
    /// 1. Looking up the library by `handle.library_id`.
    /// 2. Mapping positional signal inputs onto the library's
    ///    declared input-signal names.
    /// 3. Calling `circom::evaluate_template_witness` or equivalent.
    /// 4. Returning the outputs as field elements, keyed by the
    ///    declared output-signal names.
    fn invoke(
        &self,
        handle: &CircomHandle,
        signal_inputs: &[FieldElement],
    ) -> Result<CircomCallResult, CircomCallError>;
}

// ---------------------------------------------------------------------------
// Opcode dispatcher
// ---------------------------------------------------------------------------

impl VM {
    /// Handle the `CallCircomTemplate` opcode.
    ///
    /// Layout: `R[A] = CircomCall(R[B-1] as handle, R[B..B+C] as inputs)`.
    ///
    /// 1. Resolve the circom handle sitting at R[B-1] (put there by
    ///    a prior `LoadConst` of a `Value::circom_handle(...)`).
    /// 2. Collect signal inputs from R[B..B+C] and marshal them
    ///    into `FieldElement`s.
    /// 3. Invoke the injected `circom_handler`.
    /// 4. Marshal the returned outputs back into a single VM value
    ///    and write it to R[A]:
    ///    - Single scalar output → `Value::field(...)`.
    ///    - Single array output  → `Value::list(...)` of fields.
    ///    - Multi-output         → `Value::map(...)` keyed by output
    ///      signal name.
    pub fn handle_call_circom_template(
        &mut self,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError> {
        // Precondition: a handler must be configured before this
        // opcode can execute. Mirror prove_handler's behavior.
        if self.circom_handler.is_none() {
            return Err(RuntimeError::CircomHandlerNotConfigured);
        }

        let a = decode_a(instruction) as usize;
        let b = decode_b(instruction) as usize;
        let c = decode_c(instruction) as usize;

        // 1. Load the circom handle from R[B-1]. Following the same
        //    convention MethodCall uses for its method-name slot.
        if b == 0 {
            return Err(RuntimeError::type_mismatch(
                "CallCircomTemplate: input base register cannot be 0 \
                 (handle must live at R[B-1])",
            ));
        }
        let handle_val = self.get_reg(base, b - 1)?;
        if !handle_val.is_circom_handle() {
            return Err(RuntimeError::type_mismatch(
                "CallCircomTemplate handle slot is not a circom handle",
            ));
        }
        let handle_idx = handle_val.as_handle().ok_or_else(|| {
            RuntimeError::type_mismatch("CallCircomTemplate handle slot is not a heap handle")
        })?;
        let handle = self
            .heap
            .get_circom_handle(handle_idx)
            .ok_or_else(|| RuntimeError::stale_heap("CircomHandle", "CallCircomTemplate"))?
            .clone();

        // 2. Marshal signal inputs R[B..B+C] into FieldElements.
        let mut signal_inputs: Vec<FieldElement> = Vec::with_capacity(c);
        for i in 0..c {
            let reg = b + i;
            let val = self.get_reg(base, reg)?;
            let fe = super::prove::value_to_field_element(&self.heap, val).ok_or_else(|| {
                RuntimeError::type_mismatch(
                    "CallCircomTemplate: signal input is not a field-compatible value",
                )
            })?;
            signal_inputs.push(fe);
        }

        // 3. Dispatch to the handler.
        let result = {
            let handler = self
                .circom_handler
                .as_ref()
                .ok_or(RuntimeError::CircomHandlerNotConfigured)?;
            handler.invoke(&handle, &signal_inputs).map_err(|e| {
                RuntimeError::resource_limit_exceeded(format!("CallCircomTemplate: {e}"))
            })?
        };

        // 4. Marshal the outputs into a single Value and write it
        //    into R[A]. Projection rules:
        //    - Single scalar output   → Value::field
        //    - Single 1D array output → Value::list of fields
        //    - Multi-output           → Value::map keyed by output name
        let output_value = marshal_outputs_to_value(self, result)?;
        self.set_reg(base, a, output_value)?;
        Ok(())
    }
}

/// Projection helper: convert the handler's structured result into
/// a single VM `Value`. Kept out of the VM impl so the borrow on
/// `self.circom_handler` is dropped before we touch the heap.
fn marshal_outputs_to_value(vm: &mut VM, result: CircomCallResult) -> Result<Value, RuntimeError> {
    // Single-entry outputs cover the scalar + array case.
    if result.outputs.len() == 1 {
        let (_, only) = result.outputs.into_iter().next().unwrap();
        return match only {
            CircomOutputValue::Scalar(fe) => {
                let field_handle = vm.heap.alloc_field(fe).map_err(RuntimeError::from)?;
                Ok(Value::field(field_handle))
            }
            CircomOutputValue::Array { values, .. } => alloc_field_list(vm, values),
        };
    }

    // Multi-output templates: materialize a Map keyed by the
    // declared output-signal name. Array-valued outputs become
    // nested lists inside the map.
    let mut map: std::collections::HashMap<String, Value> =
        std::collections::HashMap::with_capacity(result.outputs.len());
    for (name, out) in result.outputs {
        let val = match out {
            CircomOutputValue::Scalar(fe) => {
                let h = vm.heap.alloc_field(fe).map_err(RuntimeError::from)?;
                Value::field(h)
            }
            CircomOutputValue::Array { values, .. } => alloc_field_list(vm, values)?,
        };
        map.insert(name, val);
    }
    let map_handle = vm.heap.alloc_map(map).map_err(RuntimeError::from)?;
    Ok(Value::map(map_handle))
}

/// Allocate a VM list value containing each field element as a
/// `Value::field` entry.
fn alloc_field_list(vm: &mut VM, fields: Vec<FieldElement>) -> Result<Value, RuntimeError> {
    let mut list: Vec<Value> = Vec::with_capacity(fields.len());
    for fe in fields {
        let h = vm.heap.alloc_field(fe).map_err(RuntimeError::from)?;
        list.push(Value::field(h));
    }
    let list_handle = vm.heap.alloc_list(list).map_err(RuntimeError::from)?;
    Ok(Value::list(list_handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::{instruction::encode_abc, OpCode};

    fn handle(name: &str) -> CircomHandle {
        CircomHandle {
            library_id: 0,
            template_name: name.to_string(),
            template_args: vec![],
        }
    }

    /// Handler that records invocations and replays a preprogrammed
    /// result. Shared scaffolding for the dispatch tests below.
    struct StubHandler {
        result: std::sync::Mutex<CircomCallResult>,
        seen: std::sync::Mutex<Vec<(CircomHandle, Vec<FieldElement>)>>,
    }

    impl StubHandler {
        fn new(result: CircomCallResult) -> Self {
            Self {
                result: std::sync::Mutex::new(result),
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl CircomWitnessHandler for StubHandler {
        fn invoke(
            &self,
            handle: &CircomHandle,
            signal_inputs: &[FieldElement],
        ) -> Result<CircomCallResult, CircomCallError> {
            self.seen
                .lock()
                .unwrap()
                .push((handle.clone(), signal_inputs.to_vec()));
            Ok(self.result.lock().unwrap().clone())
        }
    }

    /// Set up a VM with a handle at reg `handle_reg` and signal
    /// inputs at `handle_reg+1..`, then fire the opcode at base=0.
    fn setup_and_invoke(
        result: CircomCallResult,
        inputs: &[FieldElement],
    ) -> (VM, Result<Value, RuntimeError>) {
        let mut vm = VM::new();
        vm.circom_handler = Some(Box::new(StubHandler::new(result)));

        // Register 0 = handle
        let h_idx = vm.heap.alloc_circom_handle(handle("Square")).unwrap();
        vm.set_reg(0, 0, Value::circom_handle(h_idx)).unwrap();

        // Registers 1..1+inputs.len() = signal inputs
        for (i, fe) in inputs.iter().enumerate() {
            let f_idx = vm.heap.alloc_field(*fe).unwrap();
            vm.set_reg(0, 1 + i, Value::field(f_idx)).unwrap();
        }

        // Destination = register 20 (arbitrary far-away slot).
        let inst = encode_abc(
            OpCode::CallCircomTemplate.as_u8(),
            20, // A = dest
            1,  // B = first input reg (handle lives at B-1 = 0)
            inputs.len() as u8,
        );
        let res = vm
            .handle_call_circom_template(inst, 0)
            .map(|_| vm.get_reg(0, 20).unwrap());
        (vm, res)
    }

    #[test]
    fn handler_not_configured_errors_cleanly() {
        let mut vm = VM::new();
        // Do NOT set vm.circom_handler.
        let inst = encode_abc(OpCode::CallCircomTemplate.as_u8(), 5, 1, 0);
        let err = vm
            .handle_call_circom_template(inst, 0)
            .expect_err("should fail");
        assert!(matches!(err, RuntimeError::CircomHandlerNotConfigured));
    }

    #[test]
    fn scalar_output_materializes_as_field_value() {
        let mut outputs = HashMap::new();
        outputs.insert(
            "y".to_string(),
            CircomOutputValue::Scalar(FieldElement::from_u64(25)),
        );
        let result = CircomCallResult { outputs };
        let (vm, v) = setup_and_invoke(result, &[FieldElement::from_u64(5)]);
        let v = v.expect("dispatch should succeed");
        assert!(v.is_field());
        let fh = v.as_handle().unwrap();
        let fe = vm.heap.get_field(fh).unwrap();
        assert_eq!(*fe, FieldElement::from_u64(25));
    }

    #[test]
    fn single_array_output_materializes_as_list_of_fields() {
        let mut outputs = HashMap::new();
        outputs.insert(
            "out".to_string(),
            CircomOutputValue::Array {
                dims: vec![4],
                values: (0..4).map(FieldElement::from_u64).collect(),
            },
        );
        let (vm, v) = setup_and_invoke(CircomCallResult { outputs }, &[FieldElement::from_u64(5)]);
        let v = v.expect("dispatch should succeed");
        assert!(v.is_list());
        let lh = v.as_handle().unwrap();
        let list = vm.heap.get_list(lh).unwrap();
        assert_eq!(list.len(), 4);
        for (i, elem) in list.iter().enumerate() {
            let fh = elem.as_handle().unwrap();
            let fe = vm.heap.get_field(fh).unwrap();
            assert_eq!(*fe, FieldElement::from_u64(i as u64));
        }
    }

    #[test]
    fn multi_output_materializes_as_map_keyed_by_output_name() {
        let mut outputs = HashMap::new();
        outputs.insert(
            "a".to_string(),
            CircomOutputValue::Scalar(FieldElement::from_u64(11)),
        );
        outputs.insert(
            "b".to_string(),
            CircomOutputValue::Scalar(FieldElement::from_u64(22)),
        );
        let (vm, v) = setup_and_invoke(CircomCallResult { outputs }, &[FieldElement::from_u64(5)]);
        let v = v.expect("dispatch should succeed");
        assert!(v.is_map());
        let mh = v.as_handle().unwrap();
        let map = vm.heap.get_map(mh).unwrap();
        assert_eq!(map.len(), 2);
        let a = map.get("a").unwrap();
        let b = map.get("b").unwrap();
        let a_fe = vm.heap.get_field(a.as_handle().unwrap()).unwrap();
        let b_fe = vm.heap.get_field(b.as_handle().unwrap()).unwrap();
        assert_eq!(*a_fe, FieldElement::from_u64(11));
        assert_eq!(*b_fe, FieldElement::from_u64(22));
    }

    #[test]
    fn non_circom_handle_in_handle_slot_errors() {
        let mut vm = VM::new();
        vm.circom_handler = Some(Box::new(StubHandler::new(CircomCallResult {
            outputs: HashMap::new(),
        })));
        // Put a regular int in R[0] instead of a circom handle.
        vm.set_reg(0, 0, Value::int(42)).unwrap();
        let inst = encode_abc(OpCode::CallCircomTemplate.as_u8(), 5, 1, 0);
        let err = vm
            .handle_call_circom_template(inst, 0)
            .expect_err("should fail");
        assert!(matches!(err, RuntimeError::TypeMismatch(_)));
    }

    #[test]
    fn zero_input_base_register_is_rejected() {
        let mut vm = VM::new();
        vm.circom_handler = Some(Box::new(StubHandler::new(CircomCallResult {
            outputs: HashMap::new(),
        })));
        let inst = encode_abc(OpCode::CallCircomTemplate.as_u8(), 5, 0, 0);
        let err = vm
            .handle_call_circom_template(inst, 0)
            .expect_err("B=0 should fail");
        assert!(matches!(err, RuntimeError::TypeMismatch(_)));
    }
}
