//! Type checking and assertion execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute type-related opcodes (TYPE_CHECK, TYPE_ASSERT)
    pub(crate) fn execute_types(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        match opcode {
            OpCode::TypeCheck => {
                // R[A] = check_type(R[B], K[C])
                // Returns true/false based on type match
                let dst = decode_a(instruction);
                let val_reg = decode_b(instruction);
                let type_idx = decode_c(instruction) as usize;

                let value = self.get_register(val_reg)?.clone();
                let type_name = self.get_string(type_idx)?;

                let matches = self.check_type(&value, type_name);
                self.set_register(dst, Value::Boolean(matches))?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::TypeAssert => {
                // assert_type(R[A], K[Bx]) or throw TypeError
                // Uses ABx format: A = value register, Bx = type constant index
                let val_reg = decode_a(instruction);
                let type_idx = decode_bx(instruction) as usize;

                let value = self.get_register(val_reg)?.clone();
                let type_name = self.get_string(type_idx)?;

                if !self.check_type(&value, type_name) {
                    // Throw TypeError
                    let error_msg = format!(
                        "Type assertion failed: expected {}, got {}",
                        type_name,
                        self.value_type_name(&value)
                    );
                    let error = Value::Error {
                        message: error_msg,
                        kind: Some("TypeError".to_string()),
                        source: None,
                    };
                    return Ok(ExecutionResult::Exception(error));
                }

                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!(),
        }
    }

    /// Check if value matches type name
    fn check_type(&self, value: &Value, type_name: &str) -> bool {
        match type_name {
            "Number" => matches!(value, Value::Number(_)),
            "String" => matches!(value, Value::String(_)),
            "Boolean" => matches!(value, Value::Boolean(_)),
            "Complex" => matches!(value, Value::Complex(_)),
            "Vector" => matches!(value, Value::Vector(_)),
            "Tensor" => matches!(value, Value::Tensor(_) | Value::ComplexTensor(_)),
            "Record" => matches!(value, Value::Record(_)),
            "Function" => matches!(value, Value::Function(_)),
            "Generator" => matches!(value, Value::Generator(_)),
            "Future" => matches!(value, Value::Future(_)),
            "Iterator" => matches!(value, Value::Iterator(_)),
            "Null" => matches!(value, Value::Null),
            "Range" => matches!(value, Value::Range { .. }),
            "Builder" => matches!(value, Value::Builder(_)),
            "MutableRef" => matches!(value, Value::MutableRef(_)),
            "Error" => matches!(value, Value::Error { .. }),
            "Any" => true, // Any type always matches
            _ => false,    // Unknown type name
        }
    }

    /// Get type name of a value for error messages
    fn value_type_name(&self, value: &Value) -> &'static str {
        match value {
            Value::Number(_) => "Number",
            Value::String(_) => "String",
            Value::Boolean(_) => "Boolean",
            Value::Complex(_) => "Complex",
            Value::Vector(_) => "Vector",
            Value::Tensor(_) => "Tensor",
            Value::ComplexTensor(_) => "Tensor",
            Value::Record(_) => "Record",
            Value::Function(_) => "Function",
            Value::TailCall(_) => "TailCall",
            Value::EarlyReturn(_) => "EarlyReturn",
            Value::Null => "Null",
            Value::Generator(_) => "Generator",
            Value::Future(_) => "Future",
            Value::GeneratorYield(_) => "GeneratorYield",
            Value::Error { .. } => "Error",
            Value::LoopBreak(_) => "LoopBreak",
            Value::MutableRef(_) => "MutableRef",
            Value::LoopContinue => "LoopContinue",
            Value::Iterator(_) => "Iterator",
            Value::Builder(_) => "Builder",
            Value::Range { .. } => "Range",
            Value::BoundMethod { .. } => "BoundMethod",
        }
    }
}
