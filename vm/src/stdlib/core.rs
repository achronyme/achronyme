use crate::error::RuntimeError;
use crate::machine::value_ops::ValueOps;
use crate::machine::VM;
use ach_macros::{ach_module, ach_native};
use constraints::poseidon::poseidon_hash;
use constraints::PoseidonParamsProvider;
use memory::{FieldElement, Value};

/// Extract a FieldElement from a VM Value (Int or Field).
fn extract_fe(vm: &VM, val: &Value) -> Result<FieldElement, RuntimeError> {
    if val.is_field() {
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::type_mismatch("bad field handle"))?;
        let fe = vm
            .heap
            .get_field(handle)
            .ok_or(RuntimeError::stale_heap("Field", "extract_fe"))?;
        Ok(*fe)
    } else if val.is_int() {
        let i = val
            .as_int()
            .ok_or(RuntimeError::type_mismatch("bad int value"))?;
        Ok(FieldElement::from_i64(i))
    } else {
        Err(RuntimeError::type_mismatch("Expected Int or Field value"))
    }
}

#[ach_module(name = "core")]
pub mod core_impl {
    use super::*;

    #[ach_native(name = "print", arity = -1)]
    pub fn native_print(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                print!(" ");
            }
            print!("{}", vm.val_to_string(arg));
        }
        println!();
        Ok(Value::nil())
    }

    #[ach_native(name = "typeof", arity = 1)]
    pub fn native_typeof(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "typeof() takes exactly 1 argument",
            ));
        }
        let val = &args[0];
        let type_name = if val.is_int() {
            "Number"
        } else if val.is_string() {
            "String"
        } else if val.is_bool() {
            "Bool"
        } else if val.is_nil() {
            "Nil"
        } else if val.is_list() {
            "List"
        } else if val.is_map() {
            "Map"
        } else if val.is_field() {
            "Field"
        } else if val.is_bigint() {
            let handle = val.as_handle().ok_or(RuntimeError::InvalidOperand)?;
            let bi = vm.heap.get_bigint(handle);
            match bi {
                Some(b) => match b.width() {
                    memory::BigIntWidth::W256 => "BigInt256",
                    memory::BigIntWidth::W512 => "BigInt512",
                },
                None => "BigInt",
            }
        } else if val.is_proof() {
            "Proof"
        } else if val.is_function() || val.is_closure() {
            "Function"
        } else if val.is_native() {
            "Native"
        } else {
            "Unknown"
        };
        let s = type_name.to_string();
        let handle = vm.heap.alloc_string(s)?;
        Ok(Value::string(handle))
    }

    #[ach_native(name = "assert", arity = 1)]
    pub fn native_assert(_vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "assert() takes exactly 1 argument",
            ));
        }
        if !args[0].as_bool().unwrap_or(false) {
            return Err(RuntimeError::AssertionFailed);
        }
        Ok(Value::nil())
    }

    #[ach_native(name = "time", arity = 0)]
    pub fn native_time(_vm: &mut VM, _args: &[Value]) -> Result<Value, RuntimeError> {
        let now = std::time::SystemTime::now();
        let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        Ok(Value::int(duration.as_millis() as i64))
    }

    #[ach_native(name = "proof_json", arity = 1)]
    pub fn native_proof_json(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "proof_json() takes exactly 1 argument",
            ));
        }
        let val = args[0];
        if !val.is_proof() {
            return Err(RuntimeError::type_mismatch("proof_json expects a Proof"));
        }
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::type_mismatch("bad proof handle"))?;
        let json = vm
            .heap
            .get_proof(handle)
            .ok_or(RuntimeError::stale_heap("Proof", "proof_json"))?
            .proof_json
            .clone();
        let s = vm.heap.alloc_string(json)?;
        Ok(Value::string(s))
    }

    #[ach_native(name = "proof_public", arity = 1)]
    pub fn native_proof_public(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "proof_public() takes exactly 1 argument",
            ));
        }
        let val = args[0];
        if !val.is_proof() {
            return Err(RuntimeError::type_mismatch("proof_public expects a Proof"));
        }
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::type_mismatch("bad proof handle"))?;
        let json = vm
            .heap
            .get_proof(handle)
            .ok_or(RuntimeError::stale_heap("Proof", "proof_public"))?
            .public_json
            .clone();
        let s = vm.heap.alloc_string(json)?;
        Ok(Value::string(s))
    }

    #[ach_native(name = "proof_vkey", arity = 1)]
    pub fn native_proof_vkey(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "proof_vkey() takes exactly 1 argument",
            ));
        }
        let val = args[0];
        if !val.is_proof() {
            return Err(RuntimeError::type_mismatch("proof_vkey expects a Proof"));
        }
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::type_mismatch("bad proof handle"))?;
        let json = vm
            .heap
            .get_proof(handle)
            .ok_or(RuntimeError::stale_heap("Proof", "proof_vkey"))?
            .vkey_json
            .clone();
        let s = vm.heap.alloc_string(json)?;
        Ok(Value::string(s))
    }

    #[ach_native(name = "poseidon", arity = 2)]
    pub fn native_poseidon(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::arity_mismatch(
                "poseidon(left, right) takes exactly 2 arguments",
            ));
        }
        let left = extract_fe(vm, &args[0])?;
        let right = extract_fe(vm, &args[1])?;
        let params = memory::Bn254Fr::default_poseidon_t3();
        let result = poseidon_hash(&params, left, right);
        let handle = vm.heap.alloc_field(result)?;
        Ok(Value::field(handle))
    }

    #[ach_native(name = "poseidon_many", arity = -1)]
    pub fn native_poseidon_many(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() < 2 {
            return Err(RuntimeError::arity_mismatch(
                "poseidon_many() requires at least 2 arguments",
            ));
        }
        let params = memory::Bn254Fr::default_poseidon_t3();
        let first = extract_fe(vm, &args[0])?;
        let second = extract_fe(vm, &args[1])?;
        let mut acc = poseidon_hash(&params, first, second);
        for arg in &args[2..] {
            let fe = extract_fe(vm, arg)?;
            acc = poseidon_hash(&params, acc, fe);
        }
        let handle = vm.heap.alloc_field(acc)?;
        Ok(Value::field(handle))
    }

    #[ach_native(name = "verify_proof", arity = 1)]
    pub fn native_verify_proof(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 1 {
            return Err(RuntimeError::arity_mismatch(
                "verify_proof(proof) takes exactly 1 argument",
            ));
        }
        let val = args[0];
        if !val.is_proof() {
            return Err(RuntimeError::type_mismatch("verify_proof expects a Proof"));
        }
        let handle = val
            .as_handle()
            .ok_or(RuntimeError::type_mismatch("bad proof handle"))?;
        let proof_obj = vm
            .heap
            .get_proof(handle)
            .ok_or(RuntimeError::stale_heap("Proof", "verify_proof"))?
            .clone();
        let handler = vm
            .verify_handler
            .as_ref()
            .ok_or(RuntimeError::VerifyHandlerNotConfigured)?;
        match handler.verify_proof(&proof_obj) {
            Ok(valid) => Ok(Value::bool(valid)),
            Err(msg) => Err(RuntimeError::verification_failed(msg)),
        }
    }

    #[ach_native(name = "gc_stats", arity = 0)]
    pub fn native_gc_stats(vm: &mut VM, _args: &[Value]) -> Result<Value, RuntimeError> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            "collections".into(),
            Value::int(vm.heap.stats.collections as i64),
        );
        map.insert(
            "bytes_freed".into(),
            Value::int(vm.heap.stats.total_freed_bytes as i64),
        );
        map.insert(
            "peak_bytes".into(),
            Value::int(vm.heap.stats.peak_heap_bytes as i64),
        );
        map.insert(
            "gc_time_ms".into(),
            Value::int((vm.heap.stats.total_gc_time_ns / 1_000_000) as i64),
        );
        map.insert(
            "bytes_allocated".into(),
            Value::int(vm.heap.bytes_allocated as i64),
        );
        let handle = vm.heap.alloc_map(map)?;
        Ok(Value::map(handle))
    }
}
