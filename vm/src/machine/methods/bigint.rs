//! BigInt methods: to_bits, bit_and, bit_or, bit_xor, bit_not, bit_shl, bit_shr

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{BigInt, BigIntError, Value, TAG_BIGINT};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_BIGINT, "to_bits", method_to_bits);
    registry.register(TAG_BIGINT, "bit_and", method_bit_and);
    registry.register(TAG_BIGINT, "bit_or", method_bit_or);
    registry.register(TAG_BIGINT, "bit_xor", method_bit_xor);
    registry.register(TAG_BIGINT, "bit_not", method_bit_not);
    registry.register(TAG_BIGINT, "bit_shl", method_bit_shl);
    registry.register(TAG_BIGINT, "bit_shr", method_bit_shr);
}

fn map_bigint_err(e: BigIntError) -> RuntimeError {
    match e {
        BigIntError::Overflow => RuntimeError::BigIntOverflow,
        BigIntError::Underflow => RuntimeError::BigIntUnderflow,
        BigIntError::DivisionByZero => RuntimeError::DivisionByZero,
        BigIntError::WidthMismatch => RuntimeError::BigIntWidthMismatch,
    }
}

fn extract_bigint<'a>(vm: &'a VM, val: &Value) -> Result<&'a BigInt, RuntimeError> {
    let handle = val
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad bigint handle".into()))?;
    vm.heap
        .get_bigint(handle)
        .ok_or(RuntimeError::SystemError("BigInt missing".into()))
}

fn method_to_bits(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let bi = extract_bigint(vm, &receiver)?;
    let bits = bi.to_bits();
    let values: Vec<Value> = bits.iter().map(|&b| Value::int(b as i64)).collect();
    let handle = vm.heap.alloc_list(values)?;
    Ok(Value::list(handle))
}

fn method_bit_and(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "bit_and() takes exactly 1 argument".into(),
        ));
    }
    let a = extract_bigint(vm, &receiver)?.clone();
    let b = extract_bigint(vm, &args[0])?.clone();
    let result = a.bit_and(&b).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result)?;
    Ok(Value::bigint(handle))
}

fn method_bit_or(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "bit_or() takes exactly 1 argument".into(),
        ));
    }
    let a = extract_bigint(vm, &receiver)?.clone();
    let b = extract_bigint(vm, &args[0])?.clone();
    let result = a.bit_or(&b).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result)?;
    Ok(Value::bigint(handle))
}

fn method_bit_xor(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "bit_xor() takes exactly 1 argument".into(),
        ));
    }
    let a = extract_bigint(vm, &receiver)?.clone();
    let b = extract_bigint(vm, &args[0])?.clone();
    let result = a.bit_xor(&b).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result)?;
    Ok(Value::bigint(handle))
}

fn method_bit_not(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let a = extract_bigint(vm, &receiver)?.clone();
    let result = a.bit_not();
    let handle = vm.heap.alloc_bigint(result)?;
    Ok(Value::bigint(handle))
}

fn method_bit_shl(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "bit_shl() takes exactly 1 argument".into(),
        ));
    }
    let a = extract_bigint(vm, &receiver)?.clone();
    let amount = args[0].as_int().ok_or(RuntimeError::TypeMismatch(
        "Shift amount must be an integer".into(),
    ))?;
    if amount < 0 {
        return Err(RuntimeError::TypeMismatch(
            "Shift amount must be non-negative".into(),
        ));
    }
    let result = a.shl(amount as u32).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result)?;
    Ok(Value::bigint(handle))
}

fn method_bit_shr(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "bit_shr() takes exactly 1 argument".into(),
        ));
    }
    let a = extract_bigint(vm, &receiver)?.clone();
    let amount = args[0].as_int().ok_or(RuntimeError::TypeMismatch(
        "Shift amount must be an integer".into(),
    ))?;
    if amount < 0 {
        return Err(RuntimeError::TypeMismatch(
            "Shift amount must be non-negative".into(),
        ));
    }
    let result = a.shr(amount as u32);
    let handle = vm.heap.alloc_bigint(result)?;
    Ok(Value::bigint(handle))
}
