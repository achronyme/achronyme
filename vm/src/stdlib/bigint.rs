use crate::error::RuntimeError;
use crate::machine::VM;
use memory::{BigInt, BigIntWidth, Value, TAG_BIGINT};

fn extract_bigint<'a>(vm: &'a VM, val: &Value) -> Result<&'a BigInt, RuntimeError> {
    if val.tag() != TAG_BIGINT {
        return Err(RuntimeError::TypeMismatch(
            "Expected BigInt argument".into(),
        ));
    }
    let handle = val
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad bigint handle".into()))?;
    vm.heap
        .get_bigint(handle)
        .ok_or(RuntimeError::SystemError("BigInt missing".into()))
}

fn map_bigint_err(e: memory::BigIntError) -> RuntimeError {
    match e {
        memory::BigIntError::Overflow => RuntimeError::BigIntOverflow,
        memory::BigIntError::Underflow => RuntimeError::BigIntUnderflow,
        memory::BigIntError::DivisionByZero => RuntimeError::DivisionByZero,
        memory::BigIntError::WidthMismatch => RuntimeError::BigIntWidthMismatch,
    }
}

fn construct_bigint(
    vm: &mut VM,
    args: &[Value],
    width: BigIntWidth,
    name: &str,
) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(format!(
            "{name}() takes exactly 1 argument"
        )));
    }
    let val = &args[0];

    let bi = if val.is_int() {
        let i = val
            .as_int()
            .ok_or(RuntimeError::TypeMismatch("bad int value".into()))?;
        if i < 0 {
            return Err(RuntimeError::TypeMismatch(
                "BigInt cannot be constructed from a negative integer".into(),
            ));
        }
        BigInt::from_u64(i as u64, width)
    } else if val.is_string() {
        let handle = val
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad string handle".into()))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::SystemError("String missing".into()))?
            .clone();
        // Detect radix from prefix
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            BigInt::from_hex_str(hex, width)
        } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            BigInt::from_binary_str(bin, width)
        } else {
            BigInt::from_decimal_str(&s, width)
        }
        .ok_or_else(|| RuntimeError::TypeMismatch(format!("Cannot parse string as {name}: {s}")))?
    } else {
        return Err(RuntimeError::TypeMismatch(format!(
            "{name}() expects Int or String argument"
        )));
    };

    let handle = vm.heap.alloc_bigint(bi);
    Ok(Value::bigint(handle))
}

pub fn native_bigint256(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    construct_bigint(vm, args, BigIntWidth::W256, "bigint256")
}

pub fn native_bigint512(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    construct_bigint(vm, args, BigIntWidth::W512, "bigint512")
}

pub fn native_to_bits(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "to_bits() takes exactly 1 argument".into(),
        ));
    }
    let bi = extract_bigint(vm, &args[0])?;
    let bits = bi.to_bits(); // LSB-first Vec<u8>
    let values: Vec<Value> = bits.iter().map(|&b| Value::int(b as i64)).collect();
    let handle = vm.heap.alloc_list(values);
    Ok(Value::list(handle))
}

pub fn native_from_bits(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "from_bits(bits, width) takes exactly 2 arguments".into(),
        ));
    }

    // First arg: list of 0/1 ints
    if !args[0].is_list() {
        return Err(RuntimeError::TypeMismatch(
            "First argument to from_bits must be a List".into(),
        ));
    }
    let list_handle = args[0]
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad list handle".into()))?;
    let list = vm
        .heap
        .get_list(list_handle)
        .ok_or(RuntimeError::SystemError("List missing".into()))?
        .clone();

    let mut bits = Vec::with_capacity(list.len());
    for v in &list {
        let b = v.as_int().ok_or(RuntimeError::TypeMismatch(
            "Bit values must be integers".into(),
        ))?;
        if b != 0 && b != 1 {
            return Err(RuntimeError::TypeMismatch(
                "Bit values must be 0 or 1".into(),
            ));
        }
        bits.push(b as u8);
    }

    // Second arg: width (256 or 512)
    let width_val = args[1].as_int().ok_or(RuntimeError::TypeMismatch(
        "Width must be an integer".into(),
    ))?;
    let width = match width_val {
        256 => BigIntWidth::W256,
        512 => BigIntWidth::W512,
        _ => {
            return Err(RuntimeError::TypeMismatch(
                "Width must be 256 or 512".into(),
            ))
        }
    };

    let bi = BigInt::from_bits(&bits, width).ok_or_else(|| {
        RuntimeError::TypeMismatch("Too many bits for the specified width".into())
    })?;
    let handle = vm.heap.alloc_bigint(bi);
    Ok(Value::bigint(handle))
}

pub fn native_bit_and(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "bit_and() takes exactly 2 arguments".into(),
        ));
    }
    let a = extract_bigint(vm, &args[0])?.clone();
    let b = extract_bigint(vm, &args[1])?.clone();
    let result = a.bit_and(&b).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result);
    Ok(Value::bigint(handle))
}

pub fn native_bit_or(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "bit_or() takes exactly 2 arguments".into(),
        ));
    }
    let a = extract_bigint(vm, &args[0])?.clone();
    let b = extract_bigint(vm, &args[1])?.clone();
    let result = a.bit_or(&b).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result);
    Ok(Value::bigint(handle))
}

pub fn native_bit_xor(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "bit_xor() takes exactly 2 arguments".into(),
        ));
    }
    let a = extract_bigint(vm, &args[0])?.clone();
    let b = extract_bigint(vm, &args[1])?.clone();
    let result = a.bit_xor(&b).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result);
    Ok(Value::bigint(handle))
}

pub fn native_bit_not(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "bit_not() takes exactly 1 argument".into(),
        ));
    }
    let a = extract_bigint(vm, &args[0])?.clone();
    let result = a.bit_not();
    let handle = vm.heap.alloc_bigint(result);
    Ok(Value::bigint(handle))
}

pub fn native_bit_shl(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "bit_shl() takes exactly 2 arguments".into(),
        ));
    }
    let a = extract_bigint(vm, &args[0])?.clone();
    let amount = args[1].as_int().ok_or(RuntimeError::TypeMismatch(
        "Shift amount must be an integer".into(),
    ))?;
    if amount < 0 {
        return Err(RuntimeError::TypeMismatch(
            "Shift amount must be non-negative".into(),
        ));
    }
    let result = a.shl(amount as u32).map_err(map_bigint_err)?;
    let handle = vm.heap.alloc_bigint(result);
    Ok(Value::bigint(handle))
}

pub fn native_bit_shr(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "bit_shr() takes exactly 2 arguments".into(),
        ));
    }
    let a = extract_bigint(vm, &args[0])?.clone();
    let amount = args[1].as_int().ok_or(RuntimeError::TypeMismatch(
        "Shift amount must be an integer".into(),
    ))?;
    if amount < 0 {
        return Err(RuntimeError::TypeMismatch(
            "Shift amount must be non-negative".into(),
        ));
    }
    let result = a.shr(amount as u32);
    let handle = vm.heap.alloc_bigint(result);
    Ok(Value::bigint(handle))
}
