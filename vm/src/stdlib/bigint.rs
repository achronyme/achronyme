use crate::error::RuntimeError;
use crate::machine::VM;
use ach_macros::{ach_module, ach_native};
use memory::{BigInt, BigIntWidth, Value};

fn construct_bigint(
    vm: &mut VM,
    args: &[Value],
    width: BigIntWidth,
    name: &str,
) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::arity_mismatch(format!(
            "{name}() takes exactly 1 argument"
        )));
    }
    let val = &args[0];

    let bi = if val.is_int() {
        let i = val
            .as_int()
            .ok_or(RuntimeError::type_mismatch("bad int value"))?;
        if i < 0 {
            return Err(RuntimeError::type_mismatch(
                "BigInt cannot be constructed from a negative integer",
            ));
        }
        BigInt::from_u64(i as u64, width)
    } else if val.is_string() {
        let handle = val
            .as_handle()
            .ok_or_else(|| RuntimeError::type_mismatch("bad string handle"))?;
        let s = vm
            .heap
            .get_string(handle)
            .ok_or(RuntimeError::stale_heap("String", "construct_bigint"))?
            .clone();
        // Detect radix from prefix
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            BigInt::from_hex_str(hex, width)
        } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            BigInt::from_binary_str(bin, width)
        } else {
            BigInt::from_decimal_str(&s, width)
        }
        .ok_or_else(|| RuntimeError::type_mismatch(format!("Cannot parse string as {name}: {s}")))?
    } else {
        return Err(RuntimeError::type_mismatch(format!(
            "{name}() expects Int or String argument"
        )));
    };

    let handle = vm.heap.alloc_bigint(bi)?;
    Ok(Value::bigint(handle))
}

#[ach_module(name = "bigint")]
pub mod bigint_impl {
    use super::*;

    #[ach_native(name = "bigint256", arity = 1)]
    pub fn native_bigint256(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        construct_bigint(vm, args, BigIntWidth::W256, "bigint256")
    }

    #[ach_native(name = "bigint512", arity = 1)]
    pub fn native_bigint512(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        construct_bigint(vm, args, BigIntWidth::W512, "bigint512")
    }

    #[ach_native(name = "from_bits", arity = 2)]
    pub fn native_from_bits(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
        if args.len() != 2 {
            return Err(RuntimeError::arity_mismatch(
                "from_bits(bits, width) takes exactly 2 arguments",
            ));
        }

        // First arg: list of 0/1 ints
        if !args[0].is_list() {
            return Err(RuntimeError::type_mismatch(
                "First argument to from_bits must be a List",
            ));
        }
        let list_handle = args[0]
            .as_handle()
            .ok_or_else(|| RuntimeError::type_mismatch("bad list handle"))?;
        let list = vm
            .heap
            .get_list(list_handle)
            .ok_or(RuntimeError::stale_heap("List", "from_bits"))?
            .clone();

        let mut bits = Vec::with_capacity(list.len());
        for v in &list {
            let b = v
                .as_int()
                .ok_or(RuntimeError::type_mismatch("Bit values must be integers"))?;
            if b != 0 && b != 1 {
                return Err(RuntimeError::type_mismatch("Bit values must be 0 or 1"));
            }
            bits.push(b as u8);
        }

        // Second arg: width (256 or 512)
        let width_val = args[1]
            .as_int()
            .ok_or(RuntimeError::type_mismatch("Width must be an integer"))?;
        let width = match width_val {
            256 => BigIntWidth::W256,
            512 => BigIntWidth::W512,
            _ => return Err(RuntimeError::type_mismatch("Width must be 256 or 512")),
        };

        let bi = BigInt::from_bits(&bits, width)
            .ok_or_else(|| RuntimeError::type_mismatch("Too many bits for the specified width"))?;
        let handle = vm.heap.alloc_bigint(bi)?;
        Ok(Value::bigint(handle))
    }
}
