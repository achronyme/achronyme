//! List methods: len, push, pop, map, filter, reduce, for_each, find,
//! any, all, sort, flat_map, zip

use crate::error::RuntimeError;
use crate::machine::prototype::PrototypeRegistry;
use crate::machine::VM;
use memory::{Value, TAG_LIST};

pub fn register(registry: &mut PrototypeRegistry) {
    registry.register(TAG_LIST, "len", method_len);
    registry.register(TAG_LIST, "push", method_push);
    registry.register(TAG_LIST, "pop", method_pop);
    registry.register(TAG_LIST, "map", method_map);
    registry.register(TAG_LIST, "filter", method_filter);
    registry.register(TAG_LIST, "reduce", method_reduce);
    registry.register(TAG_LIST, "for_each", method_for_each);
    registry.register(TAG_LIST, "find", method_find);
    registry.register(TAG_LIST, "any", method_any);
    registry.register(TAG_LIST, "all", method_all);
    registry.register(TAG_LIST, "sort", method_sort);
    registry.register(TAG_LIST, "flat_map", method_flat_map);
    registry.register(TAG_LIST, "zip", method_zip);
}

// ---------------------------------------------------------------------------
// Helpers (adapted from stdlib/collections.rs)
// ---------------------------------------------------------------------------

fn get_list_handle(receiver: Value) -> Result<u32, RuntimeError> {
    receiver
        .as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch("bad list handle".into()))
}

fn require_callable(val: Value, method: &str) -> Result<(), RuntimeError> {
    if !val.is_closure() && !val.is_native() {
        return Err(RuntimeError::TypeMismatch(format!(
            "{method}: callback must be a Function"
        )));
    }
    Ok(())
}

fn snapshot_list(vm: &VM, handle: u32, method: &str) -> Result<Vec<Value>, RuntimeError> {
    Ok(vm
        .heap
        .get_list(handle)
        .ok_or_else(|| RuntimeError::SystemError(format!("{method}: list missing from heap")))?
        .clone())
}

fn merge_sort(vm: &mut VM, slice: &[Value], cmp: Value) -> Result<Vec<Value>, RuntimeError> {
    if slice.len() <= 1 {
        return Ok(slice.to_vec());
    }
    let mid = slice.len() / 2;
    let left = merge_sort(vm, &slice[..mid], cmp)?;
    let right = merge_sort(vm, &slice[mid..], cmp)?;

    let mut merged = Vec::with_capacity(slice.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        let cmp_result = vm.call_value(cmp, &[left[i], right[j]])?;
        let n = cmp_result.as_int().ok_or_else(|| {
            RuntimeError::TypeMismatch("sort: comparator must return a Number".into())
        })?;
        if n <= 0 {
            merged.push(left[i]);
            i += 1;
        } else {
            merged.push(right[j]);
            j += 1;
        }
    }
    merged.extend_from_slice(&left[i..]);
    merged.extend_from_slice(&right[j..]);
    Ok(merged)
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

fn method_len(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let handle = get_list_handle(receiver)?;
    let l = vm
        .heap
        .get_list(handle)
        .ok_or(RuntimeError::SystemError("List missing".into()))?;
    Ok(Value::int(l.len() as i64))
}

fn method_push(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "push() takes exactly 1 argument".into(),
        ));
    }
    let handle = get_list_handle(receiver)?;
    let item = args[0];
    vm.heap
        .list_push(handle, item)
        .ok_or(RuntimeError::SystemError(
            "List corrupted or missing".into(),
        ))?;
    Ok(Value::nil())
}

fn method_pop(vm: &mut VM, receiver: Value, _args: &[Value]) -> Result<Value, RuntimeError> {
    let handle = get_list_handle(receiver)?;
    let list = vm
        .heap
        .get_list_mut(handle)
        .ok_or(RuntimeError::SystemError(
            "List corrupted or missing".into(),
        ))?;
    let val = list.pop().unwrap_or(Value::nil());
    Ok(val)
}

fn method_map(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "map() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "map")?;

    let elements = snapshot_list(vm, list_handle, "map")?;

    let result_handle = vm.heap.alloc_list(Vec::with_capacity(elements.len()));
    let root_idx = vm.native_roots.len();
    vm.native_roots.push(Value::list(result_handle));

    let result = (|| {
        for elem in &elements {
            let mapped = vm.call_value(callback, &[*elem])?;
            vm.heap.list_push(result_handle, mapped);
        }
        Ok(Value::list(result_handle))
    })();

    vm.native_roots.truncate(root_idx);
    result
}

fn method_filter(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "filter() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "filter")?;

    let elements = snapshot_list(vm, list_handle, "filter")?;

    let result_handle = vm.heap.alloc_list(Vec::new());
    let root_idx = vm.native_roots.len();
    vm.native_roots.push(Value::list(result_handle));

    let result = (|| {
        for elem in &elements {
            let predicate = vm.call_value(callback, &[*elem])?;
            if !predicate.is_falsey() {
                vm.heap.list_push(result_handle, *elem);
            }
        }
        Ok(Value::list(result_handle))
    })();

    vm.native_roots.truncate(root_idx);
    result
}

fn method_reduce(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 2 {
        return Err(RuntimeError::ArityMismatch(
            "reduce() takes exactly 2 arguments (initial, fn)".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let mut acc = args[0];
    let callback = args[1];
    require_callable(callback, "reduce")?;

    let elements = snapshot_list(vm, list_handle, "reduce")?;

    let root_idx = vm.native_roots.len();
    vm.native_roots.push(acc);

    let result = (|| {
        for elem in &elements {
            acc = vm.call_value(callback, &[acc, *elem])?;
            vm.native_roots[root_idx] = acc;
        }
        Ok(acc)
    })();

    vm.native_roots.truncate(root_idx);
    result
}

fn method_for_each(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "for_each() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "for_each")?;

    let elements = snapshot_list(vm, list_handle, "for_each")?;

    for elem in &elements {
        vm.call_value(callback, &[*elem])?;
    }

    Ok(Value::nil())
}

fn method_find(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "find() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "find")?;

    let elements = snapshot_list(vm, list_handle, "find")?;

    for elem in &elements {
        let predicate = vm.call_value(callback, &[*elem])?;
        if !predicate.is_falsey() {
            return Ok(*elem);
        }
    }

    Ok(Value::nil())
}

fn method_any(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "any() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "any")?;

    let elements = snapshot_list(vm, list_handle, "any")?;

    for elem in &elements {
        let predicate = vm.call_value(callback, &[*elem])?;
        if !predicate.is_falsey() {
            return Ok(Value::true_val());
        }
    }

    Ok(Value::false_val())
}

fn method_all(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "all() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "all")?;

    let elements = snapshot_list(vm, list_handle, "all")?;

    for elem in &elements {
        let predicate = vm.call_value(callback, &[*elem])?;
        if predicate.is_falsey() {
            return Ok(Value::false_val());
        }
    }

    Ok(Value::true_val())
}

fn method_sort(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "sort() takes exactly 1 argument (comparator fn)".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "sort")?;

    let elements = snapshot_list(vm, list_handle, "sort")?;

    if elements.len() <= 1 {
        let h = vm.heap.alloc_list(elements);
        return Ok(Value::list(h));
    }

    let root_idx = vm.native_roots.len();
    vm.native_roots.push(callback);

    let result = (|| {
        let sorted = merge_sort(vm, &elements, callback)?;
        let h = vm.heap.alloc_list(sorted);
        Ok(Value::list(h))
    })();

    vm.native_roots.truncate(root_idx);
    result
}

fn method_flat_map(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "flat_map() takes exactly 1 argument".into(),
        ));
    }
    let list_handle = get_list_handle(receiver)?;
    let callback = args[0];
    require_callable(callback, "flat_map")?;

    let elements = snapshot_list(vm, list_handle, "flat_map")?;

    let result_handle = vm.heap.alloc_list(Vec::new());
    let root_idx = vm.native_roots.len();
    vm.native_roots.push(Value::list(result_handle));

    let result = (|| {
        for elem in &elements {
            let mapped = vm.call_value(callback, &[*elem])?;
            if mapped.is_list() {
                let inner_handle = mapped.as_handle().ok_or_else(|| {
                    RuntimeError::TypeMismatch("flat_map: bad list handle".into())
                })?;
                let inner = vm
                    .heap
                    .get_list(inner_handle)
                    .ok_or_else(|| {
                        RuntimeError::SystemError("flat_map: inner list missing".into())
                    })?
                    .clone();
                for v in inner {
                    vm.heap.list_push(result_handle, v);
                }
            } else {
                vm.heap.list_push(result_handle, mapped);
            }
        }
        Ok(Value::list(result_handle))
    })();

    vm.native_roots.truncate(root_idx);
    result
}

fn method_zip(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError> {
    if args.len() != 1 {
        return Err(RuntimeError::ArityMismatch(
            "zip() takes exactly 1 argument".into(),
        ));
    }
    let handle1 = get_list_handle(receiver)?;
    let handle2 = if !args[0].is_list() {
        return Err(RuntimeError::TypeMismatch(
            "zip: argument must be a List".into(),
        ));
    } else {
        args[0]
            .as_handle()
            .ok_or_else(|| RuntimeError::TypeMismatch("bad list handle".into()))?
    };

    let list1 = snapshot_list(vm, handle1, "zip")?;
    let list2 = snapshot_list(vm, handle2, "zip")?;

    let len = list1.len().min(list2.len());

    let result_handle = vm.heap.alloc_list(Vec::with_capacity(len));
    let root_idx = vm.native_roots.len();
    vm.native_roots.push(Value::list(result_handle));

    for i in 0..len {
        let pair = vec![list1[i], list2[i]];
        let pair_handle = vm.heap.alloc_list(pair);
        vm.heap.list_push(result_handle, Value::list(pair_handle));
    }

    vm.native_roots.truncate(root_idx);
    Ok(Value::list(result_handle))
}
