use crate::error::RuntimeError;
use crate::machine::VM;
use memory::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a list handle from a Value, returning a descriptive error.
fn require_list(val: Value, fn_name: &str, position: &str) -> Result<u32, RuntimeError> {
    if !val.is_list() {
        return Err(RuntimeError::TypeMismatch(format!(
            "{fn_name}: {position} must be a List"
        )));
    }
    val.as_handle()
        .ok_or_else(|| RuntimeError::TypeMismatch(format!("{fn_name}: bad list handle")))
}

/// Validate that a Value is callable (Closure or Native).
fn require_callable(val: Value, fn_name: &str) -> Result<(), RuntimeError> {
    if !val.is_closure() && !val.is_native() {
        return Err(RuntimeError::TypeMismatch(format!(
            "{fn_name}: callback must be a Function"
        )));
    }
    Ok(())
}

/// Snapshot a heap list into a Rust Vec to decouple iteration from heap mutations.
fn snapshot_list(vm: &VM, handle: u32, fn_name: &str) -> Result<Vec<Value>, RuntimeError> {
    Ok(vm
        .heap
        .get_list(handle)
        .ok_or_else(|| RuntimeError::SystemError(format!("{fn_name}: list missing from heap")))?
        .clone())
}

// ---------------------------------------------------------------------------
// Higher-order collection functions
// ---------------------------------------------------------------------------

/// `map(list, fn)` — Returns a new list with `fn(elem)` applied to each element.
pub fn native_map(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "map", "first argument")?;
    let callback = args[1];
    require_callable(callback, "map")?;

    let elements = snapshot_list(vm, list_handle, "map")?;

    // Allocate the result list on the heap and root it so intermediate
    // closure calls that trigger GC won't collect it.
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

/// `filter(list, fn)` — Returns a new list of elements where `fn(elem)` is truthy.
pub fn native_filter(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "filter", "first argument")?;
    let callback = args[1];
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

/// `reduce(list, initial, fn)` — Folds the list: `acc = fn(acc, elem)` for each element.
pub fn native_reduce(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "reduce", "first argument")?;
    let mut acc = args[1];
    let callback = args[2];
    require_callable(callback, "reduce")?;

    let elements = snapshot_list(vm, list_handle, "reduce")?;

    // Root the accumulator — it may be a heap object (string, list, etc.)
    // that would otherwise be invisible to GC between iterations.
    let root_idx = vm.native_roots.len();
    vm.native_roots.push(acc);

    let result = (|| {
        for elem in &elements {
            acc = vm.call_value(callback, &[acc, *elem])?;
            // Update the rooted value so GC sees the latest accumulator.
            vm.native_roots[root_idx] = acc;
        }
        Ok(acc)
    })();

    vm.native_roots.truncate(root_idx);
    result
}

/// `forEach(list, fn)` — Calls `fn(elem)` for each element. Returns nil.
pub fn native_for_each(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "forEach", "first argument")?;
    let callback = args[1];
    require_callable(callback, "forEach")?;

    let elements = snapshot_list(vm, list_handle, "forEach")?;

    for elem in &elements {
        vm.call_value(callback, &[*elem])?;
    }

    Ok(Value::nil())
}

/// `find(list, fn)` — Returns the first element where `fn(elem)` is truthy, or nil.
pub fn native_find(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "find", "first argument")?;
    let callback = args[1];
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

/// `any(list, fn)` — Returns true if `fn(elem)` is truthy for any element.
pub fn native_any(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "any", "first argument")?;
    let callback = args[1];
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

/// `all(list, fn)` — Returns true if `fn(elem)` is truthy for all elements.
pub fn native_all(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "all", "first argument")?;
    let callback = args[1];
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

/// `sort(list, fn)` — Returns a new sorted list using `fn(a, b)` as comparator.
///
/// The comparator must return a negative number if a < b, zero if a == b,
/// or a positive number if a > b (like C's `qsort` convention).
///
/// Uses merge sort for guaranteed O(n log n) and stability.
pub fn native_sort(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "sort", "first argument")?;
    let callback = args[1];
    require_callable(callback, "sort")?;

    let elements = snapshot_list(vm, list_handle, "sort")?;

    if elements.len() <= 1 {
        let h = vm.heap.alloc_list(elements);
        return Ok(Value::list(h));
    }

    // Root callback and working buffer to protect from GC during comparisons.
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

/// Stable merge sort that uses `call_value` for comparisons.
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

/// `flatMap(list, fn)` — Like map, but flattens one level of nested lists.
pub fn native_flat_map(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let list_handle = require_list(args[0], "flatMap", "first argument")?;
    let callback = args[1];
    require_callable(callback, "flatMap")?;

    let elements = snapshot_list(vm, list_handle, "flatMap")?;

    let result_handle = vm.heap.alloc_list(Vec::new());
    let root_idx = vm.native_roots.len();
    vm.native_roots.push(Value::list(result_handle));

    let result = (|| {
        for elem in &elements {
            let mapped = vm.call_value(callback, &[*elem])?;
            if mapped.is_list() {
                let inner_handle = mapped
                    .as_handle()
                    .ok_or_else(|| RuntimeError::TypeMismatch("flatMap: bad list handle".into()))?;
                let inner = vm
                    .heap
                    .get_list(inner_handle)
                    .ok_or_else(|| RuntimeError::SystemError("flatMap: inner list missing".into()))?
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

/// `zip(list1, list2)` — Returns a list of `[a, b]` pairs, truncated to the shorter list.
///
/// Not higher-order (no callback), but commonly paired with map/filter.
pub fn native_zip(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let handle1 = require_list(args[0], "zip", "first argument")?;
    let handle2 = require_list(args[1], "zip", "second argument")?;

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
