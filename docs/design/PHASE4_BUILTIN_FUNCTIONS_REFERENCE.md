# Phase 4: Built-in Functions Implementation Reference

**Date**: 2025-01-18
**Last Updated**: 2025-01-22
**Status**: Core Complete - Specialized Functions Moved to Future Stdlib
**Core Functions**: ~110 (implemented in VM runtime)
**Stdlib Functions**: ~50 (deferred to external modules via FFI)

This document provides a complete reference for implementing all built-in functions in the Achronyme VM. Functions are organized by priority and implementation complexity.

## Implementation Status Summary

### ✅ Core Runtime Functions (Implemented in VM)

| Phase | Name | Functions | Status |
|-------|------|-----------|--------|
| 4A | Core Essentials | 9 | ✅ COMPLETE |
| 4B | Higher-Order Functions | 9 | ✅ COMPLETE |
| 4C | Mathematical Functions | 20 | ✅ COMPLETE |
| 4D | String Support | 14 | ✅ COMPLETE |
| 4E | Advanced Arrays | 11 | ✅ COMPLETE |
| 4F | Complex Numbers | 6 | ✅ COMPLETE |
| 4G | Linear Algebra | 7 | ✅ COMPLETE |
| 4I | Numerical Analysis | 11 | ✅ COMPLETE |
| **CORE TOTAL** | | **~110** | **✅ 100%** |

### 📦 Future Stdlib Modules (External Libraries via FFI)

| Phase | Name | Functions | Status |
|-------|------|-----------|--------|
| 4H | DSP Functions | 11 | 🔜 DEFERRED TO STDLIB |
| 4J | Optimization | 9 | 🔜 DEFERRED TO STDLIB |
| 4K | Graph Theory | 17 | 🔜 DEFERRED TO STDLIB |
| 4L | PERT/CPM | 13 | 🔜 DEFERRED TO STDLIB |
| **STDLIB TOTAL** | | **~50** | **🔜 FUTURE** |

## Architecture Decision: Core vs Stdlib

**Decision Date**: 2025-01-22

The project has made a strategic architectural decision to keep the runtime lean and focused:

- **Core Runtime (~110 functions)**: Essential language features for data manipulation, control flow, mathematics, and I/O
- **Stdlib Modules (~50 functions)**: Specialized algorithmic functions (DSP, graphs, optimization, PERT) will be implemented as external libraries accessible via FFI once the language reaches maturity

This approach prioritizes:
1. Lightweight, fast runtime
2. Better maintainability
3. Flexibility to optimize stdlib modules independently
4. Clear separation between language primitives and domain libraries

---

## Table of Contents

1. [Implementation Architecture](#implementation-architecture)
2. [Phase 4A: Core Essentials](#phase-4a-core-essentials)
3. [Phase 4B: Higher-Order Functions](#phase-4b-higher-order-functions)
4. [Phase 4C: Mathematical Functions](#phase-4c-mathematical-functions)
5. [Phase 4D: String Support](#phase-4d-string-support)
6. [Phase 4E: Advanced Arrays](#phase-4e-advanced-arrays)
7. [Phase 4F: Complex Numbers](#phase-4f-complex-numbers)
8. [Phase 4G: Linear Algebra](#phase-4g-linear-algebra)
9. [Phase 4H: DSP Functions](#phase-4h-dsp-functions)
10. [Phase 4I: Numerical Analysis](#phase-4i-numerical-analysis)
11. [Phase 4J: Optimization](#phase-4j-optimization)
12. [Phase 4K: Graph Theory](#phase-4k-graph-theory)
13. [Phase 4L: PERT/CPM](#phase-4l-pertcpm)
14. [Implementation Checklist](#implementation-checklist)

---

## Implementation Architecture

### Opcodes Required

```rust
// New opcodes for built-in functions
pub enum OpCode {
    // ... existing opcodes ...

    // Built-in function calls
    CallBuiltin,     // A = result reg, Bx = builtin index

    // String operations
    NewString,       // A = dst reg, Bx = string constant index
    StrConcat,       // A = dst, B = str1, C = str2
    StrLen,          // A = dst, B = string
    StrSlice,        // A = dst, B = string, C = start (end in next instruction)

    // Array helpers
    ArrayLen,        // A = dst, B = array
    ArraySum,        // A = dst, B = array
    ArrayRange,      // A = dst, B = start, C = end (step in constant pool)

    // Record helpers
    RecordKeys,      // A = dst, B = record
    RecordValues,    // A = dst, B = record
    RecordHasField,  // A = dst, B = record, C = field_idx
}
```

### VM Built-in Registry

```rust
// File: crates/achronyme-vm/src/builtins/mod.rs

pub struct BuiltinRegistry {
    functions: HashMap<String, BuiltinId>,
    handlers: Vec<BuiltinHandler>,
}

pub type BuiltinId = usize;

pub enum BuiltinHandler {
    /// Regular function: (args) -> result
    Native(NativeFn),

    /// Special form: requires AST access (map, filter, etc.)
    SpecialForm(SpecialFormFn),

    /// Direct opcode: has dedicated opcode (len, sum, etc.)
    Opcode(OpCode),
}

pub type NativeFn = fn(&mut VM, &[Value]) -> Result<Value, VmError>;
pub type SpecialFormFn = fn(&mut VM, &[AstNode]) -> Result<Value, VmError>;

impl BuiltinRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            functions: HashMap::new(),
            handlers: Vec::new(),
        };

        // Register all built-ins
        registry.register_core();
        registry.register_math();
        registry.register_strings();
        registry.register_arrays();
        registry.register_hofs();

        registry
    }

    pub fn get(&self, name: &str) -> Option<BuiltinId> {
        self.functions.get(name).copied()
    }

    pub fn call(&mut self, vm: &mut VM, id: BuiltinId, args: &[Value])
        -> Result<Value, VmError> {
        match &self.handlers[id] {
            BuiltinHandler::Native(f) => f(vm, args),
            BuiltinHandler::SpecialForm(_) => {
                Err(VmError::Runtime("Special form requires AST access".into()))
            }
            BuiltinHandler::Opcode(_) => {
                Err(VmError::Runtime("Opcode built-in called as function".into()))
            }
        }
    }
}
```

### Compiler Integration

```rust
// File: crates/achronyme-vm/src/compiler/expressions/functions.rs

impl Compiler {
    pub(crate) fn compile_function_call(
        &mut self,
        name: &str,
        args: &[AstNode]
    ) -> Result<RegResult, CompileError> {
        // Check if it's a built-in function
        if let Some(builtin_id) = self.builtins.get(name) {
            return self.compile_builtin_call(builtin_id, args);
        }

        // Otherwise compile as user function
        self.compile_user_function_call(name, args)
    }

    fn compile_builtin_call(
        &mut self,
        builtin_id: BuiltinId,
        args: &[AstNode]
    ) -> Result<RegResult, CompileError> {
        // Allocate result register
        let result_reg = self.registers.allocate()?;

        // Compile arguments
        let mut arg_regs = Vec::new();
        for arg in args {
            let arg_res = self.compile_expression(arg)?;
            arg_regs.push(arg_res.reg());
        }

        // Emit CALL_BUILTIN instruction
        self.emit(encode_abx(
            OpCode::CallBuiltin.as_u8(),
            result_reg,
            builtin_id as u16,
        ));

        // Emit argument count and registers
        // (implementation detail: may need multiple instructions)

        // Free temporary argument registers
        for (i, arg_reg) in arg_regs.iter().enumerate() {
            if self.is_temp_register(*arg_reg) {
                self.registers.free(*arg_reg);
            }
        }

        Ok(RegResult::temp(result_reg))
    }
}
```

---

## Phase 4A: Core Essentials

**Priority**: CRITICAL
**Estimated Time**: 2 hours
**Dependencies**: None

### I/O Functions (3 functions)

#### 1. print(...values: Any) -> Null

**Signature**: Variadic (1+ arguments)
**Implementation File**: `crates/achronyme-vm/src/builtins/io.rs`
**Type**: Native function

```rust
pub fn builtin_print(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime("print requires at least 1 argument".into()));
    }

    let output = args.iter()
        .map(|v| format!("{}", v))
        .collect::<Vec<_>>()
        .join(" ");

    println!("{}", output);
    Ok(Value::Null)
}
```

**Example Usage**:
```javascript
print("Hello, World!")           // "Hello, World!"
print("x =", 42, "y =", 3.14)    // "x = 42 y = 3.14"
```

**Test Cases**:
```rust
#[test]
fn test_print_single() {
    let result = execute("print(42)").unwrap();
    assert_eq!(result, Value::Null);
    // Check stdout capture
}

#[test]
fn test_print_multiple() {
    execute("print(1, 2, 3)").unwrap();
    // Verify output: "1 2 3\n"
}
```

---

#### 2. typeof(value: Any) -> String

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/introspection.rs`
**Type**: Native function

```rust
pub fn builtin_typeof(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("typeof requires exactly 1 argument".into()));
    }

    let type_name = match &args[0] {
        Value::Number(_) => "Number",
        Value::Boolean(_) => "Boolean",
        Value::Null => "Null",
        Value::String(_) => "String",
        Value::Vector(_) => "Vector",
        Value::Record(_) => "Record",
        Value::Function(_) => "Function",
        Value::Closure(_) => "Function",
        Value::Tensor(_) => "Tensor",
        Value::Complex(_) => "Complex",
        Value::ComplexTensor(_) => "ComplexTensor",
    };

    Ok(Value::String(type_name.to_string()))
}
```

**Example Usage**:
```javascript
typeof(42)           // "Number"
typeof([1, 2, 3])    // "Vector"
typeof({x: 1})       // "Record"
typeof((x) => x*2)   // "Function"
```

**Test Cases**:
```rust
#[test]
fn test_typeof_number() {
    let result = execute("typeof(42)").unwrap();
    assert_eq!(result, Value::String("Number".to_string()));
}

#[test]
fn test_typeof_vector() {
    let result = execute("typeof([1, 2, 3])").unwrap();
    assert_eq!(result, Value::String("Vector".to_string()));
}
```

---

#### 3. str(value: Any) -> String

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/conversion.rs`
**Type**: Native function

```rust
pub fn builtin_str(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("str requires exactly 1 argument".into()));
    }

    let string_repr = format!("{}", args[0]);
    Ok(Value::String(string_repr))
}
```

**Example Usage**:
```javascript
str(42)              // "42"
str(3.14)            // "3.14"
str(true)            // "true"
str([1, 2, 3])       // "[1, 2, 3]"
```

---

### Array Core Functions (3 functions)

#### 4. len(collection: Vector | Record | String) -> Number

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/arrays.rs`
**Type**: Opcode (ArrayLen)

```rust
// VM execution handler
OpCode::ArrayLen => {
    let dst = a;
    let arr_reg = b;

    let value = self.get_register(arr_reg)?.clone();
    let length = match value {
        Value::Vector(vec_rc) => vec_rc.borrow().len() as f64,
        Value::Tensor(tensor) => tensor.len() as f64,
        Value::String(s) => s.len() as f64,
        Value::Record(rec_rc) => rec_rc.borrow().len() as f64,
        _ => return Err(VmError::TypeError {
            operation: "len".to_string(),
            expected: "Vector, Tensor, String, or Record".to_string(),
            got: format!("{:?}", value),
        }),
    };

    self.set_register(dst, Value::Number(length))?;
    Ok(ExecutionResult::Continue)
}
```

**Example Usage**:
```javascript
len([1, 2, 3])       // 3.0
len("hello")         // 5.0
len({a: 1, b: 2})    // 2.0
```

**Test Cases**:
```rust
#[test]
fn test_len_vector() {
    let result = execute("len([1, 2, 3, 4, 5])").unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_len_empty() {
    let result = execute("len([])").unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_len_record() {
    let result = execute("len({x: 1, y: 2, z: 3})").unwrap();
    assert_eq!(result, Value::Number(3.0));
}
```

---

#### 5. sum(array: Vector | Tensor) -> Number | Complex

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/arrays.rs`
**Type**: Native function

```rust
pub fn builtin_sum(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("sum requires exactly 1 argument".into()));
    }

    match &args[0] {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            let mut sum = Value::Number(0.0);
            for val in vec.iter() {
                sum = vm.add_values(&sum, val)?;
            }
            Ok(sum)
        }
        Value::Tensor(tensor) => {
            let sum_val = tensor.data().iter().sum();
            Ok(Value::Number(sum_val))
        }
        _ => Err(VmError::TypeError {
            operation: "sum".to_string(),
            expected: "Vector or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
```

**Example Usage**:
```javascript
sum([1, 2, 3, 4, 5])     // 15.0
sum([])                  // 0.0
sum([1.5, 2.5, 3.0])     // 7.0
```

---

#### 6. range(start: Number, end: Number, step?: Number) -> Vector

**Signature**: Variadic (2-3 arguments)
**Implementation File**: `crates/achronyme-vm/src/builtins/arrays.rs`
**Type**: Native function

```rust
pub fn builtin_range(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime("range requires 2 or 3 arguments".into()));
    }

    let start = match &args[0] {
        Value::Number(n) => *n as i64,
        _ => return Err(VmError::TypeError {
            operation: "range".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let end = match &args[1] {
        Value::Number(n) => *n as i64,
        _ => return Err(VmError::TypeError {
            operation: "range".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    let step = if args.len() == 3 {
        match &args[2] {
            Value::Number(n) => *n as i64,
            _ => return Err(VmError::TypeError {
                operation: "range".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", args[2]),
            }),
        }
    } else {
        1
    };

    if step == 0 {
        return Err(VmError::Runtime("range step cannot be zero".into()));
    }

    let mut result = Vec::new();
    if step > 0 {
        let mut i = start;
        while i < end {
            result.push(Value::Number(i as f64));
            i += step;
        }
    } else {
        let mut i = start;
        while i > end {
            result.push(Value::Number(i as f64));
            i += step;
        }
    }

    Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(result))))
}
```

**Example Usage**:
```javascript
range(0, 5)          // [0, 1, 2, 3, 4]
range(1, 10, 2)      // [1, 3, 5, 7, 9]
range(5, 0, -1)      // [5, 4, 3, 2, 1]
```

**Test Cases**:
```rust
#[test]
fn test_range_basic() {
    let result = execute("range(0, 5)").unwrap();
    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(0.0));
            assert_eq!(vec[4], Value::Number(4.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_range_step() {
    let result = execute("range(1, 10, 2)").unwrap();
    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[4], Value::Number(9.0));
        }
        _ => panic!("Expected Vector"),
    }
}
```

---

### Record Functions (3 functions)

#### 7. keys(record: Record) -> Vector

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/records.rs`
**Type**: Opcode (RecordKeys)

```rust
// VM execution handler
OpCode::RecordKeys => {
    let dst = a;
    let rec_reg = b;

    let value = self.get_register(rec_reg)?.clone();
    match value {
        Value::Record(rec_rc) => {
            let rec = rec_rc.borrow();
            let keys: Vec<Value> = rec.keys()
                .map(|k| Value::String(k.clone()))
                .collect();
            self.set_register(
                dst,
                Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(keys)))
            )?;
            Ok(ExecutionResult::Continue)
        }
        _ => Err(VmError::TypeError {
            operation: "keys".to_string(),
            expected: "Record".to_string(),
            got: format!("{:?}", value),
        }),
    }
}
```

**Example Usage**:
```javascript
keys({a: 1, b: 2, c: 3})     // ["a", "b", "c"]
keys({})                     // []
```

---

#### 8. values(record: Record) -> Vector

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/records.rs`
**Type**: Opcode (RecordValues)

```rust
// VM execution handler
OpCode::RecordValues => {
    let dst = a;
    let rec_reg = b;

    let value = self.get_register(rec_reg)?.clone();
    match value {
        Value::Record(rec_rc) => {
            let rec = rec_rc.borrow();
            let vals: Vec<Value> = rec.values().cloned().collect();
            self.set_register(
                dst,
                Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(vals)))
            )?;
            Ok(ExecutionResult::Continue)
        }
        _ => Err(VmError::TypeError {
            operation: "values".to_string(),
            expected: "Record".to_string(),
            got: format!("{:?}", value),
        }),
    }
}
```

**Example Usage**:
```javascript
values({a: 1, b: 2, c: 3})   // [1, 2, 3]
values({})                   // []
```

---

#### 9. has_field(record: Record, field: String) -> Boolean

**Signature**: 2 arguments
**Implementation File**: `crates/achronyme-vm/src/builtins/records.rs`
**Type**: Native function

```rust
pub fn builtin_has_field(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("has_field requires 2 arguments".into()));
    }

    let record = match &args[0] {
        Value::Record(rec_rc) => rec_rc,
        _ => return Err(VmError::TypeError {
            operation: "has_field".to_string(),
            expected: "Record".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let field_name = match &args[1] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "has_field".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    let has_field = record.borrow().contains_key(field_name);
    Ok(Value::Boolean(has_field))
}
```

**Example Usage**:
```javascript
has_field({a: 1, b: 2}, "a")     // true
has_field({a: 1, b: 2}, "c")     // false
```

---

## Phase 4B: Higher-Order Functions

**Priority**: HIGH
**Estimated Time**: 3-4 hours
**Dependencies**: Phase 4A (for basic array support)

All HOFs are **Special Forms** requiring access to the AST for lazy evaluation.

### Implementation Strategy

Higher-order functions cannot be implemented as simple native functions because they need to:
1. Accept function arguments without evaluating them
2. Evaluate the function body in a specific context
3. Have access to the evaluator/VM execution context

**Two approaches**:

**Approach A: Compile-time transformation** (Recommended)
- Transform HOF calls into loops at compile-time
- Example: `map((x) => x * 2, [1,2,3])` → `for i in [1,2,3] { push(result, i * 2) }`
- Pros: Better performance, no special VM support needed
- Cons: More complex compiler logic

**Approach B: Runtime HOF support**
- Add special opcodes for HOFs
- VM evaluates lambda in loop context
- Pros: Simpler compiler
- Cons: Performance overhead, complex VM state management

We'll use **Approach A** for Phase 4B.

---

### Core Higher-Order Functions (4 functions)

#### 10. map(fn: Function, collection: Vector) -> Vector

**Signature**: 2 arguments (function, collection)
**Implementation**: Compiler transformation
**File**: `crates/achronyme-vm/src/compiler/hof.rs`

**Transformation**:
```javascript
// Source code:
map((x) => x * 2, [1, 2, 3])

// Compiles to equivalent of:
{
    let __collection = [1, 2, 3]
    let __result = []
    let __len = len(__collection)
    mut __i = 0
    while (__i < __len) {
        let x = __collection[__i]
        let __mapped = x * 2
        __result[__i] = __mapped
        __i = __i + 1
    }
    __result
}
```

**Compiler Implementation**:
```rust
impl Compiler {
    fn compile_map_call(
        &mut self,
        lambda: &AstNode,
        collection: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Allocate registers
        let coll_reg = self.compile_expression(collection)?;
        let result_reg = self.registers.allocate()?;
        let i_reg = self.registers.allocate()?;
        let len_reg = self.registers.allocate()?;
        let elem_reg = self.registers.allocate()?;
        let mapped_reg = self.registers.allocate()?;

        // Create empty result array
        self.emit(encode_abc(OpCode::NewVector.as_u8(), result_reg, 0, 0));

        // Get collection length
        self.emit(encode_abc(OpCode::ArrayLen.as_u8(), len_reg, coll_reg.reg(), 0));

        // Initialize loop counter
        self.emit_load_const(i_reg, self.add_constant(Value::Number(0.0))?);

        // Loop start
        let loop_start = self.current_position();

        // Check condition: i < len
        let cond_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::Lt.as_u8(), cond_reg, i_reg, len_reg));
        let jump_end = self.emit_jump_if_false(cond_reg);

        // Get element: elem = collection[i]
        self.emit(encode_abc(OpCode::VecGet.as_u8(), elem_reg, coll_reg.reg(), i_reg));

        // Extract lambda parameter name
        let param_name = self.extract_lambda_param(lambda)?;

        // Define parameter in symbol table
        self.symbols.define(param_name.clone(), elem_reg)?;

        // Compile lambda body
        let body = self.extract_lambda_body(lambda)?;
        let mapped_result = self.compile_expression(body)?;

        // Store result: result.push(mapped)
        self.emit(encode_abc(OpCode::VecPush.as_u8(), result_reg, mapped_result.reg(), 0));

        // Increment counter: i = i + 1
        let one_reg = self.registers.allocate()?;
        self.emit_load_const(one_reg, self.add_constant(Value::Number(1.0))?);
        self.emit(encode_abc(OpCode::Add.as_u8(), i_reg, i_reg, one_reg));
        self.registers.free(one_reg);

        // Jump back to loop start
        self.emit_jump(loop_start);

        // Patch jump_end
        self.patch_jump(jump_end);

        // Free temporary registers
        self.registers.free(i_reg);
        self.registers.free(len_reg);
        self.registers.free(elem_reg);
        self.registers.free(cond_reg);
        if coll_reg.is_temp() {
            self.registers.free(coll_reg.reg());
        }

        Ok(RegResult::temp(result_reg))
    }
}
```

**Example Usage**:
```javascript
map((x) => x * 2, [1, 2, 3])              // [2, 4, 6]
map((x) => x + 1, [0, 1, 2])              // [1, 2, 3]
map((s) => upper(s), ["a", "b", "c"])     // ["A", "B", "C"]
```

**Test Cases**:
```rust
#[test]
fn test_map_double() {
    let result = execute("map((x) => x * 2, [1, 2, 3])").unwrap();
    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec[0], Value::Number(2.0));
            assert_eq!(vec[1], Value::Number(4.0));
            assert_eq!(vec[2], Value::Number(6.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_map_empty() {
    let result = execute("map((x) => x * 2, [])").unwrap();
    match result {
        Value::Vector(vec_rc) => {
            assert_eq!(vec_rc.borrow().len(), 0);
        }
        _ => panic!("Expected Vector"),
    }
}
```

---

#### 11. filter(predicate: Function, collection: Vector) -> Vector

**Signature**: 2 arguments (predicate function, collection)
**Implementation**: Compiler transformation
**File**: `crates/achronyme-vm/src/compiler/hof.rs`

**Transformation**:
```javascript
// Source:
filter((x) => x > 2, [1, 2, 3, 4, 5])

// Compiles to:
{
    let __collection = [1, 2, 3, 4, 5]
    let __result = []
    mut __i = 0
    let __len = len(__collection)
    while (__i < __len) {
        let x = __collection[__i]
        let __matches = x > 2
        if (__matches) {
            __result.push(x)
        }
        __i = __i + 1
    }
    __result
}
```

**Example Usage**:
```javascript
filter((x) => x > 2, [1, 2, 3, 4, 5])     // [3, 4, 5]
filter((x) => x % 2 == 0, [1,2,3,4,5,6])  // [2, 4, 6]
filter((x) => x > 10, [1, 2, 3])          // []
```

---

#### 12. reduce(fn: Function, init: Any, collection: Vector) -> Any

**Signature**: 3 arguments (reducer function, initial value, collection)
**Implementation**: Compiler transformation
**File**: `crates/achronyme-vm/src/compiler/hof.rs`

**Transformation**:
```javascript
// Source:
reduce((acc, x) => acc + x, 0, [1, 2, 3, 4])

// Compiles to:
{
    let __collection = [1, 2, 3, 4]
    mut __acc = 0
    mut __i = 0
    let __len = len(__collection)
    while (__i < __len) {
        let x = __collection[__i]
        __acc = acc + x
        __i = __i + 1
    }
    __acc
}
```

**Example Usage**:
```javascript
reduce((acc, x) => acc + x, 0, [1,2,3,4])        // 10
reduce((acc, x) => acc * x, 1, [1,2,3,4])        // 24
reduce((acc, x) => acc + len(x), 0, ["a","bc"])  // 3
```

---

#### 13. pipe(value: Any, ...functions: Function) -> Any

**Signature**: Variadic (2+ arguments: initial value + functions)
**Implementation**: Compiler transformation
**File**: `crates/achronyme-vm/src/compiler/hof.rs`

**Transformation**:
```javascript
// Source:
pipe(5, (x) => x * 2, (x) => x + 1, (x) => x * x)

// Compiles to:
{
    let __v0 = 5
    let __v1 = ((x) => x * 2)(__v0)
    let __v2 = ((x) => x + 1)(__v1)
    let __v3 = ((x) => x * x)(__v2)
    __v3
}
```

**Example Usage**:
```javascript
pipe(5, (x) => x * 2, (x) => x + 1)              // 11
pipe([1,2,3], (a) => map((x) => x*2, a), sum)    // 12
```

---

### Predicate Functions (5 functions)

#### 14. any(collection: Vector, predicate: Function) -> Boolean

**Signature**: 2 arguments
**Implementation**: Compiler transformation with early exit

**Transformation**:
```javascript
// Source:
any([1, 2, 3, 4], (x) => x > 3)

// Compiles to:
{
    let __collection = [1, 2, 3, 4]
    let __result = false
    mut __i = 0
    let __len = len(__collection)
    while (__i < __len) {
        let x = __collection[__i]
        if (x > 3) {
            __result = true
            break
        }
        __i = __i + 1
    }
    __result
}
```

**Example Usage**:
```javascript
any([1, 2, 3, 4], (x) => x > 3)      // true
any([1, 2, 3], (x) => x > 10)        // false
any([], (x) => true)                 // false
```

---

#### 15. all(collection: Vector, predicate: Function) -> Boolean

**Signature**: 2 arguments
**Implementation**: Compiler transformation with early exit

**Example Usage**:
```javascript
all([2, 4, 6], (x) => x % 2 == 0)    // true
all([1, 2, 3], (x) => x > 0)         // true
all([1, 2, 3], (x) => x > 2)         // false
```

---

#### 16. find(collection: Vector, predicate: Function) -> Any

**Signature**: 2 arguments
**Returns**: First element matching predicate, or `null` if none
**Implementation**: Compiler transformation with early exit

**Example Usage**:
```javascript
find([1, 2, 3, 4], (x) => x > 2)     // 3
find([1, 2, 3], (x) => x > 10)       // null
```

---

#### 17. findIndex(collection: Vector, predicate: Function) -> Number

**Signature**: 2 arguments
**Returns**: Index of first matching element, or `-1` if none
**Implementation**: Compiler transformation

**Example Usage**:
```javascript
findIndex([1, 2, 3, 4], (x) => x > 2)    // 2
findIndex([1, 2, 3], (x) => x > 10)      // -1
```

---

#### 18. count(collection: Vector, predicate: Function) -> Number

**Signature**: 2 arguments
**Returns**: Count of elements matching predicate
**Implementation**: Compiler transformation

**Example Usage**:
```javascript
count([1, 2, 3, 4, 5], (x) => x > 2)     // 3
count([1, 2, 3], (x) => x % 2 == 0)      // 1
```

---

## Phase 4C: Mathematical Functions

**Priority**: MEDIUM
**Estimated Time**: 2 hours
**Dependencies**: None (can be implemented independently)

All math functions support element-wise operations on vectors and tensors.

### Basic Math (9 functions)

#### 19. abs(x: Number | Complex | Vector) -> Number | Vector

**Signature**: 1 argument
**Implementation File**: `crates/achronyme-vm/src/builtins/math.rs`
**Type**: Native function

```rust
pub fn builtin_abs(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("abs requires exactly 1 argument".into()));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(n.abs())),

        Value::Complex(c) => {
            // Magnitude: sqrt(re^2 + im^2)
            let magnitude = (c.re * c.re + c.im * c.im).sqrt();
            Ok(Value::Number(magnitude))
        }

        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            let result: Vec<Value> = vec.iter()
                .map(|v| builtin_abs(vm, &[v.clone()]))
                .collect::<Result<_, _>>()?;
            Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(result))))
        }

        Value::Tensor(tensor) => {
            let abs_data: Vec<f64> = tensor.data().iter().map(|x| x.abs()).collect();
            Ok(Value::Tensor(RealTensor::new(abs_data, tensor.shape().to_vec())?))
        }

        _ => Err(VmError::TypeError {
            operation: "abs".to_string(),
            expected: "Number, Complex, Vector, or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
```

**Example Usage**:
```javascript
abs(-5)              // 5.0
abs(3.14)            // 3.14
abs(3+4i)            // 5.0
abs([-1, -2, -3])    // [1, 2, 3]
```

---

#### 20. sqrt(x: Number | Complex | Vector) -> Number | Complex | Vector

**Signature**: 1 argument
**Type**: Native function
**Note**: Returns Complex for negative numbers

```rust
pub fn builtin_sqrt(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime("sqrt requires exactly 1 argument".into()));
    }

    match &args[0] {
        Value::Number(n) => {
            if *n >= 0.0 {
                Ok(Value::Number(n.sqrt()))
            } else {
                // Return complex number for negative input
                Ok(Value::Complex(Complex { re: 0.0, im: (-n).sqrt() }))
            }
        }

        Value::Complex(c) => {
            // Complex square root
            let r = (c.re * c.re + c.im * c.im).sqrt();
            let theta = c.im.atan2(c.re);
            Ok(Value::Complex(Complex {
                re: (r.sqrt() * (theta / 2.0).cos()),
                im: (r.sqrt() * (theta / 2.0).sin()),
            }))
        }

        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            let result: Vec<Value> = vec.iter()
                .map(|v| builtin_sqrt(vm, &[v.clone()]))
                .collect::<Result<_, _>>()?;
            Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(result))))
        }

        _ => Err(VmError::TypeError {
            operation: "sqrt".to_string(),
            expected: "Number, Complex, or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
```

**Example Usage**:
```javascript
sqrt(16)             // 4.0
sqrt(2)              // 1.414...
sqrt(-1)             // 0+1i
sqrt([4, 9, 16])     // [2, 3, 4]
```

---

#### 21. pow(base: Number, exponent: Number) -> Number

**Signature**: 2 arguments
**Type**: Native function
**Note**: Also available as `^` operator

```rust
pub fn builtin_pow(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("pow requires exactly 2 arguments".into()));
    }

    let base = match args[0] {
        Value::Number(n) => n,
        _ => return Err(VmError::TypeError {
            operation: "pow".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let exponent = match args[1] {
        Value::Number(n) => n,
        _ => return Err(VmError::TypeError {
            operation: "pow".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    Ok(Value::Number(base.powf(exponent)))
}
```

**Example Usage**:
```javascript
pow(2, 3)            // 8.0
pow(10, -2)          // 0.01
pow(4, 0.5)          // 2.0
```

---

#### 22-23. min(...args: Number) -> Number, max(...args: Number) -> Number

**Signature**: Variadic (1+ arguments)
**Type**: Native function
**Note**: Can accept array as single argument

```rust
pub fn builtin_min(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.is_empty() {
        return Err(VmError::Runtime("min requires at least 1 argument".into()));
    }

    // Handle single array argument
    if args.len() == 1 {
        if let Value::Vector(vec_rc) = &args[0] {
            let vec = vec_rc.borrow();
            if vec.is_empty() {
                return Err(VmError::Runtime("min of empty array".into()));
            }
            return builtin_min(vm, &vec);
        }
    }

    // Find minimum
    let mut min_val = f64::INFINITY;
    for arg in args {
        match arg {
            Value::Number(n) => {
                if *n < min_val {
                    min_val = *n;
                }
            }
            _ => return Err(VmError::TypeError {
                operation: "min".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?}", arg),
            }),
        }
    }

    Ok(Value::Number(min_val))
}

pub fn builtin_max(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    // Similar to min, but find maximum
    // ... implementation
}
```

**Example Usage**:
```javascript
min(3, 1, 4, 1, 5)       // 1.0
min([3, 1, 4, 1, 5])     // 1.0
max(3, 1, 4, 1, 5)       // 5.0
max([3, 1, 4, 1, 5])     // 5.0
```

---

#### 24-26. floor(x), ceil(x), round(x)

**Signature**: 1 argument each
**Type**: Native functions
**Supports**: Element-wise on vectors/tensors

```rust
pub fn builtin_floor(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.floor(), "floor")
}

pub fn builtin_ceil(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.ceil(), "ceil")
}

pub fn builtin_round(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.round(), "round")
}

// Helper function
fn apply_unary_math<F>(args: &[Value], f: F, op_name: &str) -> Result<Value, VmError>
where
    F: Fn(f64) -> f64,
{
    if args.len() != 1 {
        return Err(VmError::Runtime(format!("{} requires exactly 1 argument", op_name)));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(f(*n))),
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            let result: Vec<Value> = vec.iter()
                .map(|v| match v {
                    Value::Number(n) => Ok(Value::Number(f(*n))),
                    _ => Err(VmError::TypeError {
                        operation: op_name.to_string(),
                        expected: "Number".to_string(),
                        got: format!("{:?}", v),
                    }),
                })
                .collect::<Result<_, _>>()?;
            Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(result))))
        }
        _ => Err(VmError::TypeError {
            operation: op_name.to_string(),
            expected: "Number or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
```

**Example Usage**:
```javascript
floor(3.7)           // 3.0
ceil(3.2)            // 4.0
round(3.5)           // 4.0
floor([1.9, 2.1])    // [1, 2]
```

---

### Trigonometry (7 functions)

#### 27-29. sin(x), cos(x), tan(x)

**Signature**: 1 argument each
**Type**: Native functions
**Supports**: Element-wise on vectors/tensors

```rust
pub fn builtin_sin(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.sin(), "sin")
}

pub fn builtin_cos(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.cos(), "cos")
}

pub fn builtin_tan(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.tan(), "tan")
}
```

**Example Usage**:
```javascript
sin(pi/2)            // 1.0
cos(0)               // 1.0
tan(pi/4)            // 1.0
```

---

#### 30-33. asin(x), acos(x), atan(x), atan2(y, x)

**Signature**: 1 argument (asin, acos, atan), 2 arguments (atan2)
**Type**: Native functions

```rust
pub fn builtin_asin(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.asin(), "asin")
}

pub fn builtin_acos(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.acos(), "acos")
}

pub fn builtin_atan(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.atan(), "atan")
}

pub fn builtin_atan2(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("atan2 requires exactly 2 arguments".into()));
    }

    let y = match args[0] {
        Value::Number(n) => n,
        _ => return Err(VmError::TypeError {
            operation: "atan2".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let x = match args[1] {
        Value::Number(n) => n,
        _ => return Err(VmError::TypeError {
            operation: "atan2".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    Ok(Value::Number(y.atan2(x)))
}
```

**Example Usage**:
```javascript
asin(1)              // π/2
acos(0)              // π/2
atan(1)              // π/4
atan2(1, 1)          // π/4
```

---

### Exponential & Logarithmic (4 functions)

#### 34-37. exp(x), ln(x), log10(x), log2(x)

**Signature**: 1 argument each
**Type**: Native functions

```rust
pub fn builtin_exp(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.exp(), "exp")
}

pub fn builtin_ln(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.ln(), "ln")
}

pub fn builtin_log10(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.log10(), "log10")
}

pub fn builtin_log2(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.log2(), "log2")
}
```

**Example Usage**:
```javascript
exp(1)               // 2.718...
ln(e)                // 1.0
log10(100)           // 2.0
log2(8)              // 3.0
```

---

## Phase 4D: String Support

**Priority**: HIGH (critical for real programs)
**Estimated Time**: 2-3 hours
**Dependencies**: None

### String Literals & Operations

#### String Literal Support

**Parser Changes**:
```rust
// File: crates/achronyme-parser/src/grammar.pest
string = { "\"" ~ string_content ~ "\"" }
string_content = { (!"\"" ~ ANY)* }
```

**AST Node**:
```rust
// File: crates/achronyme-parser/src/ast.rs
pub enum AstNode {
    // ... existing variants ...
    StringLiteral(String),
}
```

**Compiler Support**:
```rust
// File: crates/achronyme-vm/src/compiler/expressions/literals.rs
AstNode::StringLiteral(s) => {
    let reg = self.registers.allocate()?;
    let str_idx = self.add_string(s.clone())?;
    self.emit(encode_abx(OpCode::NewString.as_u8(), reg, str_idx as u16));
    Ok(RegResult::temp(reg))
}
```

**VM Support**:
```rust
// File: crates/achronyme-vm/src/vm/execution/strings.rs
OpCode::NewString => {
    let dst = a;
    let str_idx = bx as usize;

    let string = self.get_string(str_idx)?.to_string();
    self.set_register(dst, Value::String(string))?;
    Ok(ExecutionResult::Continue)
}
```

---

#### 38. String Concatenation (+ operator)

**Compiler Support**:
```rust
// File: crates/achronyme-vm/src/compiler/expressions/operators.rs
fn compile_binary_op(&mut self, op: &BinaryOp, left: &AstNode, right: &AstNode)
    -> Result<RegResult, CompileError> {

    match op {
        BinaryOp::Add => {
            let left_res = self.compile_expression(left)?;
            let right_res = self.compile_expression(right)?;
            let result_reg = self.registers.allocate()?;

            // Emit StrConcat or Add depending on runtime type
            // For now, emit Add and let VM handle string concatenation
            self.emit(encode_abc(
                OpCode::Add.as_u8(),
                result_reg,
                left_res.reg(),
                right_res.reg(),
            ));

            // Free temps
            if left_res.is_temp() { self.registers.free(left_res.reg()); }
            if right_res.is_temp() { self.registers.free(right_res.reg()); }

            Ok(RegResult::temp(result_reg))
        }
        // ... other operators
    }
}
```

**VM Support** (modify existing Add opcode):
```rust
// File: crates/achronyme-vm/src/vm/execution/arithmetic.rs
OpCode::Add => {
    let left = self.get_register(b)?.clone();
    let right = self.get_register(c)?.clone();

    let result = match (&left, &right) {
        (Value::Number(a), Value::Number(b)) => Value::Number(a + b),

        (Value::String(a), Value::String(b)) => {
            Value::String(format!("{}{}", a, b))
        }

        (Value::String(a), b) => {
            Value::String(format!("{}{}", a, b))
        }

        (a, Value::String(b)) => {
            Value::String(format!("{}{}", a, b))
        }

        // ... other cases (vectors, tensors, etc.)

        _ => return Err(VmError::TypeError {
            operation: "addition".to_string(),
            expected: "Number, String, Vector, or Tensor".to_string(),
            got: format!("{:?} + {:?}", left, right),
        }),
    };

    self.set_register(a, result)?;
    Ok(ExecutionResult::Continue)
}
```

**Example Usage**:
```javascript
"Hello" + " " + "World"      // "Hello World"
"x = " + 42                  // "x = 42"
"Count: " + len([1,2,3])     // "Count: 3"
```

---

### String Functions (14 functions)

#### 39. concat(s1: String, s2: String) -> String

**Signature**: 2 arguments
**Type**: Native function
**Note**: Same as `+` operator

```rust
pub fn builtin_concat(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("concat requires exactly 2 arguments".into()));
    }

    let s1 = match &args[0] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "concat".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let s2 = match &args[1] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "concat".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    Ok(Value::String(format!("{}{}", s1, s2)))
}
```

**Example**: `concat("hello", " world")` → `"hello world"`

---

#### 40. split(str: String, delimiter: String) -> Vector

**Signature**: 2 arguments
**Type**: Native function

```rust
pub fn builtin_split(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("split requires exactly 2 arguments".into()));
    }

    let string = match &args[0] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "split".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let delimiter = match &args[1] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "split".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    let parts: Vec<Value> = string
        .split(delimiter.as_str())
        .map(|s| Value::String(s.to_string()))
        .collect();

    Ok(Value::Vector(std::rc::Rc::new(std::cell::RefCell::new(parts))))
}
```

**Example**: `split("a,b,c", ",")` → `["a", "b", "c"]`

---

#### 41. join(array: Vector, delimiter: String) -> String

**Signature**: 2 arguments
**Type**: Native function

```rust
pub fn builtin_join(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("join requires exactly 2 arguments".into()));
    }

    let array = match &args[0] {
        Value::Vector(vec_rc) => vec_rc,
        _ => return Err(VmError::TypeError {
            operation: "join".to_string(),
            expected: "Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let delimiter = match &args[1] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "join".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    let vec = array.borrow();
    let parts: Vec<String> = vec.iter()
        .map(|v| format!("{}", v))
        .collect();

    Ok(Value::String(parts.join(delimiter)))
}
```

**Example**: `join(["a", "b", "c"], ",")` → `"a,b,c"`

---

#### 42-43. upper(str), lower(str)

**Signature**: 1 argument each
**Type**: Native functions

```rust
pub fn builtin_upper(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_string_transform(args, |s| s.to_uppercase(), "upper")
}

pub fn builtin_lower(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_string_transform(args, |s| s.to_lowercase(), "lower")
}

fn apply_string_transform<F>(args: &[Value], f: F, op_name: &str) -> Result<Value, VmError>
where
    F: Fn(&str) -> String,
{
    if args.len() != 1 {
        return Err(VmError::Runtime(format!("{} requires exactly 1 argument", op_name)));
    }

    match &args[0] {
        Value::String(s) => Ok(Value::String(f(s))),
        _ => Err(VmError::TypeError {
            operation: op_name.to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
```

**Example**:
```javascript
upper("hello")       // "HELLO"
lower("WORLD")       // "world"
```

---

#### 44-46. trim(str), trim_start(str), trim_end(str)

**Signature**: 1 argument each
**Type**: Native functions

```rust
pub fn builtin_trim(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_string_transform(args, |s| s.trim().to_string(), "trim")
}

pub fn builtin_trim_start(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_string_transform(args, |s| s.trim_start().to_string(), "trim_start")
}

pub fn builtin_trim_end(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_string_transform(args, |s| s.trim_end().to_string(), "trim_end")
}
```

**Example**:
```javascript
trim("  hello  ")        // "hello"
trim_start("  hello  ")  // "hello  "
trim_end("  hello  ")    // "  hello"
```

---

#### 47-48. starts_with(str, prefix), ends_with(str, suffix)

**Signature**: 2 arguments each
**Type**: Native functions

```rust
pub fn builtin_starts_with(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("starts_with requires 2 arguments".into()));
    }

    let string = match &args[0] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "starts_with".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let prefix = match &args[1] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "starts_with".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    Ok(Value::Boolean(string.starts_with(prefix)))
}

pub fn builtin_ends_with(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    // Similar implementation
}
```

**Example**:
```javascript
starts_with("hello world", "hello")  // true
ends_with("hello world", "world")    // true
```

---

#### 49. replace(str: String, pattern: String, replacement: String) -> String

**Signature**: 3 arguments
**Type**: Native function

```rust
pub fn builtin_replace(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime("replace requires 3 arguments".into()));
    }

    let string = match &args[0] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "replace".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[0]),
        }),
    };

    let pattern = match &args[1] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "replace".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[1]),
        }),
    };

    let replacement = match &args[2] {
        Value::String(s) => s,
        _ => return Err(VmError::TypeError {
            operation: "replace".to_string(),
            expected: "String".to_string(),
            got: format!("{:?}", args[2]),
        }),
    };

    Ok(Value::String(string.replace(pattern, replacement)))
}
```

**Example**: `replace("hello world", "world", "rust")` → `"hello rust"`

---

#### 50. contains(collection: Vector | String, value: Any) -> Boolean

**Signature**: 2 arguments
**Type**: Native function
**Note**: Works for both arrays and strings

```rust
pub fn builtin_contains(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime("contains requires 2 arguments".into()));
    }

    match &args[0] {
        Value::String(s) => {
            let substring = match &args[1] {
                Value::String(sub) => sub,
                _ => return Err(VmError::TypeError {
                    operation: "contains".to_string(),
                    expected: "String".to_string(),
                    got: format!("{:?}", args[1]),
                }),
            };
            Ok(Value::Boolean(s.contains(substring.as_str())))
        }

        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            let found = vec.iter().any(|v| v == &args[1]);
            Ok(Value::Boolean(found))
        }

        _ => Err(VmError::TypeError {
            operation: "contains".to_string(),
            expected: "String or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}
```

**Example**:
```javascript
contains("hello", "ll")      // true
contains([1, 2, 3], 2)       // true
contains([1, 2, 3], 5)       // false
```

---

#### 51-52. String Indexing & Slicing

**Note**: String indexing uses same syntax as array indexing: `str[0]`, `str[1..5]`

**Compiler**: Already handled by IndexAccess AST node
**VM**: Modify VecGet opcode to handle strings

```rust
// File: crates/achronyme-vm/src/vm/execution/vectors.rs
OpCode::VecGet => {
    let dst = a;
    let obj_reg = b;
    let idx_reg = c;

    let obj_value = self.get_register(obj_reg)?.clone();
    let idx_value = self.get_register(idx_reg)?.clone();

    match (&obj_value, &idx_value) {
        (Value::Vector(vec_rc), Value::Number(idx)) => {
            // ... existing vector logic ...
        }

        (Value::String(s), Value::Number(idx)) => {
            let index = *idx as isize;
            let actual_idx = if index < 0 {
                (s.len() as isize + index) as usize
            } else {
                index as usize
            };

            if actual_idx >= s.len() {
                return Err(VmError::Runtime(format!("String index out of bounds")));
            }

            let char_at = s.chars().nth(actual_idx)
                .ok_or_else(|| VmError::Runtime("Invalid string index".into()))?;

            self.set_register(dst, Value::String(char_at.to_string()))?;
            Ok(ExecutionResult::Continue)
        }

        _ => Err(VmError::TypeError {
            operation: "index access".to_string(),
            expected: "Vector or String with Number index".to_string(),
            got: format!("{:?}[{:?}]", obj_value, idx_value),
        }),
    }
}
```

**Example**:
```javascript
"hello"[0]           // "h"
"hello"[1]           // "e"
"hello"[-1]          // "o"
```

---

## Phase 4E: Advanced Arrays

**Priority**: MEDIUM
**Estimated Time**: 2 hours
**Dependencies**: Phase 4A (len, sum, range)

### Array Transformation Functions (11 functions)

#### 53. reverse(array: Vector) -> Vector

#### 54. product(array: Vector) -> Number

#### 55. zip(array1: Vector, array2: Vector) -> Vector

#### 56. flatten(array: Vector, depth?: Number) -> Vector

#### 57. take(array: Vector, n: Number) -> Vector

#### 58. drop(array: Vector, n: Number) -> Vector

#### 59. slice(array: Vector, start: Number, end?: Number) -> Vector

#### 60. unique(array: Vector) -> Vector

#### 61. chunk(array: Vector, size: Number) -> Vector

**Note**: Full implementations for these follow the same patterns as Phase 4A-D. They're deferred to save space in this reference document but should be straightforward native functions.

---

## Phase 4F: Complex Numbers

**Priority**: LOW
**Estimated Time**: 1 hour
**Dependencies**: None

### Complex Number Functions (6 functions)

#### 62. complex(re: Number, im: Number) -> Complex

#### 63. real(z: Complex | Number) -> Number

#### 64. imag(z: Complex | Number) -> Number

#### 65. arg(z: Complex) -> Number

#### 66. conj(z: Complex) -> Complex

**Note**: Complex numbers already supported in Value enum. These are accessor/constructor functions.

---

## Phase 4G: Linear Algebra

**Priority**: LOW (can use external crate)
**Estimated Time**: 3-4 hours
**Dependencies**: Tensor support

### Vector Operations (4 functions)

#### 67. dot(v1: Vector, v2: Vector) -> Number

#### 68. cross(v1: Vector, v2: Vector) -> Vector

#### 69. norm(v: Vector) -> Number

#### 70. normalize(v: Vector) -> Vector

### Matrix Operations (3 functions)

#### 71. transpose(matrix: Tensor) -> Tensor

#### 72. det(matrix: Tensor) -> Number

#### 73. trace(matrix: Tensor) -> Number

---

## Phase 4H: DSP Functions 🔜 REMOVED FROM CORE

**Status**: ❌ **REMOVED FROM VM RUNTIME** - Moved to future stdlib
**Priority**: Future stdlib module
**Reason**: Specialized algorithmic functions better suited for external library

These functions have been removed from the VM runtime and will be implemented as an external stdlib module accessible via FFI once the language FFI system is mature.

### FFT Functions (4 functions) - DEFERRED

#### 74. fft(signal: Vector) -> ComplexTensor

#### 75. ifft(spectrum: ComplexTensor) -> Tensor

#### 76. fft_mag(signal: Vector) -> Tensor

#### 77. fft_phase(signal: Vector) -> Tensor

### Convolution (2 functions)

#### 78. conv(signal: Vector, kernel: Vector) -> Tensor

#### 79. conv_fft(signal: Vector, kernel: Vector) -> Tensor

### Window Functions (5 functions)

#### 80-84. hanning, hamming, blackman, rectangular, linspace

---

## Phase 4I: Numerical Analysis

**Priority**: LOW (specialized)
**Estimated Time**: 6-8 hours
**Dependencies**: Special forms for function arguments

All numerical functions are **special forms** requiring AST access.

### Differentiation (4 functions)

#### 85. diff(fn: Function, x: Number, h?: Number) -> Number

#### 86. diff2(fn: Function, x: Number, h?: Number) -> Number

#### 87. diff3(fn: Function, x: Number, h?: Number) -> Number

#### 88. gradient(fn: Function, point: Vector, h?: Number) -> Vector

### Integration (4 functions)

#### 89. integral(fn: Function, a: Number, b: Number, n?: Number) -> Number

#### 90. simpson(fn: Function, a: Number, b: Number, n?: Number) -> Number

#### 91. romberg(fn: Function, a: Number, b: Number, max_iter?: Number) -> Number

#### 92. quad(fn: Function, a: Number, b: Number, tol?: Number) -> Number

### Root Finding (3 functions)

#### 93. solve(fn: Function, a: Number, b: Number, tol?: Number) -> Number

#### 94. newton(fn: Function, x0: Number, tol?: Number, max_iter?: Number) -> Number

#### 95. secant(fn: Function, x0: Number, x1: Number, tol?: Number) -> Number

---

## Phase 4J: Optimization 🔜 REMOVED FROM CORE

**Status**: ❌ **REMOVED FROM VM RUNTIME** - Moved to future stdlib
**Priority**: Future stdlib module
**Reason**: Specialized optimization algorithms better suited for external library

These functions have been removed from the VM runtime and will be implemented as an external stdlib module accessible via FFI once the language FFI system is mature.

### Linear Programming (5 functions) - DEFERRED

#### 96. ❌ simplex(c: Vector, A: Matrix, b: Vector, opts?: Record) -> Record
Standard simplex algorithm for linear programming

#### 97. ❌ dual_simplex(c: Vector, A: Matrix, b: Vector, opts?: Record) -> Record
Dual simplex algorithm variant

#### 98. ❌ two_phase_simplex(c: Vector, A: Matrix, b: Vector, opts?: Record) -> Record
Two-phase simplex for finding initial feasible solution

#### 99. ❌ revised_simplex(c: Vector, A: Matrix, b: Vector, opts?: Record) -> Record
Revised simplex with basis matrix updates

#### 100. ❌ linprog(c: Vector, A: Matrix, b: Vector, opts?: Record) -> Record
General linear programming solver (auto-selects algorithm)

### Solution Analysis (4 functions) - NOT IMPLEMENTED

#### 101. ❌ objective_value(solution: Record) -> Number
Extract objective function value from solution

#### 102. ❌ shadow_price(solution: Record, constraint: Number) -> Number
Get shadow price for a constraint

#### 103. ❌ sensitivity_c(solution: Record, variable: Number) -> Record
Sensitivity analysis on objective coefficients

#### 104. ❌ sensitivity_b(solution: Record, constraint: Number) -> Record
Sensitivity analysis on constraint bounds

---

## Phase 4K: Graph Theory 🔜 REMOVED FROM CORE

**Status**: ❌ **REMOVED FROM VM RUNTIME** - Moved to future stdlib
**Priority**: Future stdlib module
**Reason**: Specialized graph algorithms better suited for external library

These functions have been removed from the VM runtime and will be implemented as an external stdlib module accessible via FFI once the language FFI system is mature.

### Network Construction (5 functions) - DEFERRED

#### 105. network(edges: Vector, is_directed?: Boolean) -> Record

#### 106. nodes(network: Record) -> Vector

#### 107. edges(network: Record) -> Vector

#### 108. neighbors(network: Record, node: String) -> Vector

#### 109. degree(network: Record, node: String) -> Number

### Traversal (4 functions)

#### 110. bfs(network: Record, start: String) -> Vector

#### 111. dfs(network: Record, start: String) -> Vector

#### 112. bfs_path(network: Record, start: String, end: String) -> Vector

#### 113. topological_sort(network: Record) -> Vector

### Shortest Path (1 function)

#### 114. dijkstra(network: Record, start: String, end: String) -> Record

### MST (2 functions)

#### 115. kruskal(network: Record) -> Vector

#### 116. prim(network: Record, start: String) -> Vector

### Connectivity (3 functions)

#### 117. connected_components(network: Record) -> Vector

#### 118. is_connected(network: Record) -> Boolean

#### 119. has_cycle(network: Record) -> Boolean

---

## Phase 4L: PERT/CPM 🔜 REMOVED FROM CORE

**Status**: ❌ **REMOVED FROM VM RUNTIME** - Moved to future stdlib
**Priority**: Future stdlib module
**Reason**: Specialized project management algorithms better suited for external library

These functions have been removed from the VM runtime and will be implemented as an external stdlib module accessible via FFI once the language FFI system is mature.

### CPM (6 functions) - DEFERRED

#### 120. forward_pass(network: Record) -> Record

#### 121. backward_pass(network: Record) -> Record

#### 122. calculate_slack(network: Record) -> Record

#### 123. critical_path(network: Record) -> Vector

#### 124. all_critical_paths(network: Record) -> Vector

#### 125. project_duration(network: Record) -> Number

### PERT Probabilistic (6 functions)

#### 126. expected_time(optimistic: Number, most_likely: Number, pessimistic: Number) -> Number

#### 127. task_variance(optimistic: Number, most_likely: Number, pessimistic: Number) -> Number

#### 128. project_variance(network: Record) -> Number

#### 129. project_std_dev(network: Record) -> Number

#### 130. completion_probability(network: Record, target_time: Number) -> Number

#### 131. time_for_probability(network: Record, probability: Number) -> Number

### Comprehensive Analysis (1 function)

#### 132. pert_analysis(network: Record) -> Record

---

## Implementation Checklist

### Phase 4A: Core Essentials ✅ (Priority: CRITICAL) - COMPLETE

- [x] I/O Functions
  - [x] `print(...values)` - variadic, native ✅
  - [x] `typeof(value)` - 1 arg, native ✅
  - [x] `str(value)` - 1 arg, native ✅
  - [x] `println(...values)` - variadic, native (extra) ✅
  - [x] `input(prompt?)` - 0-1 args, native (extra) ✅

- [x] Array Core
  - [x] `len(collection)` - 1 arg, native ✅
  - [x] `sum(array)` - 1 arg, native ✅
  - [x] `range(start, end, step?)` - 2-3 args, native ✅

- [x] Records
  - [x] `keys(record)` - 1 arg, native ✅
  - [x] `values(record)` - 1 arg, native ✅
  - [x] `has_field(record, field)` - 2 args, native ✅

**Estimated Time**: 2 hours
**Files to Create/Modify**:
- `crates/achronyme-vm/src/builtins/mod.rs` (new)
- `crates/achronyme-vm/src/builtins/io.rs` (new)
- `crates/achronyme-vm/src/builtins/introspection.rs` (new)
- `crates/achronyme-vm/src/builtins/arrays.rs` (new)
- `crates/achronyme-vm/src/builtins/records.rs` (new)
- `crates/achronyme-vm/src/opcode.rs` (add opcodes)
- `crates/achronyme-vm/src/vm/execution/arrays.rs` (new)
- `crates/achronyme-vm/src/vm/execution/records.rs` (modify existing)
- `crates/achronyme-vm/src/compiler/expressions/functions.rs` (modify)

---

### Phase 4B: Higher-Order Functions ✅ (Priority: HIGH) - COMPLETE

- [x] Core HOFs (Native Functions)
  - [x] `map(fn, collection)` - native ✅
  - [x] `filter(predicate, collection)` - native ✅
  - [x] `reduce(fn, init, collection)` - native ✅
  - [x] `pipe(value, ...fns)` - variadic, native ✅

- [x] Predicates (Native Functions)
  - [x] `any(collection, predicate)` - native ✅
  - [x] `all(collection, predicate)` - native ✅
  - [x] `find(collection, predicate)` - native ✅
  - [x] `findIndex(collection, predicate)` - native ✅
  - [x] `count(collection, predicate)` - native ✅

**Estimated Time**: 3-4 hours
**Files to Create/Modify**:
- `crates/achronyme-vm/src/compiler/hof.rs` (new)
- `crates/achronyme-vm/src/compiler/mod.rs` (integrate HOF compiler)
- `crates/achronyme-vm/src/compiler/expressions/functions.rs` (detect HOF calls)

---

### Phase 4C: Mathematical Functions ✅ (Priority: MEDIUM) - COMPLETE

- [x] Basic Math (9 functions)
  - [x] `abs(x)` ✅, `sqrt(x)` ✅, `pow(base, exp)` ✅
  - [x] `min(...args)` ✅, `max(...args)` ✅
  - [x] `floor(x)` ✅, `ceil(x)` ✅, `round(x)` ✅, `trunc(x)` ✅

- [x] Trigonometry (7 functions)
  - [x] `sin(x)` ✅, `cos(x)` ✅, `tan(x)` ✅
  - [x] `asin(x)` ✅, `acos(x)` ✅, `atan(x)` ✅, `atan2(y, x)` ✅

- [x] Exponential (4 functions)
  - [x] `exp(x)` ✅, `ln(x)` ✅, `log10(x)` ✅, `log2(x)` ✅

- [x] Extra Functions (not in spec)
  - [x] `sinh(x)` ✅, `cosh(x)` ✅, `tanh(x)` ✅ (hyperbolic)
  - [x] `sign(x)` ✅, `deg(x)` ✅, `rad(x)` ✅, `cbrt(x)` ✅
  - [x] `pi()` ✅, `e()` ✅ (constants)
  - [x] `set_precision(n)` ✅, `log(x, base)` ✅

**Estimated Time**: 2 hours
**Files to Create/Modify**:
- `crates/achronyme-vm/src/builtins/math.rs` (new)
- `crates/achronyme-vm/src/builtins/mod.rs` (register math functions)

---

### Phase 4D: String Support ✅ (Priority: HIGH) - COMPLETE

- [x] String Literals
  - [x] Parser support for `"string"` ✅
  - [x] AST node `StringLiteral(String)` ✅
  - [x] Compiler support ✅
  - [x] VM support ✅

- [x] String Concatenation
  - [x] Add opcode handles strings ✅
  - [x] Support `"a" + "b"` syntax ✅

- [x] String Functions (14+ functions)
  - [x] `concat(s1, s2)` ✅, `split(str, delim)` ✅, `join(arr, delim)` ✅
  - [x] `upper(str)` ✅, `lower(str)` ✅
  - [x] `trim(str)` ✅, `trim_start(str)` ✅, `trim_end(str)` ✅
  - [x] `starts_with(str, prefix)` ✅, `ends_with(str, suffix)` ✅
  - [x] `replace(str, pattern, replacement)` ✅
  - [x] `contains(collection, value)` ✅
  - [x] `substring(str, start, end)` ✅
  - [x] `char_at(str, index)` ✅
  - [x] String indexing: `str[0]`, `str[-1]` ✅

**Estimated Time**: 2-3 hours
**Files to Create/Modify**:
- `crates/achronyme-parser/src/grammar.pest` (add string rule)
- `crates/achronyme-parser/src/ast.rs` (add StringLiteral)
- `crates/achronyme-vm/src/opcode.rs` (add NewString)
- `crates/achronyme-vm/src/builtins/strings.rs` (new)
- `crates/achronyme-vm/src/vm/execution/strings.rs` (new)
- `crates/achronyme-vm/src/vm/execution/arithmetic.rs` (modify Add)
- `crates/achronyme-vm/src/vm/execution/vectors.rs` (modify VecGet for strings)

---

### Phase 4E: Advanced Arrays ✅ (Priority: LOW) - COMPLETE

- [x] Array Functions (11+ functions)
  - [x] `reverse(array)` ✅, `product(array)` ✅
  - [x] `zip(arr1, arr2)` ✅, `flatten(array, depth?)` ✅
  - [x] `take(array, n)` ✅, `drop(array, n)` ✅
  - [x] `slice(array, start, end?)` ✅
  - [x] `unique(array)` ✅, `chunk(array, size)` ✅
  - [x] `sort(array)` ✅ (extra)

- [x] Vector Manipulation (extra)
  - [x] `push(vec, value)` ✅, `pop(vec)` ✅
  - [x] `insert(vec, index, value)` ✅, `remove(vec, index)` ✅
  - [x] `concat_vec(v1, v2)` ✅
  - [x] `first(vec)` ✅, `last(vec)` ✅, `is_empty(vec)` ✅

**Estimated Time**: 2 hours
**Files to Create/Modify**:
- `crates/achronyme-vm/src/builtins/arrays.rs` (extend)

---

### Phase 4F-L: Specialized Modules ⚠️ (Priority: LOW)

**Deferred to future phases**. These are specialized functions that:
- Require external crates (linalg, DSP, solver)
- Are special forms requiring AST access (numerical, optimization)
- Are domain-specific (graphs, PERT)

**Total Functions**: ~100 additional functions
**Total Time**: 30-40 hours of implementation

---

## Testing Strategy

### Test Organization

```
crates/achronyme-vm/src/tests/
├── mod.rs
├── phase4a_core.rs           # Tests for Phase 4A
├── phase4b_hof.rs             # Tests for HOFs
├── phase4c_math.rs            # Tests for math functions
├── phase4d_strings.rs         # Tests for strings
└── phase4e_advanced_arrays.rs # Tests for advanced arrays
```

### Test Coverage Requirements

Each function must have:
1. **Basic functionality test** - normal use case
2. **Edge case test** - empty inputs, boundary values
3. **Error case test** - wrong types, wrong argument count
4. **Integration test** - combined with other functions

**Example**:
```rust
// File: crates/achronyme-vm/src/tests/phase4a_core.rs

#[test]
fn test_print_single() {
    let result = execute("print(42)").unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn test_print_multiple() {
    let result = execute("print(1, 2, 3)").unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn test_print_empty_error() {
    let result = execute("print()");
    assert!(result.is_err());
}

#[test]
fn test_typeof_all_types() {
    assert_eq!(execute("typeof(42)").unwrap(), Value::String("Number".into()));
    assert_eq!(execute("typeof(true)").unwrap(), Value::String("Boolean".into()));
    assert_eq!(execute("typeof([1,2])").unwrap(), Value::String("Vector".into()));
    assert_eq!(execute("typeof({x:1})").unwrap(), Value::String("Record".into()));
}

#[test]
fn test_len_various_types() {
    assert_eq!(execute("len([1,2,3])").unwrap(), Value::Number(3.0));
    assert_eq!(execute("len({a:1,b:2})").unwrap(), Value::Number(2.0));
    assert_eq!(execute("len(\"\")").unwrap(), Value::Number(0.0));
}

#[test]
fn test_sum_empty() {
    assert_eq!(execute("sum([])").unwrap(), Value::Number(0.0));
}

#[test]
fn test_range_step_negative() {
    let result = execute("range(5, 0, -1)").unwrap();
    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 5);
            assert_eq!(vec[0], Value::Number(5.0));
            assert_eq!(vec[4], Value::Number(1.0));
        }
        _ => panic!("Expected Vector"),
    }
}

#[test]
fn test_integration_map_sum() {
    let result = execute("sum(map((x) => x * 2, [1, 2, 3]))").unwrap();
    assert_eq!(result, Value::Number(12.0));
}
```

---

## Performance Considerations

### Optimization Priorities

1. **HOFs** - Compiler transformation is faster than runtime interpretation
2. **Math functions** - Use SIMD when possible for vector operations
3. **String operations** - Minimize allocations, use string interning
4. **Array operations** - Avoid unnecessary clones, use slice operations

### Benchmarking

Create benchmarks for critical functions:

```rust
// File: crates/achronyme-vm/benches/builtins.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_map(c: &mut Criterion) {
    c.bench_function("map 1000 elements", |b| {
        b.iter(|| {
            execute(black_box("map((x) => x * 2, range(0, 1000))"))
        });
    });
}

fn bench_sum(c: &mut Criterion) {
    c.bench_function("sum 10000 elements", |b| {
        b.iter(|| {
            execute(black_box("sum(range(0, 10000))"))
        });
    });
}

criterion_group!(benches, bench_map, bench_sum);
criterion_main!(benches);
```

---

## Migration from Tree-Walker

Many functions already exist in the tree-walker evaluator. Migration strategy:

1. **Identify existing implementation** in `crates/achronyme-eval/src/function_modules/`
2. **Extract core logic** (usually pure Rust functions)
3. **Wrap in VM builtin interface**
4. **Add to builtin registry**
5. **Test compatibility** with existing Achronyme programs

**Example Migration**:
```rust
// Existing tree-walker (crates/achronyme-eval/src/function_modules/trig.rs)
pub fn sin_impl(x: f64) -> f64 {
    x.sin()
}

// New VM builtin (crates/achronyme-vm/src/builtins/math.rs)
pub fn builtin_sin(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    apply_unary_math(args, |x| x.sin(), "sin")
}
```

---

## Documentation Requirements

Each builtin function must be documented in:

1. **This reference file** - Complete specification
2. **Inline Rust docs** - For API documentation
3. **User-facing docs** - In `docs/builtins.md`
4. **Examples** - In `examples/` directory

---

## Progress Tracking

Use this checklist to track implementation progress:

### Phase 4A: Core Essentials ✅ COMPLETE
- [x] Set up builtin infrastructure ✅
- [x] Implement I/O functions (3) ✅
- [x] Implement array core (3) ✅
- [x] Implement record functions (3) ✅
- [x] Write tests (30+ test cases) ✅
- [x] Update documentation ✅

### Phase 4B: HOFs ✅ COMPLETE
- [x] Implement as native functions (not compiler transforms) ✅
- [x] Implement map ✅
- [x] Implement filter ✅
- [x] Implement reduce ✅
- [x] Implement pipe ✅
- [x] Implement predicates (5) ✅
- [x] Write tests (40+ test cases) ✅

### Phase 4C: Math ✅ COMPLETE
- [x] Implement basic math (9) ✅
- [x] Implement trigonometry (7) ✅
- [x] Implement exponential (4) ✅
- [x] Implement extras (hyperbolic, constants, etc.) ✅
- [x] Write tests (50+ test cases) ✅

### Phase 4D: Strings ✅ COMPLETE
- [x] Parser/AST support ✅
- [x] Compiler support ✅
- [x] VM opcode support ✅
- [x] String concatenation ✅
- [x] String functions (14+) ✅
- [x] Write tests (40+ test cases) ✅

### Phase 4E: Advanced Arrays ✅ COMPLETE
- [x] Advanced arrays (11) ✅
- [x] Vector manipulation functions (8 extra) ✅

### Phase 4F: Complex Numbers ✅ COMPLETE
- [x] Complex numbers (6) ✅
- [x] Enhanced with polar functions (4 extra) ✅

### Phase 4G: Linear Algebra ✅ COMPLETE
- [x] Linear algebra (7) ✅

### Phase 4H: DSP ✅ COMPLETE
- [x] DSP functions (11) ✅

### Phase 4I: Numerical Analysis ✅ COMPLETE (2025-01-21)
- [x] Differentiation (4) ✅
- [x] Integration (4) ✅
- [x] Root finding (3) ✅
- [x] Complex enhancements (4) ✅

### Phase 4J: Optimization ❌ NOT IMPLEMENTED
- [ ] Linear programming (5) ❌
- [ ] Solution analysis (4) ❌

### Phase 4K: Graph Theory ✅ COMPLETE (2025-01-21)
- [x] Network construction (5) ✅
- [x] Traversal (4) ✅
- [x] Shortest path (1) ✅
- [x] MST (2) ✅
- [x] Connectivity (3) ✅
- [x] Topological sort (1) ✅

### Phase 4L: PERT/CPM ✅ COMPLETE (2025-01-21)
- [x] CPM functions (6) ✅
- [x] PERT probabilistic (6) ✅
- [x] Comprehensive analysis (1) ✅

---

## Estimated Total Time & Current Status

| Phase | Priority | Functions | Est. Time | Actual Status | Implementation Date |
|-------|----------|-----------|-----------|---------------|---------------------|
| 4A: Core Essentials | CRITICAL | 9 | 2 hours | ✅ COMPLETE | Initial |
| 4B: HOFs | HIGH | 9 | 3-4 hours | ✅ COMPLETE | Initial |
| 4C: Math | MEDIUM | 20 | 2 hours | ✅ COMPLETE | Initial |
| 4D: Strings | HIGH | 14+ | 2-3 hours | ✅ COMPLETE | Initial |
| 4E: Advanced Arrays | LOW | 11 | 2 hours | ✅ COMPLETE | Initial |
| 4F: Complex | LOW | 6 | 1 hour | ✅ COMPLETE | Initial |
| 4G: Linear Algebra | LOW | 7 | 3-4 hours | ✅ COMPLETE | Initial |
| 4H: DSP | LOW | 11 | 4-5 hours | ✅ COMPLETE | Initial |
| 4I: Numerical | LOW | 15 | 6-8 hours | ✅ COMPLETE | 2025-01-21 |
| 4J: Optimization | LOW | 9 | 8-10 hours | ❌ NOT DONE | - |
| 4K: Graphs | LOW | 17 | 6-8 hours | ✅ COMPLETE | 2025-01-21 |
| 4L: PERT | LOW | 13 | 5-6 hours | ✅ COMPLETE | 2025-01-21 |

**Functions Implemented**: 132 of 141 (93.6%)
**Functions Remaining**: 9 (Phase 4J: Optimization only)
**Time Invested**: ~48-58 hours
**Time Remaining**: ~8-10 hours (Phase 4J only)

---

## Next Steps

### ✅ Completed (As of 2025-01-21)
- Phase 4A-4I: All core and specialized functions (except optimization)
- Phase 4K: Graph Theory - Complete graph algorithms suite
- Phase 4L: PERT/CPM - Complete project management functions

### ❌ Remaining Work

**Phase 4J: Optimization (9 functions)**
The only remaining phase requires implementing linear programming algorithms:

1. **Implement the `achronyme-solver` crate** with simplex algorithms
2. **Create VM bindings** in `crates/achronyme-vm/src/builtins/optimization.rs`
3. **Register functions** in the builtin registry
4. **Test with LP problems** (diet problem, transportation, production planning)

**Estimated Time**: 8-10 hours

### Why Phase 4J Was Deferred

1. **Low Priority**: Linear programming is a specialized domain
2. **External Dependencies**: Requires a separate solver crate
3. **Complexity**: Simplex algorithm and variants are non-trivial to implement
4. **Limited Use Cases**: Most Achronyme programs don't need LP solvers
5. **93% Complete**: The VM is fully functional without these 9 functions

**The VM is production-ready** with 132+ builtin functions covering all essential and most specialized domains.

---

*End of Phase 4 Built-in Functions Reference*
