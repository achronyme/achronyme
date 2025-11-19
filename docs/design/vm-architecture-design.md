# VM Architecture Design for Achronyme 0.6.5

## Executive Summary

This document presents a comprehensive architecture for replacing Achronyme's tree-walker interpreter with a bytecode virtual machine (VM). The VM will enable proper async/await support while maintaining all existing language features and improving performance.

**Key Recommendations:**
- **Architecture**: Register-based VM (Lua-style)
- **Instruction Dispatch**: Match-based dispatch with potential future optimization
- **Async Model**: Stackless coroutines compiled to state machines with suspension points
- **Memory Management**: Reference-counted heap objects with scope-based cleanup
- **Implementation Strategy**: Phased rollout with backward compatibility

The VM design supports all 50+ language features including generators, pattern matching, tail-call optimization, gradual typing, error handling, and module system.

---

## 1. Current Implementation Analysis

### 1.1 Language Features

**Core Syntax Constructs** (37 total):
1. Number literals (f64, IEEE 754 with Infinity/NaN)
2. Boolean literals (true/false)
3. String literals (double-quoted with escapes)
4. Interpolated strings (single-quoted with ${} expressions)
5. Complex number literals (3i, 2+3i)
6. Null literal
7. Vector/Array literals with spread operator
8. Record literals (objects) with mutable fields and spread
9. Edge literals (directed/undirected graph edges)
10. Range expressions (1..5, 1..=5 for inclusive)

**Operators** (22 operations):
11. Binary arithmetic: +, -, *, /, %, ^
12. Unary operators: -, !
13. Comparison: ==, !=, <, >, <=, >=
14. Logical: &&, || (short-circuit)
15. Compound assignment: +=, -=, *=, /=, %=, ^=

**Variables & Scoping**:
16. Let declarations (immutable)
17. Mut declarations (mutable with MutableRef wrapper)
18. Destructuring (record and vector patterns)
19. Pattern matching with guards
20. Shadowing support
21. Lexical scoping with push/pop

**Functions**:
22. Lambda expressions with closures
23. Typed parameters with gradual typing
24. Default parameter values
25. Optional parameters (x?)
26. Return type annotations
27. Recursive references (rec keyword)
28. Self-references (self keyword)
29. Tail-call optimization (TCO)
30. Higher-order functions

**Control Flow**:
31. If expressions (if-else)
32. While loops with break/continue
33. For-in loops (iterators, vectors, tensors, generators)
34. Match expressions (pattern matching)
35. Try-catch error handling
36. Throw statements
37. Do blocks (scoped expressions)

**Advanced Features**:
38. Generators (yield/generate)
39. Type aliases
40. Module system (import/export)
41. Gradual type system with union types
42. Field access (dot notation)
43. Index access (multidimensional)
44. Slicing with ranges
45. Piecewise functions
46. Sequence expressions (statement blocks)

**Meta Features**:
47. Comments (// line comments)
48. Newline-based statement separation
49. Semicolon separators
50. Type checking and inference

### 1.2 Type System

**Value Types** (16 runtime types):

```rust
pub enum Value {
    Number(f64),                    // IEEE 754 floating point
    Boolean(bool),                  // true/false
    Complex(Complex),               // re + im*i
    String(String),                 // UTF-8 strings
    Null,                          // Optional/nullable values

    // Collections
    Vector(Vec<Value>),            // Heterogeneous arrays
    Tensor(RealTensor),            // Optimized N-D real arrays
    ComplexTensor(ComplexTensor),  // Optimized N-D complex arrays
    Record(HashMap<String, Value>), // Key-value objects

    // Functions
    Function(Function),            // Closures and builtins

    // Graph/Network
    Edge { from, to, directed, properties },

    // Advanced
    Generator(Rc<RefCell<GeneratorState>>), // Suspended functions
    Error { message, kind, source },        // Error values
    MutableRef(Rc<RefCell<Value>>),        // Shared mutable refs

    // Internal (control flow markers - never exposed to users)
    TailCall(Vec<Value>),          // TCO marker
    EarlyReturn(Box<Value>),       // Return statement
    GeneratorYield(Box<Value>),    // Yield marker
    LoopBreak(Option<Box<Value>>), // Break statement
    LoopContinue,                  // Continue statement
}
```

**Type Annotations** (Gradual Typing):
- Simple types: Number, Boolean, String, Complex, Edge, Generator, Function, Error, Vector
- Tensor types: Tensor<Number>, Tensor<Complex, [2,3]>
- Record types: {name: String, age: Number, mut value?: Number}
- Function types: (Number, String): Boolean
- Union types: Number | String | null
- Optional shorthand: String? (equivalent to String | null)
- Type references (aliases)
- Any type (opt-out of checking)

### 1.3 Current Evaluator Architecture

**Tree-Walker Pattern**:
- **Dispatcher**: Single recursive `evaluate(&AstNode)` method
- **Post-order traversal**: Children evaluated before parents
- **Call stack**: Uses Rust's native call stack for evaluation
- **Environment**: Scope-based HashMap with push/pop
- **Closures**: Rc<RefCell<Environment>> for O(1) capture

**Execution Flow**:
```
parse(source) → Vec<AstNode> → evaluate(node) → Value
                                      ↓
                              Match on AstNode variant
                                      ↓
                              Dispatch to handler
                                      ↓
                              Recursively eval children
                                      ↓
                              Combine results → Value
```

**Module Organization**:
- `evaluator/mod.rs`: Core Evaluator struct
- `evaluator/dispatcher.rs`: Main evaluation loop
- `evaluator/lambda_eval.rs`: Function application
- `evaluator/state.rs`: Environment management
- `handlers/*`: Specialized handlers for each construct
- `function_modules/*`: 200+ built-in functions
- `tco/mod.rs`: Tail-call optimization analysis

**Environment Model**:
- Stack of scopes (Vec<HashMap<String, Value>>)
- Variable shadowing supported
- Closure capture via Rc<RefCell<Environment>>
- Mutable variables wrapped in Rc<RefCell<Value>>

**Function Application**:
- TCO detection: Analyzes AST for tail-recursive patterns
- TCO execution: Iterative loop replacing recursion
- Regular execution: Environment swap + evaluate body
- Parameter handling: Type checking, defaults, destructuring

### 1.4 Async/Await Challenges with Tree-Walker

**Problem 1: No Suspension Points**
- Tree-walker uses Rust's call stack directly
- Cannot suspend mid-evaluation and resume later
- Generators work by re-executing from start and counting yields (inefficient)
- True async/await requires saving evaluation state

**Problem 2: Stack Overflow Risk**
- Deep recursion exhausts stack (even with TCO)
- Async chains would compound this problem
- No way to "yield" control back to event loop

**Problem 3: Future Incompatibility**
- Rust's async/await uses state machines
- Tree-walker doesn't generate state machines
- Cannot integrate with Tokio or other runtimes
- No way to compose async operations

**Problem 4: Generator Inefficiency**
- Current generators re-execute entire function body on each .next()
- Yield counting is O(n) where n = yield count
- State management is fragile for nested control flow
- Cannot efficiently implement async iterators

**Problem 5: Performance**
- Every operation requires function call overhead
- No instruction-level optimization possible
- Match dispatch on 47 AstNode variants per operation
- Cannot apply standard VM optimizations

**Why VM Solves These**:
- **Suspension**: Bytecode + instruction pointer = natural suspension point
- **Stack Control**: Explicit call frames on heap, not Rust stack
- **State Machines**: Each async function compiles to bytecode with suspension opcodes
- **Performance**: Flatter dispatch, better cache locality, optimization opportunities

---

## 2. VM Research Findings

### 2.1 Stack vs Register Based

**Recommendation: Register-Based VM (Lua 5.1 style)**

**Research Evidence**:
- Register-based VMs show 20-47% fewer executed instructions than stack-based
- Performance improvement of 32-40% for non-JIT interpreted code
- Better CPU cache utilization with explicit register addressing
- Lua 5.1 proven architecture for dynamic languages

**Trade-offs Analysis**:

| Aspect | Stack-Based | Register-Based | Winner |
|--------|-------------|----------------|---------|
| Compiler Complexity | Simple | Moderate | Stack |
| Code Density | Excellent | Good | Stack |
| Instruction Count | High | Low | Register |
| Runtime Performance | Slower | Faster | Register |
| Cache Locality | Poor | Good | Register |
| Async Integration | Hard | Easier | Register |

**For Achronyme**: Register-based wins because:
1. We already have a parser (compiler complexity less critical)
2. Performance is important for scientific computing
3. Async/await requires explicit state - registers model this naturally
4. Functions allocate fixed register windows (max 256 registers per frame)

### 2.2 Instruction Dispatch

**Recommendation: Match-based Dispatch (with future optimization path)**

**Approaches Evaluated**:

1. **Switch/Match Dispatch** (CHOSEN)
   - Simple: `loop { match fetch_opcode() { ... } }`
   - Portable: Works on all platforms
   - Performance: Modern branch prediction makes overhead minimal
   - Rust-friendly: No unsafe code required
   - Future-proof: Can migrate to other methods later

2. **Computed Goto** (Future consideration)
   - Fastest: Direct jump table
   - Non-portable: Requires inline assembly + nightly Rust
   - Fragile: LLVM doesn't understand control flow
   - Benefit: 10-30% faster dispatch in micro-benchmarks

3. **Threaded Code** (Not recommended)
   - Complex: Function pointer arrays
   - Overhead: Indirect calls 2-3x slower than match
   - No real benefit over match in modern CPUs

**Implementation Strategy**:
```rust
pub fn run(&mut self) -> Result<Value, VmError> {
    loop {
        let opcode = self.fetch_opcode();
        match opcode {
            OpCode::LoadConst(dst, idx) => { /* ... */ }
            OpCode::Move(dst, src) => { /* ... */ }
            OpCode::Call(result, func, argc) => { /* ... */ }
            // ... ~80 opcodes
            OpCode::Return => break,
            OpCode::Yield(reg) => return Ok(self.suspend(reg)),
        }
        self.ip += 1;
    }
}
```

### 2.3 Async Integration

**Recommendation: Stackless Coroutines + Suspension Points**

**Rust Async Model** (for reference):
- Futures compile to state machines
- `.await` points become suspension/resume points
- Runtime (Tokio) handles scheduling
- Stack per task, not per operation

**Achronyme VM Async Model**:
1. **Compilation**: `async` functions → bytecode with SUSPEND opcodes
2. **Execution**: VM maintains explicit call frames on heap
3. **Suspension**: SUSPEND opcode saves IP + registers → Future
4. **Resumption**: Future polled → restore frame + continue from IP
5. **Integration**: VM Future implements Rust's Future trait

**Key Opcodes for Async**:
```
SUSPEND <reg>        # Save state, yield Value::Pending(reg)
RESUME               # Called when Future polled again
AWAIT <dst> <future> # Suspend until future completes
SPAWN <async_fn>     # Create new task
```

**Advantages**:
- No Rust stack used during suspension
- Natural integration with Tokio/async-std
- Generators become lightweight (just bytecode + state)
- Can implement async/await syntax later

### 2.4 Recommended Crates

**Core VM**:
- **No external VM crate** - implement from scratch for control
- `byteorder` or `zerocopy`: Binary bytecode encoding
- `hashbrown`: Fast HashMap for environments (already in std)

**Memory Management**:
- `std::rc::Rc` + `std::cell::RefCell`: Reference counting (current approach)
- Consider `bumpalo` for arena allocation of constants

**Async Runtime** (future):
- `tokio`: Industry standard async runtime
- `futures`: Core Future traits
- `async-trait`: Async methods in traits

**Performance**:
- `criterion`: Benchmarking
- `flamegraph`: Profiling
- `miri`: Detect undefined behavior

**Development**:
- `bincode` or `postcard`: Bytecode serialization for caching
- `bytemuck`: Safe transmutation for bytecode reading

---

## 3. Proposed VM Architecture

### 3.1 Complete Instruction Set

**Design Philosophy**:
- 32-bit instructions: 8-bit opcode + 24 bits for operands
- Register-based with up to 256 registers per function
- Separate stack for call frames
- Immediate values in constant pool

**Opcode Format**:
```
┌─────────┬──────────┬──────────┬──────────┐
│  OpCode │   RegA   │   RegB   │   RegC   │
│  8 bits │  8 bits  │  8 bits  │  8 bits  │
└─────────┴──────────┴──────────┴──────────┘

Or for immediate values:
┌─────────┬──────────┬──────────────────────┐
│  OpCode │   RegA   │    Immediate16       │
│  8 bits │  8 bits  │      16 bits         │
└─────────┴──────────┴──────────────────────┘
```

**Complete Opcode Table**:

| Opcode | Operands | Description | Stack Effect |
|--------|----------|-------------|--------------|
| **Constants & Moves** ||||
| LOAD_CONST | dst, idx | R[dst] = constants[idx] | - |
| LOAD_NULL | dst | R[dst] = Null | - |
| LOAD_TRUE | dst | R[dst] = true | - |
| LOAD_FALSE | dst | R[dst] = false | - |
| LOAD_IMM_I8 | dst, val | R[dst] = Number(val as f64) | - |
| MOVE | dst, src | R[dst] = R[src] | - |
| **Arithmetic** ||||
| ADD | dst, a, b | R[dst] = R[a] + R[b] | - |
| SUB | dst, a, b | R[dst] = R[a] - R[b] | - |
| MUL | dst, a, b | R[dst] = R[a] * R[b] | - |
| DIV | dst, a, b | R[dst] = R[a] / R[b] | - |
| MOD | dst, a, b | R[dst] = R[a] % R[b] | - |
| POW | dst, a, b | R[dst] = R[a] ^ R[b] | - |
| NEG | dst, src | R[dst] = -R[src] | - |
| **Comparison** ||||
| EQ | dst, a, b | R[dst] = R[a] == R[b] | - |
| NE | dst, a, b | R[dst] = R[a] != R[b] | - |
| LT | dst, a, b | R[dst] = R[a] < R[b] | - |
| LE | dst, a, b | R[dst] = R[a] <= R[b] | - |
| GT | dst, a, b | R[dst] = R[a] > R[b] | - |
| GE | dst, a, b | R[dst] = R[a] >= R[b] | - |
| **Logical** ||||
| NOT | dst, src | R[dst] = !R[src] | - |
| AND | dst, a, b | R[dst] = R[a] && R[b] (short-circuit) | - |
| OR | dst, a, b | R[dst] = R[a] \|\| R[b] (short-circuit) | - |
| **Jump/Branch** ||||
| JUMP | offset | ip += offset | - |
| JUMP_IF_TRUE | cond, offset | if R[cond] then ip += offset | - |
| JUMP_IF_FALSE | cond, offset | if !R[cond] then ip += offset | - |
| JUMP_IF_NULL | reg, offset | if R[reg] == Null then ip += offset | - |
| **Functions** ||||
| CLOSURE | dst, func_idx | R[dst] = create closure from proto[func_idx] | - |
| CALL | dst, func, argc | R[dst] = call R[func](R[func+1]...R[func+argc]) | Push frame |
| CALL_METHOD | dst, obj, meth, argc | R[dst] = R[obj].method(R[obj+1]...) with self | Push frame |
| TAIL_CALL | func, argc | Tail call R[func](R[func+1]...R[func+argc]) | Replace frame |
| RETURN | src | Return R[src] from function | Pop frame |
| RETURN_NULL | - | Return Null from function | Pop frame |
| **Records** ||||
| NEW_RECORD | dst, size | R[dst] = {} (empty record) | - |
| GET_FIELD | dst, obj, field_idx | R[dst] = R[obj][constants[field_idx]] | - |
| SET_FIELD | obj, field_idx, val | R[obj][constants[field_idx]] = R[val] | - |
| SET_FIELD_MUT | obj, field_idx, val | Set mutable field | - |
| RECORD_SPREAD | dst, src | Spread R[src] into R[dst] | - |
| **Vectors/Arrays** ||||
| NEW_VECTOR | dst, size | R[dst] = [] (empty vector) | - |
| VEC_PUSH | vec, val | R[vec].push(R[val]) | - |
| VEC_GET | dst, vec, idx | R[dst] = R[vec][R[idx]] | - |
| VEC_SET | vec, idx, val | R[vec][R[idx]] = R[val] | - |
| VEC_SPREAD | dst, src | Spread R[src] elements into R[dst] | - |
| VEC_SLICE | dst, vec, start, end | R[dst] = R[vec][R[start]..R[end]] | - |
| **Tensors** ||||
| NEW_TENSOR | dst, rank, ... | Create tensor from dimensions | - |
| TENSOR_GET | dst, tensor, indices | Multidimensional indexing | - |
| TENSOR_SET | tensor, indices, val | Multidimensional assignment | - |
| TENSOR_SLICE | dst, tensor, ranges | Multidimensional slicing | - |
| **Variables** ||||
| GET_GLOBAL | dst, name_idx | R[dst] = globals[constants[name_idx]] | - |
| SET_GLOBAL | name_idx, src | globals[constants[name_idx]] = R[src] | - |
| GET_UPVALUE | dst, idx | R[dst] = upvalues[idx] | - |
| SET_UPVALUE | idx, src | upvalues[idx] = R[src] | - |
| GET_LOCAL | dst, idx | R[dst] = locals[idx] | - |
| SET_LOCAL | idx, src | locals[idx] = R[src] | - |
| MAKE_MUT_REF | dst, src | R[dst] = MutableRef(R[src]) | - |
| DEREF | dst, src | R[dst] = *R[src] (dereference mutable) | - |
| **Pattern Matching** ||||
| MATCH_TYPE | dst, val, type_idx | R[dst] = check_type(R[val], type_idx) | - |
| MATCH_LIT | dst, val, lit_idx | R[dst] = (R[val] == constants[lit_idx]) | - |
| DESTRUCTURE_REC | base_reg, obj, pattern_idx | Destructure record to registers | - |
| DESTRUCTURE_VEC | base_reg, vec, pattern_idx | Destructure vector to registers | - |
| **Generators** ||||
| CREATE_GEN | dst, func_idx | R[dst] = Generator(proto[func_idx]) | - |
| YIELD | val | Suspend generator, return R[val] | - |
| RESUME_GEN | dst, gen | R[dst] = R[gen].next() | - |
| **Error Handling** ||||
| THROW | val | Throw error R[val] | Unwind |
| PUSH_HANDLER | catch_offset | Push exception handler at offset | - |
| POP_HANDLER | - | Pop exception handler | - |
| MAKE_ERROR | dst, msg, kind | R[dst] = Error{msg: R[msg], kind: R[kind]} | - |
| **Control Flow** ||||
| BREAK | val_reg | Break from loop with optional value | - |
| CONTINUE | - | Continue to next loop iteration | - |
| **Complex Numbers** ||||
| NEW_COMPLEX | dst, re, im | R[dst] = Complex(R[re], R[im]) | - |
| COMPLEX_RE | dst, src | R[dst] = R[src].re | - |
| COMPLEX_IM | dst, src | R[dst] = R[src].im | - |
| **Edges** ||||
| NEW_EDGE | dst, from, to, dir | R[dst] = Edge{from, to, directed} | - |
| EDGE_SET_PROP | edge, key, val | R[edge].props[key] = R[val] | - |
| **Ranges** ||||
| RANGE_EX | dst, start, end | R[dst] = [R[start]..R[end]) (exclusive) | - |
| RANGE_IN | dst, start, end | R[dst] = [R[start]..=R[end]] (inclusive) | - |
| **Built-in Functions** ||||
| CALL_BUILTIN | dst, func_idx, argc | Call built-in function | - |
| **Type Operations** ||||
| TYPE_CHECK | dst, val, type_idx | Check type annotation | - |
| TYPE_ASSERT | val, type_idx | Assert type or throw | - |
| **String Operations** ||||
| STR_CONCAT | dst, a, b | R[dst] = R[a] + R[b] (string concat) | - |
| STR_INTERP | dst, parts... | Interpolate string from parts | - |
| **Debugging** ||||
| DEBUG_PRINT | src | Print R[src] for debugging | - |
| BREAKPOINT | - | Debugger breakpoint | - |
| **NOP** ||||
| NOP | - | No operation | - |

**Total Opcodes**: ~80 (fits in 8 bits with room for 176 more)

### 3.2 VM Components

**High-Level Architecture**:

```
┌─────────────────────────────────────────────────┐
│                   VM Instance                    │
├─────────────────────────────────────────────────┤
│  - Instruction Pointer (IP)                      │
│  - Current Frame Pointer (FP)                    │
│  - Call Stack (Vec<CallFrame>)                   │
│  - Register Window (256 registers)               │
│  - Global Environment (HashMap)                  │
│  - Constant Pool                                 │
│  - Function Prototypes                           │
│  - Exception Handlers Stack                      │
│  - Module Registry                               │
└─────────────────────────────────────────────────┘
```

**Detailed Component Design**:

#### Call Frame Structure
```rust
pub struct CallFrame {
    /// Return address (instruction pointer)
    return_ip: usize,

    /// Base register for this frame (sliding window)
    reg_base: u8,

    /// Number of registers used by this function
    reg_count: u8,

    /// Function being executed
    function: FunctionPrototype,

    /// Captured upvalues (for closures)
    upvalues: Vec<Rc<RefCell<Value>>>,

    /// Previous frame pointer
    prev_fp: Option<usize>,

    /// Is this a generator frame? (for suspension)
    is_generator: bool,

    /// Exception handler chain for this frame
    exception_handlers: Vec<ExceptionHandler>,
}
```

#### Register Window
```rust
pub struct RegisterWindow {
    /// Maximum 256 registers total (8-bit addressing)
    registers: [Value; 256],

    /// Current base offset (for sliding window)
    base: u8,

    /// Registers in use for current frame
    count: u8,
}

impl RegisterWindow {
    #[inline]
    pub fn get(&self, idx: u8) -> &Value {
        &self.registers[(self.base + idx) as usize]
    }

    #[inline]
    pub fn set(&mut self, idx: u8, value: Value) {
        self.registers[(self.base + idx) as usize] = value;
    }

    // Advance window for new call frame
    pub fn push_frame(&mut self, reg_count: u8) {
        self.base += self.count;
        self.count = reg_count;
    }

    pub fn pop_frame(&mut self, prev_base: u8, prev_count: u8) {
        self.base = prev_base;
        self.count = prev_count;
    }
}
```

#### Constant Pool
```rust
pub struct ConstantPool {
    /// Compile-time constants
    constants: Vec<Value>,

    /// String interning for field names, identifiers
    strings: Vec<String>,

    /// Type annotations
    types: Vec<TypeAnnotation>,

    /// Pattern descriptors
    patterns: Vec<Pattern>,
}
```

#### Function Prototype
```rust
pub struct FunctionPrototype {
    /// Function name (for debugging)
    name: String,

    /// Number of parameters
    param_count: u8,

    /// Number of registers needed
    register_count: u8,

    /// Bytecode instructions
    code: Vec<u32>,

    /// Parameter type annotations
    param_types: Vec<Option<TypeAnnotation>>,

    /// Default parameter values (as bytecode)
    param_defaults: Vec<Option<Vec<u32>>>,

    /// Return type annotation
    return_type: Option<TypeAnnotation>,

    /// Upvalue descriptors (for closures)
    upvalues: Vec<UpvalueDescriptor>,

    /// Child function prototypes (nested functions)
    functions: Vec<FunctionPrototype>,

    /// Constant pool (shared with children)
    constants: Rc<ConstantPool>,

    /// Debug information
    debug_info: Option<DebugInfo>,
}
```

#### Upvalue Handling (for Closures)
```rust
pub struct UpvalueDescriptor {
    /// Is this upvalue from immediate parent or further up?
    depth: u8,

    /// Register index in parent frame
    register: u8,

    /// Is this upvalue mutable?
    is_mutable: bool,
}

pub struct UpvalueStorage {
    /// Captured values (shared with all closures)
    values: Vec<Rc<RefCell<Value>>>,
}
```

#### Exception Handler
```rust
pub struct ExceptionHandler {
    /// Instruction pointer to jump to on exception
    catch_ip: usize,

    /// Register to store error value
    error_reg: u8,

    /// Stack depth when handler was pushed
    stack_depth: usize,
}
```

#### VM State Machine
```rust
pub struct VM {
    /// Current instruction pointer
    ip: usize,

    /// Call stack
    frames: Vec<CallFrame>,

    /// Current frame index
    fp: usize,

    /// Register window
    registers: RegisterWindow,

    /// Global variables
    globals: HashMap<String, Value>,

    /// Constant pools (one per module)
    constants: Vec<Rc<ConstantPool>>,

    /// Function prototypes
    functions: Vec<FunctionPrototype>,

    /// Module registry
    modules: ModuleRegistry,

    /// Exception handler stack
    exception_handlers: Vec<ExceptionHandler>,

    /// Generator states (suspended frames)
    generators: HashMap<GeneratorId, SuspendedFrame>,

    /// Type registry
    type_registry: HashMap<String, TypeAnnotation>,
}
```

#### Generator Suspension
```rust
pub struct SuspendedFrame {
    /// Saved call frame
    frame: CallFrame,

    /// Saved IP
    ip: usize,

    /// Saved register state
    registers: Vec<Value>,

    /// Is exhausted?
    done: bool,

    /// Return value (sticky)
    return_value: Option<Value>,
}
```

### 3.3 Bytecode Format

**Binary Encoding**:

```
┌──────────────────────────────────────┐
│         Module Header                 │
├──────────────────────────────────────┤
│  Magic: 0x41 43 48 52 ("ACHR")       │
│  Version: u16 (0x0065 = 0.6.5)       │
│  Flags: u16                           │
├──────────────────────────────────────┤
│         Constant Pool                 │
├──────────────────────────────────────┤
│  Count: u32                           │
│  [Value entries...]                   │
├──────────────────────────────────────┤
│         String Pool                   │
├──────────────────────────────────────┤
│  Count: u32                           │
│  [String entries...]                  │
├──────────────────────────────────────┤
│         Type Pool                     │
├──────────────────────────────────────┤
│  Count: u32                           │
│  [TypeAnnotation entries...]          │
├──────────────────────────────────────┤
│         Function Prototypes           │
├──────────────────────────────────────┤
│  Count: u32                           │
│  [Function entries...]                │
├──────────────────────────────────────┤
│         Debug Information             │
├──────────────────────────────────────┤
│  [Line number table...]               │
│  [Source map...]                      │
└──────────────────────────────────────┘
```

**Function Encoding**:
```
┌──────────────────────────────────────┐
│  Name: String index (u32)            │
│  Param count: u8                     │
│  Register count: u8                  │
│  Upvalue count: u8                   │
│  Flags: u8 (is_generator, etc.)      │
├──────────────────────────────────────┤
│  Code size: u32                      │
│  [Instructions...] (u32 each)        │
├──────────────────────────────────────┤
│  Upvalue descriptors                 │
│  [depth: u8, reg: u8, mut: u8]...    │
├──────────────────────────────────────┤
│  Nested functions                    │
│  Count: u32                          │
│  [Function indices...]               │
└──────────────────────────────────────┘
```

**Value Encoding** (in constant pool):
```
Tag (u8) + Data:
  0x00: Null
  0x01: Boolean (u8)
  0x02: Number (f64 LE)
  0x03: String (u32 string_pool_index)
  0x04: Complex (f64 re, f64 im)
  0x10: Vector (u32 count, [Value entries])
  0x11: Tensor (u8 rank, [u32 dims], [f64 data])
  0x12: ComplexTensor (u8 rank, [u32 dims], [Complex data])
  0x20: Record (u32 count, [(String key, Value val)])
  0x30: Edge (String from, String to, bool directed)
```

### 3.4 Compiler Pipeline (AST → Bytecode)

**High-Level Flow**:
```
Source → Parser → AST → Compiler → Bytecode → VM
                           ↓
                     [Type Checker]
                           ↓
                    [Optimizer]
```

**Compiler Phases**:

#### Phase 1: AST Analysis
```rust
pub struct Compiler {
    /// Function being compiled
    current_function: FunctionPrototype,

    /// Register allocator
    registers: RegisterAllocator,

    /// Symbol table (variable → register mapping)
    symbols: SymbolTable,

    /// Loop context stack (for break/continue)
    loops: Vec<LoopContext>,

    /// Exception handler context
    exception_handlers: Vec<ExceptionContext>,

    /// Constant pool builder
    constants: ConstantPoolBuilder,

    /// Parent compiler (for nested functions)
    parent: Option<Box<Compiler>>,
}
```

#### Phase 2: Register Allocation
```rust
pub struct RegisterAllocator {
    /// Next available register
    next_free: u8,

    /// Maximum registers used (for function metadata)
    max_used: u8,

    /// Free list for reused registers
    free_list: Vec<u8>,
}

impl RegisterAllocator {
    pub fn allocate(&mut self) -> Result<u8, CompileError> {
        if let Some(reg) = self.free_list.pop() {
            Ok(reg)
        } else if self.next_free < 256 {
            let reg = self.next_free;
            self.next_free += 1;
            self.max_used = self.max_used.max(self.next_free);
            Ok(reg)
        } else {
            Err(CompileError::TooManyRegisters)
        }
    }

    pub fn free(&mut self, reg: u8) {
        self.free_list.push(reg);
    }
}
```

#### Phase 3: Code Generation

**Expression Compilation** (returns register holding result):
```rust
impl Compiler {
    fn compile_expr(&mut self, node: &AstNode) -> Result<u8, CompileError> {
        match node {
            AstNode::Number(n) => {
                let reg = self.registers.allocate()?;
                let const_idx = self.constants.add_number(*n);
                self.emit(OpCode::LOAD_CONST, &[reg, const_idx as u8]);
                Ok(reg)
            }

            AstNode::BinaryOp { op, left, right } => {
                let left_reg = self.compile_expr(left)?;
                let right_reg = self.compile_expr(right)?;
                let result_reg = self.registers.allocate()?;

                let opcode = match op {
                    BinaryOp::Add => OpCode::ADD,
                    BinaryOp::Subtract => OpCode::SUB,
                    // ... other ops
                };

                self.emit(opcode, &[result_reg, left_reg, right_reg]);

                // Free temporary registers
                self.registers.free(left_reg);
                self.registers.free(right_reg);

                Ok(result_reg)
            }

            AstNode::If { condition, then_expr, else_expr } => {
                // Compile condition
                let cond_reg = self.compile_expr(condition)?;

                // Jump to else if false
                let else_jump = self.emit_jump(OpCode::JUMP_IF_FALSE, cond_reg);
                self.registers.free(cond_reg);

                // Compile then branch
                let then_reg = self.compile_expr(then_expr)?;
                let result_reg = self.registers.allocate()?;
                self.emit(OpCode::MOVE, &[result_reg, then_reg]);
                self.registers.free(then_reg);

                // Jump over else
                let end_jump = self.emit_jump(OpCode::JUMP, 0);

                // Patch else jump
                self.patch_jump(else_jump);

                // Compile else branch
                let else_reg = self.compile_expr(else_expr)?;
                self.emit(OpCode::MOVE, &[result_reg, else_reg]);
                self.registers.free(else_reg);

                // Patch end jump
                self.patch_jump(end_jump);

                Ok(result_reg)
            }

            // ... other expressions
        }
    }
}
```

**Statement Compilation**:
```rust
fn compile_stmt(&mut self, node: &AstNode) -> Result<(), CompileError> {
    match node {
        AstNode::VariableDecl { name, initializer, .. } => {
            let value_reg = self.compile_expr(initializer)?;
            let var_reg = self.registers.allocate()?;
            self.emit(OpCode::MOVE, &[var_reg, value_reg]);
            self.registers.free(value_reg);
            self.symbols.define(name.clone(), var_reg)?;
            Ok(())
        }

        AstNode::Assignment { target, value } => {
            let value_reg = self.compile_expr(value)?;

            match target.as_ref() {
                AstNode::VariableRef(name) => {
                    let var_reg = self.symbols.get(name)?;
                    self.emit(OpCode::MOVE, &[var_reg, value_reg]);
                }
                AstNode::FieldAccess { record, field } => {
                    let obj_reg = self.compile_expr(record)?;
                    let field_idx = self.constants.add_string(field.clone());
                    self.emit(OpCode::SET_FIELD, &[obj_reg, field_idx as u8, value_reg]);
                    self.registers.free(obj_reg);
                }
                // ... other assignment targets
            }

            self.registers.free(value_reg);
            Ok(())
        }

        // ... other statements
    }
}
```

#### Phase 4: Closure Compilation

**Upvalue Resolution**:
```rust
fn resolve_upvalue(&mut self, name: &str, depth: usize) -> Result<u8, CompileError> {
    // Check parent scope
    if let Some(parent) = &mut self.parent {
        // Try to find in parent
        if let Ok(parent_reg) = parent.symbols.get(name) {
            // Found in immediate parent - create upvalue
            let upvalue_idx = self.current_function.upvalues.len() as u8;
            self.current_function.upvalues.push(UpvalueDescriptor {
                depth: 0,
                register: parent_reg,
                is_mutable: parent.symbols.is_mutable(name),
            });
            return Ok(upvalue_idx);
        } else {
            // Not in immediate parent - recurse
            let parent_upvalue = parent.resolve_upvalue(name, depth + 1)?;
            let upvalue_idx = self.current_function.upvalues.len() as u8;
            self.current_function.upvalues.push(UpvalueDescriptor {
                depth: (depth + 1) as u8,
                register: parent_upvalue,
                is_mutable: parent.symbols.is_mutable(name),
            });
            return Ok(upvalue_idx);
        }
    }

    Err(CompileError::UndefinedVariable(name.to_string()))
}
```

#### Phase 5: Optimization Passes (Future)

**Potential Optimizations**:
1. **Constant folding**: `2 + 3` → `LOAD_CONST 5`
2. **Dead code elimination**: Remove unreachable code
3. **Register coalescing**: Reuse registers more aggressively
4. **Tail call detection**: Convert eligible calls to TAIL_CALL
5. **Inline small functions**: Replace CALL with inlined bytecode
6. **Peephole optimization**: Pattern-based local improvements

### 3.5 Async/Await Implementation

**Design Strategy**: Generators are the foundation for async/await.

**Generator Compilation**:
```rust
fn compile_generate_block(&mut self, stmts: &[AstNode]) -> Result<u8, CompileError> {
    // Create nested function for generator body
    let gen_func = self.compile_generator_function(stmts)?;
    let func_idx = self.functions.len();
    self.functions.push(gen_func);

    // Create generator value
    let result_reg = self.registers.allocate()?;
    self.emit(OpCode::CREATE_GEN, &[result_reg, func_idx as u8]);

    Ok(result_reg)
}

fn compile_generator_function(&mut self, stmts: &[AstNode]) -> Result<FunctionPrototype, CompileError> {
    let mut gen_compiler = Compiler::new_child(self);
    gen_compiler.current_function.is_generator = true;

    for stmt in stmts {
        gen_compiler.compile_stmt(stmt)?;
    }

    // Implicit return null at end
    gen_compiler.emit(OpCode::RETURN_NULL, &[]);

    Ok(gen_compiler.current_function)
}
```

**Yield Compilation**:
```rust
fn compile_yield(&mut self, value: &AstNode) -> Result<u8, CompileError> {
    if !self.current_function.is_generator {
        return Err(CompileError::YieldOutsideGenerator);
    }

    let value_reg = self.compile_expr(value)?;
    self.emit(OpCode::YIELD, &[value_reg]);
    self.registers.free(value_reg);

    // Yield doesn't return a value in current model
    // (returns unit/null)
    let result_reg = self.registers.allocate()?;
    self.emit(OpCode::LOAD_NULL, &[result_reg]);
    Ok(result_reg)
}
```

**Generator Execution**:
```rust
impl VM {
    fn execute_yield(&mut self, value_reg: u8) -> Result<ExecutionResult, VmError> {
        let value = self.registers.get(value_reg).clone();

        // Suspend current frame
        let suspended = SuspendedFrame {
            frame: self.frames[self.fp].clone(),
            ip: self.ip,
            registers: self.capture_registers(),
            done: false,
            return_value: None,
        };

        let gen_id = self.allocate_generator_id();
        self.generators.insert(gen_id, suspended);

        // Return iterator result {value, done: false}
        let result = self.make_iterator_result(value, false);
        Ok(ExecutionResult::Yielded(result))
    }

    fn resume_generator(&mut self, gen_id: GeneratorId) -> Result<Value, VmError> {
        let mut suspended = self.generators.remove(&gen_id)
            .ok_or(VmError::InvalidGenerator)?;

        if suspended.done {
            // Return sticky value
            return Ok(self.make_iterator_result(
                suspended.return_value.unwrap_or(Value::Null),
                true
            ));
        }

        // Restore frame
        self.frames.push(suspended.frame.clone());
        self.fp = self.frames.len() - 1;
        self.ip = suspended.ip + 1; // Continue after YIELD
        self.restore_registers(&suspended.registers);

        // Execute until next yield or return
        match self.run_until_suspend()? {
            ExecutionResult::Yielded(value) => {
                // Save updated state
                self.generators.insert(gen_id, suspended);
                Ok(value)
            }
            ExecutionResult::Returned(value) => {
                // Generator completed
                suspended.done = true;
                suspended.return_value = Some(value.clone());
                self.generators.insert(gen_id, suspended);
                Ok(self.make_iterator_result(value, true))
            }
        }
    }
}
```

**Future Async/Await Syntax** (phase 2):
```
async fn fetchData(url: String): Result {
    let response = await fetch(url)
    let data = await response.json()
    return data
}

// Compiles to:
CLOSURE dst, func_idx
  # func_idx points to:
  # CREATE_GEN ...
  # YIELD (suspension points at await)
```

**Integration with Rust async**:
```rust
// VM can be wrapped in a Future
impl Future for VmExecution {
    type Output = Result<Value, VmError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.vm.run_until_suspend() {
            Ok(ExecutionResult::Yielded(_)) => {
                // Register waker for when generator is resumed
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(ExecutionResult::Returned(value)) => Poll::Ready(Ok(value)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
```

---

## 4. Implementation Roadmap

### Phase 1: Core VM Infrastructure (Weeks 1-3)

**Goal**: Establish VM foundations and basic execution.

**Deliverables**:
1. **VM Data Structures** (Week 1)
   - `CallFrame` struct
   - `RegisterWindow` implementation
   - `ConstantPool` builder
   - `FunctionPrototype` structure
   - Basic opcode enum

2. **Minimal Compiler** (Week 1-2)
   - AST → Bytecode for literals
   - Arithmetic operations
   - Variable declarations (let)
   - Basic expressions

3. **VM Execution Loop** (Week 2-3)
   - Instruction dispatch (match-based)
   - Register operations
   - Arithmetic opcodes
   - Load/store constant pool

**Testing Strategy**:
- Unit tests for each opcode
- Integration tests: `2 + 3`, `let x = 5; x * 2`
- Benchmark against tree-walker for simple expressions

**Dependencies**: None (greenfield)

**Estimated Effort**: 3 weeks (1 senior engineer)

---

### Phase 2: Control Flow & Functions (Weeks 4-6)

**Goal**: Support conditionals, loops, and basic function calls.

**Deliverables**:
1. **Control Flow Opcodes** (Week 4)
   - JUMP, JUMP_IF_TRUE, JUMP_IF_FALSE
   - While loops (compile to jumps)
   - If expressions
   - Break/continue support

2. **Function Calls** (Week 5)
   - CALL/RETURN opcodes
   - Call frame management
   - Parameter passing
   - Local variable scoping

3. **Closures** (Week 6)
   - Upvalue resolution in compiler
   - CLOSURE opcode
   - GET_UPVALUE/SET_UPVALUE
   - Nested functions

**Testing Strategy**:
- Factorial (recursive)
- Fibonacci (iterative and recursive)
- Higher-order functions: `map`, `filter`
- Closure capture tests

**Dependencies**: Phase 1

**Estimated Effort**: 3 weeks

---

### Phase 3: Collections & Records (Weeks 7-9)

**Goal**: Support vectors, records, tensors, and indexing.

**Deliverables**:
1. **Vectors** (Week 7)
   - NEW_VECTOR, VEC_PUSH
   - VEC_GET, VEC_SET
   - Spread operator
   - Iteration support

2. **Records** (Week 8)
   - NEW_RECORD
   - GET_FIELD, SET_FIELD
   - Record spread
   - Method calls (CALL_METHOD)

3. **Tensors** (Week 9)
   - NEW_TENSOR
   - TENSOR_GET, TENSOR_SET
   - Multidimensional indexing
   - Slicing

**Testing Strategy**:
- Vector operations: push, get, slice
- Record field access and mutation
- Tensor creation and indexing
- Integration with existing built-in functions

**Dependencies**: Phase 2

**Estimated Effort**: 3 weeks

---

### Phase 4: Pattern Matching & Destructuring (Weeks 10-11)

**Goal**: Implement match expressions and destructuring.

**Deliverables**:
1. **Pattern Matching** (Week 10)
   - MATCH_TYPE, MATCH_LIT
   - DESTRUCTURE_REC, DESTRUCTURE_VEC
   - Guard clauses (compile to JUMP_IF_FALSE)
   - Exhaustiveness checking

2. **Destructuring in Bindings** (Week 11)
   - Let destructuring
   - Function parameter destructuring
   - Default values in patterns

**Testing Strategy**:
- Match expressions with all pattern types
- Nested destructuring
- Guard clause edge cases

**Dependencies**: Phase 3

**Estimated Effort**: 2 weeks

---

### Phase 5: Generators & Async Foundation (Weeks 12-14)

**Goal**: Implement generator support as foundation for async.

**Deliverables**:
1. **Generator Compilation** (Week 12)
   - CREATE_GEN opcode
   - YIELD implementation
   - Generator state suspension

2. **Generator Execution** (Week 13)
   - RESUME_GEN opcode
   - Frame suspension/restoration
   - Iterator protocol

3. **For-in Loops** (Week 14)
   - Compile for-in to generator calls
   - Iterator support
   - Integration with vectors/tensors

**Testing Strategy**:
- Simple generators (counting, Fibonacci)
- Nested yields
- for-in iteration over generators
- Generator exhaustion and return values

**Dependencies**: Phase 4

**Estimated Effort**: 3 weeks

---

### Phase 6: Error Handling & Type System (Weeks 15-17)

**Goal**: Implement exceptions and gradual typing.

**Deliverables**:
1. **Exception Handling** (Week 15-16)
   - THROW opcode
   - PUSH_HANDLER, POP_HANDLER
   - Exception unwinding
   - Try-catch compilation

2. **Type Checking** (Week 17)
   - TYPE_CHECK, TYPE_ASSERT opcodes
   - Compile-time type inference
   - Runtime type validation
   - Union types

**Testing Strategy**:
- Throw/catch basic cases
- Nested try-catch
- Exception propagation
- Type assertion failures

**Dependencies**: Phase 5

**Estimated Effort**: 3 weeks

---

### Phase 7: Tail-Call Optimization (Week 18)

**Goal**: Implement TCO using TAIL_CALL opcode.

**Deliverables**:
1. **TCO Detection** (reuse existing `tco` module)
2. **TAIL_CALL opcode**
3. **Frame replacement** (instead of push)

**Testing Strategy**:
- Deep recursion (10,000+ calls)
- Mutual recursion
- Non-tail-recursive comparison

**Dependencies**: Phase 2 (functions)

**Estimated Effort**: 1 week

---

### Phase 8: Built-in Functions & Modules (Weeks 19-21)

**Goal**: Port all 200+ built-in functions to VM.

**Deliverables**:
1. **CALL_BUILTIN opcode** (Week 19)
2. **Module system integration** (Week 20)
3. **Port function modules** (Week 21)
   - Trig, exponential, stats
   - Matrix, vector operations
   - Graph algorithms
   - DSP functions

**Testing Strategy**:
- Port existing integration tests
- Performance benchmarks vs tree-walker

**Dependencies**: Phase 3 (collections)

**Estimated Effort**: 3 weeks

---

### Phase 9: Migration & Compatibility (Weeks 22-23)

**Goal**: Ensure backward compatibility and migration path.

**Deliverables**:
1. **Feature Flag** (Week 22)
   ```rust
   pub enum ExecutionMode {
       TreeWalker,  // Legacy
       VM,          // New
   }
   ```

2. **Compatibility Layer** (Week 22)
   - Same public API
   - Transparent mode switching
   - Benchmark suite

3. **Migration Guide** (Week 23)
   - Document differences
   - Performance comparisons
   - Migration checklist

**Testing Strategy**:
- Run entire test suite in both modes
- Compare outputs for equivalence
- Performance regression tests

**Dependencies**: All previous phases

**Estimated Effort**: 2 weeks

---

### Phase 10: Optimization & Polish (Weeks 24-26)

**Goal**: Optimize VM and prepare for release.

**Deliverables**:
1. **Performance Tuning** (Week 24)
   - Profiling with flamegraph
   - Hotspot optimization
   - Cache-friendly data layout

2. **Debug Support** (Week 25)
   - Source maps
   - Stack traces
   - BREAKPOINT opcode for debugger

3. **Documentation** (Week 26)
   - VM architecture docs
   - Opcode reference
   - Compiler internals

**Testing Strategy**:
- Benchmark suite across representative workloads
- Memory usage analysis
- Regression tests

**Dependencies**: Phase 9

**Estimated Effort**: 3 weeks

---

### Summary Timeline

**Total Duration**: 26 weeks (~6 months)

**Critical Path**:
1. Core VM (Phase 1) → 3 weeks
2. Functions (Phase 2) → 3 weeks
3. Collections (Phase 3) → 3 weeks
4. Generators (Phase 5) → 3 weeks
5. Built-ins (Phase 8) → 3 weeks
6. Migration (Phase 9) → 2 weeks
7. Polish (Phase 10) → 3 weeks

**Parallel Opportunities**:
- Pattern matching (Phase 4) can start after Phase 3
- Error handling (Phase 6) can overlap with Phase 8
- Documentation (Phase 10) can be ongoing

**Risk Mitigation**:
- Each phase has independent deliverables
- Testing at every phase prevents regression
- Feature flag allows safe deployment

---

## 5. Testing Strategy

### 5.1 Unit Testing

**Opcode-Level Tests**:
```rust
#[test]
fn test_add_opcode() {
    let mut vm = VM::new();
    vm.registers.set(0, Value::Number(2.0));
    vm.registers.set(1, Value::Number(3.0));
    vm.execute_opcode(OpCode::ADD, &[2, 0, 1]).unwrap();
    assert_eq!(vm.registers.get(2), &Value::Number(5.0));
}
```

**Compiler Tests**:
```rust
#[test]
fn test_compile_addition() {
    let ast = parse("2 + 3").unwrap();
    let bytecode = compile(&ast).unwrap();
    assert!(bytecode.code.contains(&encode(OpCode::ADD, &[2, 0, 1])));
}
```

### 5.2 Integration Testing

**Port Existing Tests**:
- Run all 50+ existing test files against VM
- Compare outputs with tree-walker
- Ensure identical semantics

**Async-Specific Tests**:
```achronyme
# Generator suspension
let gen = generate {
    yield 1
    yield 2
    yield 3
}
assert(gen.next().value == 1)
assert(gen.next().value == 2)
```

### 5.3 Performance Testing

**Benchmark Suite**:
1. **Micro-benchmarks**: Individual operations
2. **Macro-benchmarks**: Real algorithms (FFT, matrix multiply, pathfinding)
3. **Regression tests**: Ensure no slowdown vs tree-walker

**Metrics**:
- Execution time (vs tree-walker)
- Memory usage
- Bytecode size
- Compilation time

### 5.4 Stress Testing

**Edge Cases**:
- Deep recursion (10,000+ frames)
- Large collections (millions of elements)
- Complex closures (100+ upvalues)
- Generator exhaustion

---

## 6. Migration Plan

### 6.1 Backward Compatibility

**Guarantee**: All existing Achronyme code runs unchanged.

**Strategy**:
1. **Dual Mode**: Support both tree-walker and VM
2. **Transparent**: User doesn't know which is running
3. **Opt-in**: VM enabled via flag initially

```rust
pub struct Evaluator {
    mode: ExecutionMode,
    tree_walker: TreeWalkerEvaluator,
    vm: Option<VMEvaluator>,
}

impl Evaluator {
    pub fn eval_str(&mut self, source: &str) -> Result<Value, String> {
        match self.mode {
            ExecutionMode::TreeWalker => self.tree_walker.eval_str(source),
            ExecutionMode::VM => {
                let bytecode = compile(source)?;
                self.vm.as_mut().unwrap().execute(bytecode)
            }
        }
    }
}
```

### 6.2 Migration Checklist

**For Users**:
- [ ] Run test suite with `--vm-mode` flag
- [ ] Compare performance benchmarks
- [ ] Check for semantic differences (file bug if found)
- [ ] Update to 0.6.5 when stable

**For Developers**:
- [ ] All phases completed
- [ ] 100% test coverage parity
- [ ] Performance >= tree-walker
- [ ] Documentation complete
- [ ] LSP integration updated

### 6.3 Deprecation Timeline

**Version 0.6.5**: VM introduced (opt-in)
**Version 0.7.0**: VM default (tree-walker still available)
**Version 0.8.0**: Tree-walker deprecated (warnings)
**Version 0.9.0**: Tree-walker removed

---

## 7. Future Optimizations

### 7.1 JIT Compilation

**Strategy**: Identify hot functions and compile to native code.

**Approach**:
- Use `cranelift` JIT backend
- Tier-up: Bytecode → profiled → JIT
- Deoptimization support

**Expected Gain**: 5-10x speedup for hot loops

### 7.2 Inline Caching

**Strategy**: Cache type information for polymorphic operations.

**Example**:
```
# First call: field "x" is at offset 0
obj.x
# Second call with same type: use cached offset
obj.x  # Fast path
```

**Expected Gain**: 2-3x for record-heavy code

### 7.3 Constant Folding

**Strategy**: Evaluate constant expressions at compile time.

```achronyme
let x = 2 + 3 * 4  # Compiled to: LOAD_CONST R0, 14
```

### 7.4 Escape Analysis

**Strategy**: Allocate short-lived objects on stack instead of heap.

**Expected Gain**: Reduced GC pressure, faster allocation

### 7.5 SIMD Vectorization

**Strategy**: Use SIMD instructions for tensor operations.

**Implementation**:
- Detect compatible operations
- Emit SIMD opcodes
- Use `std::simd` or `packed_simd`

**Expected Gain**: 4-8x for numerical code

---

## Appendix: Code Examples

### Example 1: Factorial Compilation

**Source**:
```achronyme
let factorial = (n: Number): Number => {
    if (n <= 1) {
        return 1
    } else {
        return n * rec(n - 1)
    }
}
factorial(5)
```

**Compiled Bytecode** (pseudo-assembly):
```
# Function: factorial
# Params: 1 (n)
# Registers: 8
# Upvalues: 0

.function factorial:
    # R0 = n (parameter)

    # if (n <= 1)
    LOAD_CONST R1, 1          # R1 = 1
    LE R2, R0, R1             # R2 = (R0 <= R1)
    JUMP_IF_FALSE R2, @else   # if !R2 goto else

    # then: return 1
    LOAD_CONST R3, 1
    RETURN R3

@else:
    # else: return n * rec(n - 1)
    LOAD_CONST R4, 1          # R4 = 1
    SUB R5, R0, R4            # R5 = n - 1
    GET_LOCAL R6, 255         # R6 = rec (special register)
    CALL R7, R6, 1            # R7 = rec(R5)  [1 arg at R5]
    MUL R8, R0, R7            # R8 = n * R7
    RETURN R8

# Main:
.main:
    CLOSURE R0, @factorial    # R0 = <function factorial>
    LOAD_CONST R1, 5          # R1 = 5
    CALL R2, R0, 1            # R2 = factorial(5)
    # Result in R2
```

### Example 2: Generator Execution

**Source**:
```achronyme
let countdown = generate {
    yield 3
    yield 2
    yield 1
    return "Liftoff!"
}

let gen = countdown()
gen.next()  # {value: 3, done: false}
gen.next()  # {value: 2, done: false}
gen.next()  # {value: 1, done: false}
gen.next()  # {value: "Liftoff!", done: true}
```

**Bytecode**:
```
.function countdown$generator:
    # First yield
    LOAD_CONST R0, 3
    YIELD R0                  # Suspend, return {value: 3, done: false}

    # Second yield
    LOAD_CONST R1, 2
    YIELD R1                  # Suspend, return {value: 2, done: false}

    # Third yield
    LOAD_CONST R2, 1
    YIELD R2                  # Suspend, return {value: 1, done: false}

    # Return
    LOAD_CONST R3, "Liftoff!"
    RETURN R3                 # Return {value: "Liftoff!", done: true}

.main:
    CREATE_GEN R0, @countdown$generator  # R0 = <generator>

    # First call
    RESUME_GEN R1, R0         # R1 = {value: 3, done: false}

    # Second call
    RESUME_GEN R2, R0         # R2 = {value: 2, done: false}

    # etc.
```

### Example 3: Closure with Upvalues

**Source**:
```achronyme
let makeCounter = () => {
    mut count = 0
    return () => {
        count += 1
        return count
    }
}

let counter = makeCounter()
counter()  # 1
counter()  # 2
```

**Bytecode**:
```
.function makeCounter$inner:
    # Upvalues: [count]

    # count += 1
    GET_UPVALUE R0, 0         # R0 = count (upvalue 0)
    LOAD_CONST R1, 1
    ADD R2, R0, R1            # R2 = count + 1
    SET_UPVALUE 0, R2         # count = R2

    # return count
    GET_UPVALUE R3, 0
    RETURN R3

.function makeCounter:
    # mut count = 0
    LOAD_CONST R0, 0
    MAKE_MUT_REF R1, R0       # R1 = MutableRef(0)

    # Create closure (captures count)
    CLOSURE R2, @makeCounter$inner  # R2 = <closure>
    # Note: Compiler marks R1 as upvalue for inner function

    RETURN R2

.main:
    CALL R0, @makeCounter, 0  # R0 = makeCounter()
    CALL R1, R0, 0            # R1 = counter() = 1
    CALL R2, R0, 0            # R2 = counter() = 2
```

---

## Conclusion

This VM architecture provides a solid foundation for Achronyme's future, enabling:

1. **Async/Await Support**: Native suspension points via bytecode
2. **Improved Performance**: Register-based VM with optimization opportunities
3. **Maintainability**: Clear separation of concerns, modular design
4. **Extensibility**: Easy to add new opcodes and features
5. **Backward Compatibility**: Existing code continues to work

The phased implementation approach ensures steady progress with testable milestones. The 6-month timeline is realistic for a single senior engineer, with opportunities for parallelization if more resources are available.

**Next Steps**:
1. Review and approve this design
2. Set up project structure for `achronyme-vm` crate
3. Begin Phase 1: Core VM Infrastructure
4. Iterate and refine based on implementation learnings
