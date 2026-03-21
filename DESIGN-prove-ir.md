# RFC: ProveIR — Unified Pre-compiled Circuit Representation

**Status:** Draft
**Date:** 2026-03-20
**Target:** 0.2.0

---

## Summary

Unify the circuit compilation pipeline for both `ach circuit` and `prove {}`
blocks under a single pre-compiled intermediate representation (**ProveIR**)
that sits between the AST and the SSA IR. This eliminates double parsing,
enables compile-time validation, allows standard Achronyme syntax in circuits,
and opens the door to witness auto-inference.

---

## Motivation

### Current architecture (the problem)

```
Parser                Bytecode Compiler           VM Runtime              Prove Handler
──────                ─────────────────           ──────────              ─────────────
parse_prove()         compile_prove()             handle_prove()          execute_prove()
│                     │                           │                       │
├─ AST (Block)        ├─ prescan for names        ├─ read capture map     ├─ strip "{ }"
├─ raw source string  ├─ capture vars from scope  ├─ convert to FE        ├─ RE-PARSE SOURCE ← 💀
│                     ├─ store source as K[str]   ├─ call handler         ├─ lower to IR SSA
│                     ├─ emit Prove opcode        │                       ├─ optimize
│                     ├─ DISCARD the AST body     │                       ├─ compile R1CS
│                     │                           │                       ├─ generate proof
```

**Problems:**

1. **Double parsing.** The source is parsed by the main parser (producing an AST that is thrown away), then re-parsed from a raw string by `IrLowering::lower_self_contained()` at runtime.

2. **No compile-time validation.** Errors inside prove blocks (type mismatches, unsupported operations, undeclared variables) are only detected when the prove block *executes*, not when the program is compiled.

3. **Fragile source extraction.** The compiler uses `source.find('{').unwrap_or(0)` to strip the `prove` keyword — byte-position hacking on raw source text.

4. **Two dialects.** Users must write a restricted subset of Achronyme inside prove blocks: no `mut`, no `return`, no methods, no `Field::ZERO`, no dot access. The promise "same syntax" is not fulfilled.

5. **Opaque to tooling.** The LSP cannot analyze prove block contents. The bytecode compiler cannot optimize across the prove boundary. The disassembler shows a string blob.

6. **No serialization.** Pre-compiled circuits cannot be cached or stored in `.achb` binaries. Every execution re-compiles from source.

### What this RFC enables

- **Compile-time validation** of prove block contents
- **Standard Achronyme syntax** inside prove blocks (mut, return, methods, static namespaces)
- **Witness auto-inference** (everything captured is witness unless marked public)
- **IDE support** inside prove blocks (completions, hover, diagnostics)
- **Circuit caching** (same ProveIR + same captures → reuse R1CS)
- **Serializable circuit templates** in `.achb` bytecode

---

## Design

### Unified pipeline: `ach circuit` and `prove {}`

Today there are three entry points to IR lowering that all re-parse source:

| Entry point | Used by | Declares inputs | Source |
|---|---|---|---|
| `lower_circuit()` | `ach circuit` CLI | External (CLI flags) | Re-parses from string |
| `lower_self_contained()` | `prove {}` handler | Internal (from source) | RE-PARSES at runtime |
| `lower()` | Internal/generic | Pre-declared by caller | Re-parses from string |

With ProveIR, both converge to the same pipeline. The only difference is
**where values come from**:

```
ach circuit file.ach                 ach run file.ach (with prove {})
────────────────────                 ─────────────────────────────────
Parser → AST                         Parser → AST → Bytecode → VM
       ↓                                    ↓                   ↓
ProveIR Compiler ◄── SAME CODE ──► ProveIR Compiler             │
       ↓                                    ↓                   │
   ProveIR                             ProveIR (in bytecode)    │
       ↓                                    ↓ (at runtime)      │
instantiate(--inputs)               instantiate(scope captures)  │
       ↓                                    ↓                   │
    IR SSA  ◄──────── SAME CODE ──►      IR SSA                 │
       ↓                                    ↓                   │
R1CS/Plonkish → proof               R1CS/Plonkish → proof
```

For `ach circuit`, the ProveIR is compiled and immediately instantiated (no
serialization needed). For `prove {}`, the ProveIR is serialized into the
bytecode constant pool and instantiated at runtime when the VM executes the
Prove opcode.

This unification means:
- **Same desugaring rules** for both modes (mut, return, methods, statics)
- **Same validation** at compile time for both modes
- **Same error messages** with the same quality
- `IrLowering::lower_circuit()`, `lower_self_contained()`, and `lower()`
  are all **replaced** by `ProveIrCompiler::compile(ast) → ProveIR` followed
  by `ProveIR::instantiate(values) → IrProgram`

### New pipeline (both modes)

```
Parser → AST → ProveIR Compiler → ProveIR (serialized in bytecode)
                                      │
                               ┌──────┘ (runtime)
                               │
                    ProveIR + scope values
                               │
                    instantiate (unroll loops, expand arrays)
                               │
                            IR SSA
                               │
                    optimize → R1CS/Plonkish → proof
```

### ProveIR: the intermediate representation

ProveIR is a **validated, desugared, serializable circuit template** that preserves structural information (loops, conditionals) while removing all VM-only constructs.

#### Key properties

| Property | AST | ProveIR | IR SSA |
|----------|-----|---------|--------|
| Parsed & validated | ✓ | ✓ | ✓ |
| Functions inlined | ✗ | ✓ | ✓ |
| VM constructs desugared | ✗ | ✓ | ✓ |
| Loops preserved (not unrolled) | ✓ | ✓ | ✗ |
| Arrays symbolic (not expanded) | ✓ | ✓ | ✗ |
| SSA form | ✗ | ✗ | ✓ |
| Serializable to bytecode | ✗ | ✓ | ✗ |
| Parametric (has "holes") | ✗ | ✓ | ✗ |

#### Data structures

```rust
/// A pre-compiled circuit template, ready for instantiation.
pub struct ProveIR {
    /// Variables the verifier knows (explicitly declared by user).
    pub public_inputs: Vec<InputDecl>,
    /// Variables only the prover knows (auto-inferred or explicit).
    pub witness_inputs: Vec<InputDecl>,
    /// Template parameters — values from outer scope that affect circuit
    /// structure (loop bounds, array sizes) but are NOT circuit inputs.
    pub captures: Vec<CaptureDef>,
    /// The circuit body — validated, desugared, functions inlined.
    pub body: Vec<CircuitNode>,
}

pub struct InputDecl {
    pub name: String,
    pub array_size: Option<ArraySize>,  // None = scalar, Some = array
    pub ir_type: IrType,                // Field or Bool
}

/// Array size can be a literal or a captured value.
pub enum ArraySize {
    Literal(usize),
    Capture(String),  // resolved at instantiation
}

pub struct CaptureDef {
    pub name: String,
    pub usage: CaptureUsage,  // StructureOnly | CircuitInput | Both
}

/// How a captured variable is used in the circuit.
pub enum CaptureUsage {
    /// Only affects structure (loop bounds, array sizes, exponents).
    /// Becomes a compile-time constant during instantiation — NOT a circuit input.
    StructureOnly,
    /// Used in constraint expressions. Becomes a witness input.
    CircuitInput,
    /// Both structural and in constraints.
    Both,
}
```

#### Circuit nodes (the body)

```rust
pub enum CircuitNode {
    // Declarations
    Let { name: String, value: CircuitExpr },

    // Constraints
    AssertEq { lhs: CircuitExpr, rhs: CircuitExpr },
    Assert { expr: CircuitExpr },

    // Control flow (preserved, not unrolled)
    For {
        var: String,
        start: CircuitExpr,
        end: CircuitExpr,     // may be Capture("n")
        body: Vec<CircuitNode>,
    },
    If {
        cond: CircuitExpr,
        then_body: Vec<CircuitNode>,
        else_body: Vec<CircuitNode>,
    },
}

pub enum CircuitExpr {
    Const(FieldElement),
    Input(String),              // public or witness variable
    Capture(String),            // template parameter
    Var(String),                // local let-binding
    BinOp(BinOp, Box<Self>, Box<Self>),
    UnaryOp(UnaryOp, Box<Self>),
    Comparison(CmpOp, Box<Self>, Box<Self>),
    BoolOp(BoolOp, Box<Self>, Box<Self>),
    Mux { cond: Box<Self>, if_true: Box<Self>, if_false: Box<Self> },
    PoseidonHash(Box<Self>, Box<Self>),
    PoseidonMany(Vec<Self>),
    RangeCheck { value: Box<Self>, bits: u32 },
    MerkleVerify { root: Box<Self>, leaf: Box<Self>, path: String, indices: String },
    ArrayIndex(String, Box<Self>),
    ArrayLen(String),           // compile-time if literal size, capture if dynamic
}
```

### Desugaring rules (VM syntax → ProveIR)

The ProveIR compiler translates standard Achronyme constructs into their
circuit equivalents during **compile time**, before any runtime execution:

| Achronyme syntax | ProveIR desugaring | Notes |
|---|---|---|
| `mut x = a; x = b; x = c` | `Let(x_0, a); Let(x_1, b); Let(x_2, c)` | SSA renaming. All uses of `x` after reassignment use `x_N`. |
| `return expr` | Last expression of block | Functions are inlined; return becomes the inline result. |
| `Field::ZERO` | `Const(FieldElement::ZERO)` | Static namespace members are compile-time constants. |
| `Field::ONE` | `Const(FieldElement::ONE)` | |
| `Field::ORDER` | Error: `ORDER is a string, not a field element` | Strings are not constrainable. |
| `Int::MAX` | `Const(FieldElement::from_i64(2^59-1))` | |
| `value.len()` | `Const(n)` or `Capture("len")` | Known-size arrays resolve at compile time. |
| `value.to_field()` | Identity (all circuit values are field elements) | No-op in circuit context. |
| `value.to_string()` | Error: strings not constrainable | Clear error message. |
| `value.abs()` | `Mux(IsLt(x, Const(0)), Neg(x), x)` | Conditional selection. |
| `n.min(m)` | `Mux(IsLt(n, m), n, m)` | |
| `n.max(m)` | `Mux(IsLt(n, m), m, n)` | |
| `n.pow(k)` | Unrolled multiplications (k must be const) | Same as current behavior. |
| `[a,b,c].map(fn(x){f(x)})` | `[f(a), f(b), f(c)]` | Inline + unroll. Array size must be known. |
| `arr.reduce(init, fn(a,x){...})` | Unrolled accumulator chain | Array size must be known. |
| `list.filter(fn(x){...})` | **Error**: variable-length output | With actionable suggestion. |
| `list.push(x)` | **Error**: mutation not constrainable | With actionable suggestion. |
| `map.keys()` | **Error**: maps not constrainable | |
| `if c { a } else { b }` | `Mux(c, a, b)` | Both branches always evaluated. |
| `for i in 0..n { body }` | `For { start: 0, end: Capture("n"), body }` | Preserved; unrolled at instantiation. |

### Witness auto-inference

With ProveIR, the `prove` block syntax changes:

```ach
// Current (verbose, redundant)
let secret = 42
let hash = poseidon(secret, 0)
let p = prove {
    witness secret
    public hash
    assert_eq(poseidon(secret, 0), hash)
}

// New syntax: public is opt-in, witness is inferred
let secret = 42
let hash = poseidon(secret, 0)
let p = prove(public: [hash]) {
    assert_eq(poseidon(secret, 0), hash)
}
```

#### Inference rules

1. Variables listed in `public: [...]` → `InputDecl` with `Visibility::Public`
2. Variables referenced in the body that exist in the outer scope and are NOT public → `InputDecl` with `Visibility::Witness` (auto-inferred)
3. Variables used only in structural positions (loop bounds, array sizes, exponents) → `CaptureDef` with `CaptureUsage::StructureOnly` (inlined as constants, not circuit inputs)
4. Literal constants → `Const(...)` (never captured)
5. Variables defined inside the prove block → local bindings (not captured)

#### Backward compatibility

The explicit `witness`/`public` declaration syntax MUST continue to work. The
new `prove(public: [...])` syntax is additive. Migration path:

```ach
// Old syntax — still valid
prove {
    witness secret
    public hash
    assert_eq(poseidon(secret, 0), hash)
}

// New syntax — equivalent
prove(public: [hash]) {
    assert_eq(poseidon(secret, 0), hash)
}
```

If both old-style declarations and new-style `public: [...]` are present,
the compiler emits an error (pick one style).

### Taint analysis compatibility

The taint analysis pass is **unchanged**. It receives an IR SSA program with
`Input { visibility: Public/Witness }` instructions exactly as before. The only
difference is who decided the visibility:

- **Old:** User explicitly wrote `witness x` / `public y`
- **New:** Compiler inferred witness, user opted-in to public

The taint analysis detects:
- **UnderConstrained**: a witness input that never flows into an `assert_eq`
- **UnusedInput**: an input that is never referenced

Both warnings remain valid and useful regardless of how the visibility was determined.

### Instantiation (runtime)

```rust
impl ProveIR {
    /// Instantiate the template with concrete values.
    ///
    /// 1. Resolve all Capture("name") with provided values
    /// 2. Unroll For loops (now that bounds are known)
    /// 3. Expand array declarations (now that sizes are known)
    /// 4. Generate IR SSA (all values are concrete)
    pub fn instantiate(
        &self,
        captures: &HashMap<String, FieldElement>,
    ) -> Result<IrProgram, ProveError> {
        // ...
    }
}
```

### Serialization

ProveIR must be serializable for `.achb` bytecode files. Options:

1. **Binary format** (custom): compact, fast to deserialize, versioned
2. **Bincode/MessagePack**: existing serde-based formats

Recommendation: start with bincode for simplicity, move to custom binary if
size/speed becomes a concern.

### Compilation phases

```
Phase 1: ProveIR Compilation (at `cargo build` / `ach compile` time)
───────────────────────────────────────────────────────────────────
  AST Block
    → validate (reject non-constrainable constructs)
    → inline functions
    → desugar VM constructs (mut→SSA, methods→primitives, statics→const)
    → classify captures (structural vs circuit input)
    → emit ProveIR

Phase 2: Instantiation (at runtime, when prove opcode executes)
──────────────────────────────────────────────────────────────
  ProveIR + scope values
    → resolve captures
    → unroll loops
    → expand arrays
    → generate IR SSA

Phase 3: Constraint Generation (existing pipeline, unchanged)
─────────────────────────────────────────────────────────────
  IR SSA
    → optimize (constant folding, DCE, bool propagation)
    → taint analysis
    → compile to R1CS or Plonkish
    → generate proof
```

---

## Implementation Plan

### Phase A: ProveIR data structures and compiler

**Crate:** `ir` (new module `ir/src/prove_ir/`)

1. Define `ProveIR`, `CircuitNode`, `CircuitExpr` types
2. Implement `ProveIrCompiler` that walks an AST `Block` and emits `ProveIR`
3. Implement desugaring rules (mut→SSA, methods→primitives, statics→const)
4. Implement capture classification (structural vs circuit input)
5. Implement validation with clear error messages
6. Tests: valid circuits, desugaring correctness, error messages

### Phase B: Instantiation

**Crate:** `ir`

1. Implement `ProveIR::instantiate()` → `IrProgram`
2. Loop unrolling with concrete bounds
3. Array expansion with concrete sizes
4. SSA variable generation
5. Tests: instantiation correctness, match output with current IR lowering

### Phase C: Serialization

**Crate:** `ir`

1. Add serde derives to ProveIR types
2. Implement serialize/deserialize with bincode
3. Tests: roundtrip serialization

### Phase D: `ach circuit` migration

**Crate:** `cli`

1. Change `ach circuit` command to: parse AST → ProveIR → instantiate(inputs) → IR SSA
2. Remove direct call to `IrLowering::lower_circuit()` / `lower_circuit_with_base()`
3. `--public` and `--witness` CLI flags inject into ProveIR's input declarations
4. In-source `public`/`witness` declarations handled by ProveIR compiler (not IrLowering)
5. Tests: all 26 `test/circuit/*.ach` tests must pass unchanged

### Phase E: Bytecode compiler integration (`prove {}`)

**Crate:** `compiler`

1. Change `compile_prove()` to invoke ProveIR compiler instead of storing raw source
2. Store serialized ProveIR in constant pool (instead of source string)
3. Update `prescan_prove_block()` to use ProveIR's input/capture declarations
4. Update capture map building to include auto-inferred witnesses

### Phase F: Runtime integration (`prove {}`)

**Crate:** `vm` + `cli`

1. Update `handle_prove()` to deserialize ProveIR from constant pool
2. Update `ProveHandler::execute_prove()` signature to accept `ProveIR` instead of `&str`
3. Update `DefaultProveHandler` to call `instantiate()` then existing IR→R1CS pipeline
4. Remove `IrLowering::lower_self_contained()` (no longer needed)
5. Remove `IrLowering::lower_circuit()` and `lower()` (replaced by ProveIR)

### Phase G: New prove syntax

**Crate:** `achronyme-parser`

1. Parse `prove(public: [names]) { body }` syntax
2. Maintain backward compatibility with `prove { witness x; public y; body }` syntax
3. AST: `Expr::Prove` gains optional `public_list: Vec<String>` field
4. Remove `source: String` field from `Expr::Prove` (no longer needed)

### Phase H: Documentation and migration

1. Update docs site (methods.mdx, native-functions.mdx)
2. Add migration guide for explicit → inferred witness syntax
3. Update tutorials with new syntax
4. Deprecation warnings for old syntax (optional, can keep both)

---

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Large refactor touches many crates | Phase-by-phase rollout. Each phase is independently testable. Phase D (ach circuit) can ship before Phase E-F (prove blocks). |
| Desugaring incorrectness | Extensive test suite comparing ProveIR output with current IR lowering output for all existing test circuits. |
| Capture classification errors | Conservative default: if unsure, treat as `Both` (circuit input). User can override. |
| Performance regression | ProveIR compilation is O(AST size) — negligible vs proof generation. Instantiation replaces re-parsing which is slower. |
| Backward compatibility | Old `witness`/`public` syntax continues to work. No breaking changes. |
| Serialization versioning | Include format version in serialized ProveIR. Reject incompatible versions with clear error. |

---

## Non-goals (for this RFC)

- **Multi-curve support** — ProveIR is curve-agnostic by design, but this RFC doesn't add new curves.
- **Cross-prove-block optimization** — Each prove block is independently compiled. Sharing constraints between blocks is a future enhancement.
- **Recursive proofs** — Verifying a proof inside a prove block requires IVC/folding schemes, out of scope.
- **Dynamic array sizes in circuit inputs** — `witness arr[n]` where `n` is a runtime value requires the ProveIR capture mechanism, but the R1CS/Plonkish backends still need fixed sizes. The ProveIR resolves `n` at instantiation time.

---

## Success criteria

1. All 12 existing `test/prove/*.ach` tests pass unchanged
2. All 26 existing `test/circuit/*.ach` tests pass unchanged
3. `ach circuit` and `prove {}` use the same ProveIR pipeline (no code duplication)
4. Both modes support `mut`, `return`, methods, and static namespaces
5. `prove(public: [x])` syntax works with auto-inferred witnesses
6. Circuit/prove errors are reported at compile time, not runtime
7. `.achb` files contain serialized ProveIR (no raw source strings)
8. `IrLowering::lower_circuit()`, `lower_self_contained()`, and `lower()` are removed
9. LSP can report diagnostics inside prove blocks and circuit files
