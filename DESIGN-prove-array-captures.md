# Design: Array Captures in `prove(public:[])` Blocks

## Status
**Resolved** — implemented 2026-03-22. Array type inference + enriched `OuterScopeEntry` + `CaptureArrayDef` metadata.

## Problem

`prove(public: [...])` auto-inference does not support arrays from the VM scope.

```ach
let path = [voter1, n1]
let indices = [0p0, 0p0]

// This fails — path and indices are VM lists, not circuit arrays
prove(public: [merkle_root, nullifier]) {
    merkle_verify(merkle_root, commitment, path, indices)
}
```

**Error:** `merkle_verify requires array identifiers for path and indices`

### Workaround

Use explicit witness declarations instead of auto-inference:

```ach
prove {
    public merkle_root
    public nullifier
    witness secret
    witness path[2]
    witness indices[2]
    // ...
}
```

This works because the bytecode compiler expands `witness path[2]` to captures `path_0`, `path_1`, which match the outer scope variables.

## Root Cause

Three layers block array auto-inference:

### 1. ProveIR compiler only knows scalar captures

`ProveIrCompiler::compile` receives `outer_scope: HashSet<String>` — a flat set of names with no type information. Everything is registered as `CompEnvValue::Capture(name)`. When the body references `path` as an array for `merkle_verify`, it's not found as an array in the environment.

### 2. The capture map is `HashMap<String, FieldElement>`

The `ProveHandler` trait and VM handler only pass scalar field elements:

```rust
// vm/src/machine/prove.rs
pub trait ProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,  // ← scalars only
    ) -> Result<ProveResult, ProveError>;
}
```

A VM list (`TAG_LIST`) cannot be represented as a `FieldElement`.

### 3. The bytecode compiler doesn't know types at compile time

The bytecode compiler emits `Move`/`GetUpvalue`/`GetGlobal` to load capture values into the map. It doesn't know whether `path` is a field element or a list — types are resolved at runtime.

## Proposed Solution

Three changes, propagating array awareness through the pipeline:

### A. Enrich `outer_scope` in ProveIR compiler

```rust
// ir/src/prove_ir/compiler.rs
pub enum OuterScopeEntry {
    Scalar,
    Array(usize),  // element count
}

pub fn compile(
    block: &Block,
    outer_scope: &HashMap<String, OuterScopeEntry>,
) -> Result<ProveIR, ProveIrError>
```

When an entry is `Array(n)`, register as `CompEnvValue::Array` with elements `name_0..name_{n-1}`. The ProveIR compiler can then resolve `merkle_verify(..., path, ...)` correctly.

### B. Expand lists in the VM prove handler

In `vm/src/machine/prove.rs`, when building `scope_values` from the capture map, detect `TAG_LIST` values and expand them:

```rust
// If val is a list [a, b, c], expand to:
//   "path_0" → a, "path_1" → b, "path_2" → c
// Plus keep "path" out of the scalar map.
```

This keeps the `ProveHandler` trait unchanged — the expansion happens before calling `execute_prove_ir`.

### C. Bytecode compiler passes array names alongside captures

The bytecode compiler's `compile_prove` needs to tell the ProveIR compiler which outer scope names are arrays. Since types aren't known at compile time, the compiler should:
1. Pass all outer scope names to ProveIR as `Scalar` (current behavior)
2. When ProveIR detects array usage (e.g., `merkle_verify`), record it
3. At runtime, the VM handler handles both scalar and list values

Alternatively, the bytecode compiler could emit a separate list of "array capture names" alongside the scalar capture map, and the VM handler would know to expand those.

## Rejected Approach

Heuristic reconstruction from naming convention (`name_0`, `name_1` → array `name`):
- **Fragile**: `player_1`, `round_0` would be falsely reconstructed
- **Duplicated**: same logic in compiler and instantiator
- **Wrong layer**: the problem is missing type info, not missing pattern matching

## Implemented Solution

Three coordinated changes propagate type info through the pipeline:

### 1. Array type inference (compiler)
`let x = [a, b, c]` auto-infers `FieldArray(3)` on the `Local.type_ann`. Only for
immutable `let` bindings — `mut` is excluded because reassignment could change the size.

### 2. Enriched outer_scope (ProveIR compiler)
`outer_scope` changed from `HashSet<String>` to `HashMap<String, OuterScopeEntry>` where
`OuterScopeEntry` is `Scalar | Array(usize)`. Array entries register as
`CompEnvValue::Array(["name_0", ...])` with element sub-captures, so `merkle_verify` and
other array-consuming constructs resolve correctly.

### 3. CaptureArrayDef metadata (ProveIR serialization)
New `capture_arrays: Vec<CaptureArrayDef>` field in ProveIR (format version 2). Records
which outer-scope arrays had captured elements. At instantiation, reconstructs
`InstEnvValue::Array` entries from individual element captures.

### 4. Type-directed capture loading (bytecode compiler)
`find_array_parent()` uses the enriched outer_scope as ground truth to detect array element
captures. Pushes the parent array name into `capture_names` instead of decomposed element
names. The VM handler's existing TAG_LIST expansion creates individual entries at runtime.

## Files Changed

- `compiler/src/statements/declarations.rs` — array type inference for `let`
- `ir/src/prove_ir/compiler.rs` — `OuterScopeEntry`, array capture registration, `capture_arrays` population
- `ir/src/prove_ir/types.rs` — `CaptureArrayDef` struct, format version 2
- `ir/src/prove_ir/instantiate.rs` — array env reconstruction from `capture_arrays`
- `compiler/src/control_flow.rs` — enriched outer_scope, `find_array_parent`, capture_names fix
- `vm/src/machine/prove.rs` — unchanged (TAG_LIST expansion already worked)
