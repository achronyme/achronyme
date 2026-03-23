# Design: Array Auto-Capture in Prove Blocks for Top-Level Globals

## Status
**Open** — 2026-03-22. Pre-existing bug, discovered during syntax unification.

## Problem

Arrays declared at top-level (`scope_depth == 0`) are not recognized as arrays when auto-captured by `prove` blocks. This causes `merkle_verify` and array indexing inside prove blocks to fail with:

```
merkle_verify path `path` is not an array
```

or:

```
`arr` is not an array
```

### Root Cause

When `let arr: Field[2] = [0p1, 0p2]` is compiled at top-level:

1. **`compile_let_decl`** (`compiler/src/statements/declarations.rs:47-79`) checks `scope_depth`:
   - If `scope_depth > 0` → creates a `Local` with `type_ann` (preserves array size)
   - If `scope_depth == 0` → registers as **global** via `DefGlobalLet` — **no `Local` created, no `type_ann` stored**

2. **`compile_prove`** (`compiler/src/control_flow.rs:448-464`) builds `outer_scope` by reading `local.type_ann.array_size` from all locals. Globals are added separately at line 466-471 with a hardcoded comment:

   ```rust
   // Global symbols (no type annotation info available — treated as scalar)
   for name in self.collect_in_scope_names() {
       outer_scope
           .entry(name.to_string())
           .or_insert(ir::prove_ir::OuterScopeEntry::Scalar);
   }
   ```

3. **ProveIR** receives `proof_path` as `Scalar` in the outer scope → doesn't know it's an array → `merkle_verify` rejects it.

### The naming convention `_N` doesn't help

The `find_array_parent` function (`control_flow.rs:40-56`) checks if `proof_path_0` has a parent `proof_path` registered as `Array(n)` in the outer scope. But since `proof_path` was never registered as an array (it's a global treated as scalar), the lookup fails.

Even individual elements like `let proof_path_0 = x; let proof_path_1 = y;` don't work because there's no parent `proof_path` with `Array(2)` in the outer scope to match against.

## Reproduction

### Minimal case — fails

```ach
let root = poseidon(poseidon(0p1, 0p2), poseidon(0p3, 0p4))
let path: Field[2] = [0p2, poseidon(0p3, 0p4)]
let idx: Field[2] = [0p0, 0p0]

prove(root: Public) {
    merkle_verify(root, 0p1, path, idx)
}
```

Error: `merkle_verify path 'path' is not an array`

### Same code inside a function — also fails

```ach
fn main() {
    let root = poseidon(poseidon(0p1, 0p2), poseidon(0p3, 0p4))
    let path: Field[2] = [0p2, poseidon(0p3, 0p4)]
    let idx: Field[2] = [0p0, 0p0]

    prove(root: Public) {
        merkle_verify(root, 0p1, path, idx)
    }
}
main()
```

Error: `merkle_verify path 'path' is not an array`

This fails too because the VM stores `[0p2, ...]` as a single `Value::Array` in one register. The `Local` has `type_ann = Some(Field[2])` and the outer_scope gets `Array(2)`, but the ProveIR compilation fails at a different stage — it sees `path` as a single captured variable, not as decomposed `path_0, path_1` elements.

### Circuit mode — works

```ach
circuit merkle(root: Public, leaf: Witness, path: Witness Field[2], idx: Witness Field[2]) {
    merkle_verify(root, leaf, path, idx)
}
```

This works because `circuit` params go through `compile_input_decl` which explicitly decomposes `path[2]` into `path_0, path_1` as separate IR input variables.

## Affected Files

- `examples/credential_proof.ach` — uses `merkle_verify` in prove block with top-level arrays (broken)
- `examples/hash_chain_proof.ach` — may have similar issues
- Any user code using `merkle_verify` inside `prove` blocks (vs. `circuit` blocks)

## Analysis

There are two distinct sub-problems:

### Sub-problem A: Globals don't carry type annotations

**Where**: `compiler/src/statements/declarations.rs:65-79`

Globals are stored as `(name → global_index)` in `global_symbols: HashMap<String, u16>`. There is no mechanism to attach a `TypeAnnotation` to a global. When `compile_prove` builds the outer scope, it can only say "this name exists" but not "this name is an array of size N".

**Possible fix**: Add a parallel `global_type_anns: HashMap<String, TypeAnnotation>` to the `Compiler` struct, and populate it when compiling global let declarations. Then `compile_prove` can read from it when building the outer scope.

### Sub-problem B: Array values aren't decomposed for prove capture

**Where**: `compiler/src/control_flow.rs` (prove capture emission, lines ~520-570)

Even when a local has `type_ann = Some(Field[2])` and the outer scope has `Array(2)`, the runtime capture mechanism loads the variable as a single `Value::Array` from one register. But the ProveIR instantiation expects individual scalar values `path_0, path_1` delivered as separate captures.

The `circuit` path works because `compile_input_decl` in ProveIR (`ir/src/prove_ir/compiler.rs:321`) explicitly expands `path[2]` into `path_0, path_1` as separate IR input variables. The prove capture path doesn't do this decomposition.

**Possible fix**: When emitting captures for a prove block, detect array-typed variables and decompose them: load the array value, then emit individual element captures (`array[0]`, `array[1]`, ...) instead of a single capture.

## Impact

- **Circuit mode** (`circuit name(...)` and `ach circuit file.ach`): **NOT affected** — arrays work correctly because inputs are decomposed at declaration time.
- **Prove blocks** (`prove(x: Public) { ... }`): **Affected** when the prove body uses `merkle_verify` or array indexing on auto-captured arrays from the outer scope.
- **Workaround**: Use individual scalar variables with `_N` naming AND ensure the parent array is declared in the outer scope with a type annotation that the compiler can see. Currently no reliable workaround exists for top-level code.

## Priority

**High** — blocks the Tornado Cash example and any real-world prove block that uses Merkle proofs with auto-captured arrays.
