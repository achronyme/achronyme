# Architecture

Achronyme is a programming language for zero-knowledge circuits.
It compiles source code into R1CS constraint systems over the BN254 scalar field,
producing outputs compatible with snarkjs for Groth16 proof generation.

## Pipeline

```
Source (.ach)
    │
    ▼
┌──────────┐    parse_program()
│  Parser  │    achronyme-parser/src/parser.rs
└────┬─────┘
     │  Program (AST)
     ▼
┌──────────┐    IrLowering::lower_circuit()
│ IR Lower │    ir/src/lower.rs
└────┬─────┘
     │  IrProgram (SSA)
     ▼
┌──────────┐    optimize()
│  Passes  │    ir/src/passes/mod.rs
└────┬─────┘    ├─ const_fold
     │          └─ dce
     ▼
┌──────────┐    R1CSCompiler::compile_ir()
│ Backend  │    compiler/src/r1cs_backend.rs
└────┬─────┘    (or PlonkishCompiler)
     │  ConstraintSystem
     ▼
┌──────────┐    write_r1cs() / write_wtns()
│  Export  │    constraints/src/export.rs
└──────────┘
     │
     ▼
  .r1cs + .wtns  →  snarkjs groth16
```

## Crate Map

| Crate | Path | Purpose | Key Types |
|-------|------|---------|-----------|
| `memory` | `memory/` | BN254 field arithmetic, tagged values, heap/GC | `FieldElement`, `Value`, `Heap` |
| `achronyme-parser` | `achronyme-parser/` | Recursive descent parser, AST types | `Program`, `Stmt`, `Expr`, `Block` |
| `constraints` | `constraints/` | R1CS + Plonkish constraint systems, export | `ConstraintSystem`, `Variable`, `LinearCombination`, `PlonkishSystem` |
| `ir` | `ir/` | SSA intermediate representation, lowering, optimization | `IrProgram`, `SsaVar`, `Instruction`, `IrLowering` |
| `compiler` | `compiler/` | Bytecode compiler + ZK backends | `R1CSCompiler`, `PlonkishCompiler`, `Compiler` |
| `vm` | `vm/` | Virtual machine execution | `VM` |
| `cli` | `cli/` | Command-line interface, prove handler | `DefaultProveHandler` |

### Dependency Graph

```
cli → compiler → ir → achronyme-parser
 │       │        │
 │       │        └──→ constraints → memory
 │       │                  ↑
 │       └────────────────────
 └──→ vm → memory
```

## Data Flow: Circuit Compilation

A complete circuit compilation follows these steps:

### 1. Parse

```rust
// achronyme-parser/src/parser.rs
pub fn parse_program(source: &str) -> Result<Program, String>
```

Recursive descent parser with Pratt expression parsing. Produces an owned AST
with `Stmt` and `Expr` nodes. Handles `public`/`witness` declarations,
`for` ranges, `fn` definitions, and `prove {}` blocks.

### 2. Lower to IR

```rust
// ir/src/lower.rs
impl IrLowering {
    // External inputs specified by caller:
    pub fn lower_circuit(source: &str, public: &[&str], witness: &[&str])
        -> Result<IrProgram, IrError>

    // In-source public/witness declarations:
    pub fn lower_self_contained(source: &str)
        -> Result<(Vec<String>, Vec<String>, IrProgram), IrError>
}
```

Walks the AST and emits SSA instructions. Each `let` binding is an alias (no
instruction). `if/else` becomes `Mux`, `for` is statically unrolled, and `fn`
calls are inlined at each call site with a recursion guard.

### 3. Optimize

```rust
// ir/src/passes/mod.rs
pub fn optimize(program: &mut IrProgram)
```

Runs two passes in sequence:
- **const_fold** — forward pass, folds arithmetic on known constants, mul-by-zero,
  `x - x → 0`, `x / x → 1`, boolean logic, comparisons
- **dce** — backward pass, removes instructions whose result is unused
  (conservative on side-effecting instructions)

### 4. Compile to R1CS

```rust
// compiler/src/r1cs_backend.rs
impl R1CSCompiler {
    pub fn compile_ir(&mut self, program: &IrProgram) -> Result<(), R1CSError>

    // Evaluate + compile + build witness in one pass:
    pub fn compile_ir_with_witness(
        &mut self, program: &IrProgram, inputs: &HashMap<String, FieldElement>,
    ) -> Result<Vec<FieldElement>, R1CSError>
}
```

Walks IR instructions and builds a `HashMap<SsaVar, LinearCombination>`.
Add/Sub/Neg are free (linear combination arithmetic). Only `Mul`, `Div`,
`Mux`, `AssertEq`, `PoseidonHash`, and comparison instructions generate
actual R1CS constraints.

### 5. Export

```rust
// constraints/src/export.rs
pub fn write_r1cs(cs: &ConstraintSystem) -> Vec<u8>   // iden3 v1
pub fn write_wtns(witness: &[FieldElement]) -> Vec<u8> // iden3 v2
```

Produces binary files directly consumable by `snarkjs r1cs info` and
`snarkjs wtns check`.

## Key Types Reference

### memory

| Type | Description |
|------|-------------|
| `FieldElement` | BN254 scalar field element in Montgomery form (`[u64; 4]` limbs) |
| `Value` | Tagged u64: 4-bit tag + 60-bit payload. No floats — integers are i60 |
| `Heap` | Arena allocator for strings, lists, maps, closures, field elements |

### constraints

| Type | Description |
|------|-------------|
| `Variable(usize)` | Wire reference. `Variable::ONE` = index 0 (constant-1 wire) |
| `LinearCombination` | Sparse `Vec<(Variable, FieldElement)>` — sum of weighted wires |
| `ConstraintSystem` | Collects `A * B = C` constraints, allocates wires, verifies witnesses |
| `PlonkishSystem` | Gate/lookup/copy constraint system for Plonkish arithmetization |

### ir

| Type | Description |
|------|-------------|
| `SsaVar(u32)` | SSA variable — defined exactly once |
| `Instruction` | One of 19 variants: `Const`, `Input`, `Add`, `Sub`, `Mul`, `Div`, `Neg`, `Mux`, `AssertEq`, `PoseidonHash`, `RangeCheck`, `Not`, `And`, `Or`, `IsEq`, `IsNeq`, `IsLt`, `IsLe`, `Assert` |
| `IrProgram` | Flat list of instructions + variable name map |
| `IrLowering` | AST→IR converter with environment, function table, call stack |

### compiler

| Type | Description |
|------|-------------|
| `R1CSCompiler` | IR→R1CS: maps `SsaVar` to `LinearCombination`, emits constraints |
| `PlonkishCompiler` | IR→Plonkish: deferred add/sub, cell-based with arith rows |
| `WitnessOp` | Trace entry for witness generation replay |
| `Compiler` | Bytecode compiler for VM execution (non-circuit path) |

## Circuit Compilation Deep Dive

### Wire Layout (R1CS)

```
Index:  0       1..n_pub    n_pub+1..
        │         │             │
        ONE     public        witness + intermediate
```

All public inputs must be allocated before witnesses (snarkjs compatibility).

### Instruction → Constraint Mapping

| IR Instruction | R1CS Cost | How |
|----------------|-----------|-----|
| `Const` | 0 | `LinearCombination::from_constant(value)` |
| `Input` | 0 | `alloc_input` / `alloc_witness` → `from_variable` |
| `Add` | 0 | `lc_a + lc_b` (LC arithmetic, no constraint) |
| `Sub` | 0 | `lc_a - lc_b` |
| `Neg` | 0 | `lc * (-1)` |
| `Mul` | 1 | `enforce(A, B, out)` via `multiply_lcs` |
| `Div` | 2 | inverse + multiplication constraints |
| `Mux` | 2 | boolean enforcement + `cond * (then - else)` |
| `AssertEq` | 1 | `enforce_equal(lhs, rhs)` |
| `Assert` | 2 | boolean enforcement + `enforce(op, 1, 1)` |
| `PoseidonHash` | 361 | Poseidon permutation circuit (360 rounds + 1 capacity) |
| `RangeCheck(n)` | n+1 | n boolean decomposition bits + sum check |
| `Not` | 1 | boolean enforcement on operand |
| `And` | 3 | 2 boolean enforcements + 1 multiplication |
| `Or` | 3 | 2 boolean enforcements + 1 multiplication |
| `IsEq` | 2 | IsZero gadget (inverse witness + 2 constraints) |
| `IsNeq` | 2 | IsZero gadget + `1 - result` |
| `IsLt` | ~760 | 2×252-bit range checks + 253-bit decomposition |
| `IsLe` | ~760 | Same as IsLt with swapped args |

### Witness Generation

The `R1CSCompiler` records `WitnessOp` entries during compilation. The
`WitnessGenerator` replays these ops with concrete input values to fill the
witness vector:

- `AssignLC` — evaluate a linear combination
- `Multiply` — compute `a * b`
- `Inverse` — compute `a⁻¹ mod p`
- `BitExtract` — extract bit `i` from a value
- `PoseidonHash` — replay the full Poseidon permutation
- `IsZero` — compute the inverse-or-zero witness

## Extension Points

### Adding a new IR instruction

1. Add variant to `Instruction` enum in `ir/src/types.rs`
2. Implement `result_var()`, `has_side_effects()`, `operands()` for the new variant
3. Handle in `ir/src/lower.rs` (AST→IR emission)
4. Handle in `ir/src/eval.rs` (concrete evaluation)
5. Handle in `ir/src/passes/const_fold.rs` if foldable
6. Handle in `ir/src/passes/dce.rs` (is it side-effecting?)
7. Handle in `compiler/src/r1cs_backend.rs` (`compile_ir` match arm)
8. Handle in `compiler/src/plonkish_backend.rs` (Plonkish match arm)
9. Add witness op if the instruction needs intermediate wire values

### Adding a builtin function

1. Add the function name to the match in `ir/src/lower.rs` (`lower_call`)
2. Emit the appropriate IR instruction(s)
3. Add evaluation logic in `ir/src/eval.rs`
4. Add R1CS constraint logic in `compiler/src/r1cs_backend.rs`
5. Add Plonkish constraint logic in `compiler/src/plonkish_backend.rs`

### Adding an optimization pass

1. Create a new module in `ir/src/passes/`
2. Implement a function `pub fn my_pass(program: &mut IrProgram)`
3. Call it from `optimize()` in `ir/src/passes/mod.rs`
4. The pass receives the full instruction list and can rewrite, remove, or
   reorder instructions (respecting SSA and side-effect constraints)
