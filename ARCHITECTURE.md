# Architecture

Achronyme is a programming language for zero-knowledge circuits.
It compiles source code into R1CS or Plonkish constraint systems over a configurable
prime field (BN254, BLS12-381, or Goldilocks), producing outputs compatible with
snarkjs for Groth16 proof generation, or native PlonK proofs via halo2.

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
| `memory` | `memory/` | Generic field arithmetic (`F: FieldBackend`), tagged values, heap/GC | `FieldElement<F>`, `FieldBackend`, `Value`, `Heap` |
| `achronyme-parser` | `achronyme-parser/` | Recursive descent parser, AST types | `Program`, `Stmt`, `Expr`, `Block` |
| `constraints` | `constraints/` | R1CS + Plonkish constraint systems, export | `ConstraintSystem`, `Variable`, `LinearCombination`, `PlonkishSystem` |
| `ir` | `ir/` | SSA intermediate representation, lowering, optimization | `IrProgram`, `SsaVar`, `Instruction`, `IrLowering` |
| `compiler` | `compiler/` | Bytecode compiler + ZK backends | `R1CSCompiler`, `PlonkishCompiler`, `Compiler` |
| `vm` | `vm/` | Virtual machine execution | `VM` |
| `cli` | `cli/` | Command-line interface, prove handler, project config | `DefaultProveHandler`, `AchronymeToml`, `ProjectConfig` |

### Dependency Graph

```
cli → compiler → ir → achronyme-parser
 │       │        │
 │       │        └──→ constraints → memory
 │       │                  ↑
 │       └────────────────────
 └──→ vm → memory
```

## Field Architecture

The entire constraint pipeline is generic over `F: FieldBackend`. One `match` at the CLI
boundary selects the concrete backend; generics carry it through the rest of the pipeline:

```
CLI --prime flag
    │
    ├─ bn254      → circuit_command_inner::<Bn254Fr>(...)
    ├─ bls12-381  → circuit_command_inner::<Bls12_381Fr>(...)
    └─ goldilocks → circuit_command_inner::<GoldilocksFr>(...)
```

| Field | Bit size | Repr | Groth16 | PlonK | Solidity |
|-------|----------|------|---------|-------|----------|
| BN254 | 254 | `[u64;4]` Montgomery | Yes (ark-bn254) | Yes (halo2) | Yes (EVM precompiles) |
| BLS12-381 | 255 | `[u64;4]` Montgomery | Yes (ark-bls12-381) | No | No |
| Goldilocks | 64 | `u64` direct | No (no pairing) | No | No |

ProveIR uses `FieldConst([u8;32])` — field-erased canonical LE bytes — so the serialized
format is non-generic. `FieldElement<F>` is reconstructed at instantiation time via
`FieldConst::to_field::<F>()`. Format version: v5.

## Data Flow: Circuit Compilation

A complete circuit compilation follows these steps:

### 1. Parse

```rust
// achronyme-parser/src/parser/mod.rs
pub fn parse_program(source: &str) -> (Program, Vec<Diagnostic>)
```

Recursive descent parser with Pratt expression parsing. Returns a (possibly partial)
AST plus all collected diagnostics. The parser recovers at statement boundaries,
so a single call can report multiple errors. Handles `public`/`witness` declarations,
`for` ranges, `fn` definitions, `import`/`export`, and `prove {}` blocks.

### 2. Lower to IR

```rust
// ir/src/lower.rs
impl<F: FieldBackend> IrLowering<F> {
    // External inputs specified by caller:
    pub fn lower_circuit(source: &str, public: &[&str], witness: &[&str])
        -> Result<IrProgram<F>, IrError>

    // In-source public/witness declarations:
    pub fn lower_self_contained(source: &str)
        -> Result<(Vec<String>, Vec<String>, IrProgram<F>), IrError>
}
```

Walks the AST and emits SSA instructions. Each `let` binding is an alias (no
instruction). `if/else` becomes `Mux`, `for` is statically unrolled, and `fn`
calls are inlined at each call site with a recursion guard.

### 3. Optimize

```rust
// ir/src/passes/mod.rs
pub fn optimize<F: FieldBackend>(program: &mut IrProgram<F>)
```

Runs three passes in sequence:
- **const_fold** — forward pass, folds arithmetic on known constants, mul-by-zero,
  `x - x → 0`, `x / x → 1`, boolean logic, comparisons
- **dce** — backward pass, removes instructions whose result is unused
  (conservative on side-effecting instructions)
- **bool_prop** — forward pass, computes the set of proven-boolean SSA variables
  (seeds: `Const(0/1)`, comparisons, `RangeCheck(x,1)`, `Assert`, `Bool` annotations;
  propagates through `Not`/`And`/`Or`/`Mux`). Used by backends to skip redundant
  boolean enforcement constraints.

### 4. Compile to R1CS

```rust
// compiler/src/r1cs_backend.rs
impl<F: FieldBackend + PoseidonParamsProvider> R1CSCompiler<F> {
    pub fn compile_ir(&mut self, program: &IrProgram<F>) -> Result<(), R1CSError>

    // Evaluate + compile + build witness in one pass:
    pub fn compile_ir_with_witness(
        &mut self, program: &IrProgram<F>, inputs: &HashMap<String, FieldElement<F>>,
    ) -> Result<Vec<FieldElement<F>>, R1CSError>
}
```

Walks IR instructions and builds a `HashMap<SsaVar, LinearCombination>`.
Add/Sub/Neg are free (linear combination arithmetic). Only `Mul`, `Div`,
`Mux`, `AssertEq`, `PoseidonHash`, and comparison instructions generate
actual R1CS constraints.

### 5. Export

```rust
// constraints/src/export.rs
pub fn write_r1cs<F: FieldBackend>(cs: &ConstraintSystem<F>, prime_id: PrimeId) -> Vec<u8>
pub fn write_wtns<F: FieldBackend>(witness: &[FieldElement<F>], prime_id: PrimeId) -> Vec<u8>
```

Produces binary files directly consumable by `snarkjs r1cs info` and
`snarkjs wtns check`.

## Key Types Reference

### memory

| Type | Description |
|------|-------------|
| `FieldBackend` | Trait: zero-sized marker type carrying all field-specific logic. Impls: `Bn254Fr`, `Bls12_381Fr`, `GoldilocksFr` |
| `FieldElement<F>` | Generic wrapper over `F::Repr`. Montgomery `[u64;4]` for 254/255-bit fields, direct `u64` for Goldilocks |
| `PrimeId` | Runtime enum for field selection at the CLI boundary (`--prime bn254\|bls12-381\|goldilocks`) |
| `Value` | Tagged u64: 4-bit tag + 60-bit payload. No floats — integers are i60 |
| `Heap` | Arena allocator for strings, lists, maps, closures, field elements |

### constraints

| Type | Description |
|------|-------------|
| `Variable(usize)` | Wire reference. `Variable::ONE` = index 0 (constant-1 wire) |
| `LinearCombination<F>` | Sparse `Vec<(Variable, FieldElement<F>)>` — sum of weighted wires |
| `ConstraintSystem<F>` | Collects `A * B = C` constraints, allocates wires, verifies witnesses |
| `PlonkishSystem<F>` | Gate/lookup/copy constraint system for Plonkish arithmetization |

### ir

| Type | Description |
|------|-------------|
| `SsaVar(u32)` | SSA variable — defined exactly once |
| `Instruction` | One of 19 variants: `Const`, `Input`, `Add`, `Sub`, `Mul`, `Div`, `Neg`, `Mux`, `AssertEq`, `PoseidonHash`, `RangeCheck`, `Not`, `And`, `Or`, `IsEq`, `IsNeq`, `IsLt`, `IsLe`, `Assert` |
| `IrProgram<F>` | Flat list of instructions + variable name map. `Const` embeds `FieldElement<F>` |
| `IrLowering<F>` | AST→IR converter with environment, function table, call stack |
| `FieldConst` | Field-erased `[u8;32]` constant in ProveIR. Reconstructed to `FieldElement<F>` at instantiation |

### compiler

| Type | Description |
|------|-------------|
| `R1CSCompiler<F>` | IR→R1CS: maps `SsaVar` to `LinearCombination<F>`, emits constraints |
| `PlonkishCompiler<F>` | IR→Plonkish: deferred add/sub, cell-based with arith rows |
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

## Diagnostic Pipeline

All compilation phases produce errors and warnings through a unified `Diagnostic` type
defined in `achronyme-parser/src/diagnostic.rs`. This ensures consistent formatting
regardless of where an error originates.

### Types

```
achronyme-parser/src/diagnostic.rs
├── SpanRange          Byte-range span with line/col start and end
├── Severity           Error | Warning | Note | Help
├── Label              Secondary span with message
├── Suggestion         Code replacement (span + replacement text + message)
└── Diagnostic         The unified diagnostic (severity, message, code, primary_span, labels, suggestions, notes)
```

`Diagnostic` uses a builder pattern:

```rust
Diagnostic::error("undefined variable: `x`", span)
    .with_code("E001")
    .with_label(other_span, "defined here")
    .with_suggestion(span, "y", "did you mean `y`?")
    .with_note("variables must be declared before use")
```

### Error → Diagnostic Conversion

Each crate's error type implements a `to_diagnostic()` method:

| Error Type | Crate | Conversion |
|------------|-------|------------|
| `ParseError` | `achronyme-parser` | Already a `Diagnostic` (parser emits diagnostics directly) |
| `CompilerError` | `compiler` | `to_diagnostic()` — extracts `OptSpan` from each variant |
| `CompilerError::DiagnosticError` | `compiler` | Passthrough — already wraps a `Box<Diagnostic>` |
| `IrError` | `ir` | `to_diagnostic()` — `ParseError` variant wraps `Box<Diagnostic>` directly |

### Rendering

```
achronyme-parser/src/render.rs
├── ColorMode          Always | Never | Auto (TTY detection via isatty(2))
└── DiagnosticRenderer Renders source snippets with margin, line numbers, underline carets
```

The `DiagnosticRenderer` produces rustc-style output:

```
error[E001]: type mismatch
 --> 3:5
  |
3 |     let x: u32 = "hello"
  |                   ^^^^^^^
  |
  = note: expected u32, found string
```

Features:
- Single-line and multi-line span rendering
- Secondary labels at related locations
- Footer lines for notes (`= note:`) and suggestions (`= help:`)
- ANSI color codes gated on `ColorMode` (auto-detects TTY)

### Output Formats (CLI)

The CLI (`cli/src/commands/mod.rs`) supports three output formats via `--error-format`:

| Format | Function | Output |
|--------|----------|--------|
| `human` | `DiagnosticRenderer::render()` | Source snippets with colors |
| `json` | `diagnostic_to_json()` | JSON Lines — one object per diagnostic |
| `short` | `diagnostic_to_short()` | `file:line:col: severity: message` |

`ErrorFormat` is threaded through all CLI commands (`run`, `compile`, `circuit`, `disassemble`).

### Compiler Warnings

The bytecode compiler (`compiler/src/codegen.rs`) collects warnings in a `Vec<Diagnostic>`.
They are emitted after successful compilation via `Compiler::take_warnings()`.

| Code | Warning | Emitted by |
|------|---------|------------|
| W001 | Unused variable | `scopes.rs` (end_scope) and `functions.rs` (function params) |
| W002 | Variable declared `mut` but never mutated | `scopes.rs` (end_scope) |
| W003 | Unreachable code after `return` | `control_flow.rs` and `codegen.rs` |
| W004 | Variable shadows previous binding in same scope | `statements/declarations.rs` |

Variables prefixed with `_` are exempt from W001.

### "Did You Mean?" Suggestions

When an undefined variable is encountered (`codegen.rs:undefined_var_error`):

1. `collect_in_scope_names()` gathers all locals (from current function compiler) and globals
2. `suggest::find_similar()` computes Levenshtein distance against each candidate
3. Threshold: max distance 2, but scaled down to 1 for names ≤ 3 characters
4. Exact matches and `_`-prefixed names are excluded
5. If a match is found, it's attached as a `Suggestion` on the `Diagnostic`

Source: `compiler/src/suggest.rs`

### Error Recovery (Parser)

`parse_program()` returns `(Program, Vec<Diagnostic>)` — a possibly-partial AST plus all
collected errors. The parser synchronizes at statement boundaries after encountering an error,
allowing it to report multiple problems in a single pass. Failed regions appear as `Stmt::Error`
nodes in the AST.

### Adding a New Warning

1. Choose the next available code (`W005`, etc.)
2. Build a `Diagnostic::warning(message, span).with_code("W005")` at the detection point
3. Call `self.emit_warning(diag)` on the `Compiler`
4. Warnings are collected in `self.warnings` and retrieved via `take_warnings()`
5. Document the new code in `docs/src/content/docs/language/diagnostics.mdx`

### Adding a New Error Format

1. Add a variant to `ErrorFormat` in `cli/src/commands/mod.rs`
2. Handle the new variant in `render_diagnostic()`
3. Update `parse_error_format()` in `cli/src/main.rs` to accept the new string
4. Update the `--error-format` help text in `cli/src/args.rs`

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

## Project Configuration (`achronyme.toml`)

Source: `cli/src/config.rs`, `cli/src/init.rs`

### Schema

```toml
[project]
name = "my-circuit"           # Required. [a-zA-Z_][a-zA-Z0-9_-]*
version = "0.1.0"             # Required. SemVer
description = ""              # Optional
license = ""                  # Optional. SPDX identifier
authors = []                  # Optional
entry = "src/main.ach"        # Optional. Default entry file

[build]
backend = "r1cs"              # "r1cs" | "plonkish"
optimize = true               # Inverse of --no-optimize
error_format = "human"        # "human" | "json" | "short"

[build.output]
r1cs = "build/circuit.r1cs"
wtns = "build/witness.wtns"
binary = "build/{name}.achb"  # {name} resolved from project.name
solidity = ""
plonkish_json = ""

[vm]
max_heap = ""                 # "256M", "1G", etc.
stress_gc = false
gc_stats = false

[circuit]
prime = "bn254"               # "bn254" | "bls12-381" | "goldilocks"
public = []                   # ["x", "y"]
witness = []                  # ["w"]
```

### Resolution Flow

```
CLI flags (explicit)  >  achronyme.toml values  >  hardcoded defaults
```

1. `find_project_toml()` walks up from the input file's directory (or CWD)
2. `load_toml()` parses + validates (`deny_unknown_fields`)
3. `resolve_config()` merges `CliOverrides` + `AchronymeToml` + defaults into `ProjectConfig`
4. `main.rs` dispatches commands using the resolved config

`--no-config` global flag disables toml loading entirely.

### `ach init <name>`

Creates a project scaffold:

```
<name>/
├── achronyme.toml
├── src/
│   └── main.ach
└── .gitignore
```

Templates: `--template circuit` (default), `--template vm`, `--template prove`
