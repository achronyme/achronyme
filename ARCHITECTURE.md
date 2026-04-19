# Architecture

Achronyme is a programming language for zero-knowledge circuits.
It compiles source code into R1CS or Plonkish constraint systems over a configurable
prime field (BN254, BLS12-381, or Goldilocks), producing outputs compatible with
snarkjs for Groth16 proof generation, or native PlonK proofs via halo2.

Alongside the native `.ach` language, Achronyme consumes `.circom` files in two
modes: as a **full circuit** (via `import circuit "x.circom" as C`) or as a
**template library** whose templates are called from `.ach` code both inside
`prove {}` / `circuit` blocks and in regular VM mode. The Circom Interop section
below covers the dispatch architecture, the dependency-cycle break, and the
scope limitations of the current (beta.20) implementation.

## Pipeline

```
Source (.ach)                    Source (.circom)
    │                                │
    ▼                                ▼
┌──────────┐  parse_program()   ┌──────────┐  parse_circom()
│  Parser  │  achronyme-parser  │  Circom  │  circom/src/parser
└────┬─────┘                    │  Parser  │
     │  Program (AST)           └────┬─────┘
     │                               │  CircomProgram (AST)
     │                               ▼
     │                          ┌──────────┐  check_constraints()
     │                          │ Analysis │  circom/src/analysis
     │                          └────┬─────┘  (<-- without === = error)
     │                               │
     │                               ▼
     │                          ┌──────────┐  lower_template()
     │                          │ Lowering │  circom/src/lowering
     │                          └────┬─────┘
     ▼                               │
┌──────────┐  IrLowering             │
│ IR Lower │  ir/src/lower.rs        │  ProveIR
└────┬─────┘                         │
     │  IrProgram (SSA)              ▼
     │◄──────────────────── instantiate()
     ▼
┌──────────┐    optimize()
│  Passes  │    ir/src/passes/mod.rs
└────┬─────┘
     ▼
┌──────────┐    R1CSCompiler / PlonkishCompiler
│ Backend  │    compiler/src/
└────┬─────┘
     │  ConstraintSystem
     ▼
┌──────────┐    write_r1cs() / write_wtns() / prove()
│  Export  │    constraints/ + proving/
└──────────┘
```

## Crate Map

| Crate | Path | Purpose | Key Types |
|-------|------|---------|-----------|
| `diagnostics` | `diagnostics/` | Shared diagnostic infrastructure (zero deps) | `Span`, `Diagnostic`, `SpanRange`, `DiagnosticRenderer` |
| `memory` | `memory/` | Generic field arithmetic (`F: FieldBackend`), tagged values, heap/GC | `FieldElement<F>`, `FieldBackend`, `Value`, `Heap` |
| `achronyme-parser` | `achronyme-parser/` | Recursive descent parser, AST types | `Program`, `Stmt`, `Expr`, `Block` |
| `constraints` | `constraints/` | R1CS + Plonkish constraint systems, export | `ConstraintSystem`, `Variable`, `LinearCombination`, `PlonkishSystem` |
| `ir` | `ir/` | SSA intermediate representation, lowering, optimization; also hosts `prove_ir::circom_interop` (trait-only surface for circom dispatch) | `IrProgram`, `SsaVar`, `Instruction`, `IrLowering`, `CircomLibraryHandle`, `CircomCallable` |
| `compiler` | `compiler/` | Bytecode compiler + ZK backends + compile-time circom handle/library registries | `R1CSCompiler`, `PlonkishCompiler`, `Compiler`, `CircomHandleInterner`, `CircomLibraryRegistry` |
| `akron` | `akron/` | General-purpose bytecode VM (tagged values, GC) + `CallCircomTemplate` opcode dispatcher | `VM`, `CircomWitnessHandler`, `CircomCallResult` |
| `artik` | `artik/` | Dedicated witness-computation VM: register-based, Artik bytecode, executed at prove time for lifted circom functions | `ArtikContext`, `ArtikError`, `Program`, `execute` |
| `proving` | `proving/` | Groth16 (arkworks), PlonK (halo2-KZG), Solidity verifier | `groth16_prove`, `halo2_prove` |
| `achronyme-std` | `std/` | Standard library via `NativeModule` trait | `StdModule` |
| `ach-macros` | `ach-macros/` | Proc-macros: `#[ach_native]`, `#[ach_module]` | — |
| `circom` | `circom/` | Circom 2.x frontend: lexer, parser, analysis, ProveIR lowering, library-mode template API | `parse_circom`, `lower_template`, `compile_template_library`, `instantiate_template_into`, `evaluate_template_witness` |
| `cli` | `cli/` | Command-line interface, prove handler, circom witness handler, project config | `DefaultProveHandler`, `DefaultCircomWitnessHandler`, `AchronymeToml`, `ProjectConfig` |

### Dependency Graph

```
diagnostics (zero deps)
  │
  ├──→ achronyme-parser
  │         │
  ├──→ ir ──┘──→ memory, constraints
  │    │
  ├──→ circom ──→ ir
  │
  └──→ compiler → ir, achronyme-parser, memory, constraints, artik
          │
          └──→ cli → compiler, akron, proving
                      │
                      └──→ akron → memory
                      └──→ artik → memory   (witness-computation VM, side-channel
                                             via ir::Instruction::WitnessCall)
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

## Circom Interop

Achronyme consumes `.circom` files in two independent modes:

| Mode | Syntax | Entry point | Runtime path |
|------|--------|-------------|--------------|
| **Full circuit import** | `import circuit "x.circom" as C` | `circom::compile_file` | Serialized into ProveIR bytes, bound as an `.ach` global — same runtime path as a hand-written `circuit` declaration |
| **Library template import** | `import { T } from "x.circom"` / `import "x.circom" as P` | `circom::compile_template_library` | Each `T(params)(inputs)` call dispatches through a trait object at compile time (circuit mode) or a VM opcode (VM mode) |

The full-circuit path requires a `component main` in the `.circom` file — it's a one-shot compilation into a complete ProveIR template. The library path skips `component main` and keeps the circom AST around so individual templates can be instantiated on demand. Both modes are exclusive at the file level: a single `.circom` file is consumed *either* as a circuit *or* as a library.

### The dependency-cycle problem

`circom` already depends on `ir` to reuse `CircuitExpr` / `CircuitNode` / `FieldConst`, so `ir` cannot reach back into `circom` without creating a cycle. The dispatcher has to work in both directions — `ir::prove_ir::compiler::ProveIrCompiler` needs to instantiate circom templates at compile time, and the `akron` crate (which sits below `circom` too) needs to invoke witness evaluation at run time.

Both problems are solved the same way: define a trait in the lower crate, implement it in `circom`, and let the crate above both wire up the trait object.

```
circom  →  ir  →  memory             (ir defines CircomLibraryHandle,
    │                                 circom impls it on CircomLibrary)
    ↓
akron  →  memory                     (akron defines CircomWitnessHandler,
    │                                 cli impls it with Arc<CircomLibrary>)
    ↓
compiler  →  ir, akron, circom       (compiler wires both sides together)
    ↓
cli  →  compiler                     (cli injects the concrete handler at run time)
```

### Circuit mode dispatch (Phase 3)

When a `prove {}` or `circuit` block calls a circom template, the `ProveIrCompiler` resolves the call through an in-memory `circom_table: HashMap<String, CircomCallable>` seeded from the parent compiler's circom imports at entry.

**Key types** (`ir/src/prove_ir/circom_interop.rs`):

- `CircomLibraryHandle` — dyn-safe trait with three methods: `template_signature`, `template_names`, `instantiate_template`. Send + Sync for future parallel compilation.
- `CircomCallable { library: Arc<dyn CircomLibraryHandle>, template_name: String }` — one entry per dispatch key. Selective imports key by bare template name (`"Poseidon"`), namespace imports pre-flatten to `"P::T"` form so the call-site lookup stays a single `HashMap::get`.
- `CircomInstantiation { body: Vec<CircuitNode>, outputs: HashMap<String, CircomTemplateOutput> }` — what a successful instantiation returns. The dispatcher appends the body to the current prove-block body and stores the outputs under dotted env keys so `r.out_i` DotAccess resolves.
- `CircomDispatchError` — failure reasons (unknown template, param count mismatch, missing signal input, array input unsupported, lowering failed).

**Implementation** (`circom/src/library/handle.rs`): `impl CircomLibraryHandle for CircomLibrary` delegates every method to the existing library API. `template_signature` projects out the cached `CircomTemplateEntry`; `instantiate_template` wraps `instantiate_template_into` and converts `TemplateOutput` / `InstantiationError` into the ir-local shapes.

**Seeding** (`compiler/src/statements/circom_imports.rs::build_circom_imports_for_outer_scope`): flattens `compiler.circom_template_aliases` (selective imports) and `compiler.circom_namespaces` (namespace imports) into the flat `HashMap<String, CircomCallable>` that `OuterScope.circom_imports` carries into the ProveIR compiler.

**Call-site resolution** (`ir/src/prove_ir/compiler.rs::compile_call`): the dispatcher pattern-matches on `Call { callee: Call { callee: Ident(T) | Ident(P).field, args: template_args }, args: signal_inputs }`, looks up the key in `circom_table`, evaluates template args to `CircuitExpr::Const` (rejecting runtime values), maps signal inputs by declared name, allocates a fresh `circom_call_N` prefix, and calls `instantiate_template`. The returned body is appended to `self.body`; outputs bind under `"<let_name>.<output_name>"` env keys for single-scalar templates and `"<let_name>.<output_name>_<i>"` for array outputs. `compile_dot_access` checks these dotted keys alongside the existing `module::field` namespace constants.

**Diagnostics** (Phase 3.5): `ProveIrError::CircomDispatch { kind, span }` with 11 specific kinds — `NamespaceNotFound`, `TemplateNotFoundInNamespace`, `TemplateNotFoundSelective`, `MissingTemplateParams`, `NotAtomic`, `ParamCountMismatch`, `SignalInputCountMismatch`, `TemplateArgNotConst`, `ArrayInputUnsupported`, `ArrayOutputRequiresIndex`, `LoweringFailed`. Unresolved names carry Levenshtein `did_you_mean` suggestions scoped to the compiler's registered templates / namespaces.

### VM mode dispatch (Phase 4)

Outside `prove {}` / `circuit` blocks, circom template calls compile to a dedicated VM opcode so the template runs as ordinary witness code. The whole pipeline — opcode, tag, heap object, trait, handler — is deliberately parallel to the existing `Prove` opcode and `prove_handler` machinery so the injection pattern stays uniform.

**Value tag + heap object** (`memory/src/value.rs`, `memory/src/heap.rs`):

```rust
pub const TAG_CIRCOM_HANDLE: u64 = 15; // last of the 16 tag slots

pub struct CircomHandle {
    pub library_id: u32,       // index into the handler's library registry
    pub template_name: String, // resolved template name on that library
    pub template_args: Vec<u64>, // pre-evaluated compile-time template params
}
```

`CircomHandle` is a leaf GC object (no nested Values). The compiler allocates one per call site via `CircomHandleInterner`, intern-style; the bytecode loader bulk-imports the vec into the heap's `circom_handles` arena at program-load time with `Heap::import_circom_handles`, mirroring `import_bytes`.

**Opcode** (`vm/src/opcode.rs::CallCircomTemplate = 162`, ABC encoding):

```
R[A] = CircomCall(R[B-1] as handle, R[B..B+C] as inputs)
       │             │                │
       │             │                └── C = input count
       │             └────── B = first signal input register
       │                     (handle Value lives at R[B-1],
       │                      same slot convention MethodCall uses
       │                      for its method-name register)
       └────── A = destination register for the projected result:
                   scalar output  → Value::field
                   array output   → Value::list of fields
                   multi-output   → Value::map keyed by output name
```

The compiler always loads the handle with a preceding `LoadConst`, then compiles each signal input into the next contiguous register slot. This reuses the exact register-layout convention `compile_method_call` already uses and avoids introducing a new opcode format.

**Handler trait + dispatcher** (`vm/src/machine/circom.rs`):

```rust
pub trait CircomWitnessHandler: Send + Sync {
    fn invoke(
        &self,
        handle: &CircomHandle,
        signal_inputs: &[FieldElement],
    ) -> Result<CircomCallResult, CircomCallError>;
}

pub struct VM {
    // ...
    pub circom_handler: Option<Box<dyn CircomWitnessHandler>>,
}
```

`VM::handle_call_circom_template` reads `R[B-1]` as a `TAG_CIRCOM_HANDLE`, pulls the heap object, marshals `R[B..B+C]` into `FieldElement` values via the existing `prove::value_to_field_element` helper, calls `circom_handler.invoke`, and projects the returned `CircomCallResult` into a single `Value` via `marshal_outputs_to_value` / `alloc_field_list`.

`CircomCallError` variants: `HandlerNotConfigured`, `UnknownLibraryId`, `InvalidSignalInput`, `WitnessEvaluation`, `OutputMarshalling`. The opcode maps all of them through `RuntimeError::CircomHandlerNotConfigured` (for the `None` case) or `resource_limit_exceeded` (for runtime failures) so the CLI error renderer handles them uniformly.

**Compiler-side emission** (`compiler/src/statements/circom_imports.rs::CircomVmCallEmitter`):

- `try_resolve_circom_vm_call(inner_callee)` — same resolution logic as the ProveIR dispatcher but against `compiler.circom_template_aliases` and `compiler.circom_namespaces` directly (no `OuterScope` indirection needed — we're still in the bytecode compiler's own state).
- `compile_circom_vm_call(library, template_name, template_args, signal_inputs)` — validates arity, parses each template arg as a compile-time integer literal (Phase 4 limitation; runtime/computed params deferred), interns the `Arc<CircomLibrary>` into `compiler.circom_library_registry` to get a `library_id`, builds the `CircomHandle`, interns it via `CircomHandleInterner`, and emits the register sequence described above. Called from `expressions/mod.rs::compile_call` via a short-circuit pre-dispatch that runs before the normal method-call / function-call match.

**Run-time wiring** (`cli/src/circom_handler.rs::DefaultCircomWitnessHandler`): owns the `Vec<Arc<CircomLibrary>>` drained from `compiler.circom_library_registry.take_libraries()` and installs itself into `vm.circom_handler` before `vm.interpret()` — same pattern as `DefaultProveHandler`. The `invoke` impl looks up the library by `handle.library_id`, maps positional signal inputs onto the template's declared input-signal names, calls `circom::evaluate_template_witness::<Bn254Fr>` with `handle.template_args`, and converts `TemplateOutputValue` → `CircomOutputValue` before returning.

### Data flow: `let h = P.Square()(0p5)` in VM mode

```
.ach source                                        Run-time VM state
    │                                                  │
    ▼                                                  │
Parser → Call{Call{DotAccess(P, Square), []}, [0p5]}   │
    │                                                  │
    ▼  compiler::expressions::compile_call             │
try_resolve_circom_vm_call(DotAccess(P, Square))       │
    → (Arc<Library>, "Square")                         │
    │                                                  │
    ▼  compile_circom_vm_call                          │
register_circom_library(arc)              ─→  compiler.circom_library_registry
    → library_id = 0                                   │
CircomHandle{ library_id: 0, template_name: "Square",  │
              template_args: [] }                      │
    │                                                  │
intern_circom_handle(handle)              ─→  compiler.circom_handle_interner[0]
    → handle_idx = 0                                   │
add_constant(Value::circom_handle(0))                  │
    → const_idx = K                                    │
    │                                                  │
emit LoadConst r2, K                                   │
emit compile_expr(0p5)         → lands in r3           │
emit CallCircomTemplate A=2, B=3, C=1                  │
    │                                                  │
    ▼  cli::run_file                                   │
compiler.bytes_interner → vm.heap                      │
compiler.circom_handle_interner  ─→  vm.heap.import_circom_handles(…)
compiler.circom_library_registry ─→  DefaultCircomWitnessHandler::new(…)
                                 ─→  vm.circom_handler = Some(handler)
    │                                                  │
    ▼  vm.interpret() — hits CallCircomTemplate        │
handle = vm.heap.get_circom_handle(0)                  │
inputs = [vm.heap.get_field(R[3])]  ←─ 0p5 materialized│
handler.invoke(&handle, &inputs)                       │
    │                                                  │
    ▼  DefaultCircomWitnessHandler                     │
library = self.libraries[0]                            │
evaluate_template_witness::<Bn254Fr>(library, "Square",│
                                      [], {"x": 0p5}) │
    → {"y": Scalar(0p25)}                              │
    │                                                  │
    ▼  marshal_outputs_to_value                        │
Value::field(heap.alloc_field(0p25))                   │
    │                                                  │
    ▼  set_reg(base, A=2, result)                      │
R[2] now holds 0p25                                    │
```

The same dispatch works for array outputs (marshalled to `Value::list`) and multi-output templates (marshalled to `Value::map` keyed by declared output-signal name).

### Scope limitations (beta.20)

- Cross-process persistence is out of scope — the `.achb` bytecode format does not serialize circom handles or library source paths. `ach compile` + later `ach run file.achb` will not carry circom state. In-process `ach run file.ach` is the MVP target.
- VM-mode template parameters must be integer literals at the call site. Compile-time constant folding of expressions like `let n = 4; Num2Bits(n)(...)` is deferred — the compiler emits a "template argument must be an integer literal" error today.
- Array-valued signal inputs are not supported in either mode — the library-mode inliner rejects them and the VM handler surfaces the same error.
- The VM is single-field (BN254). Cross-field circom imports in VM mode require the generic-VM work tracked for beta.21+.



All compilation phases produce errors and warnings through a unified `Diagnostic` type
defined in the standalone `diagnostics` crate (zero external dependencies). This crate is
shared by all frontends (`achronyme-parser`, `circom`, future `noir`) and by `ir` for
lowering/optimization errors.

### Types

```
diagnostics/src/
├── span.rs            Span (byte range + line/col)
├── diagnostic.rs      SpanRange, Severity, Label, Suggestion, Diagnostic
├── error.rs           ParseError (with Display, Error, From<ParseError> for Diagnostic)
└── render.rs          DiagnosticRenderer, ColorMode, atty_stderr()
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
diagnostics/src/render.rs
├── ColorMode          Always | Never | Auto (TTY detection via isatty(2))
└── DiagnosticRenderer Renders source snippets with margin, line numbers, underline carets
```

Note: `achronyme-parser` re-exports all types from `diagnostics` for backward
compatibility. New code should import directly from `diagnostics`.

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

### Adding a new circom dispatch error

1. Extend `CircomDispatchErrorKind` in `ir/src/prove_ir/error.rs` with the new variant
2. Add a `Display` impl arm carrying the user-facing message
3. Emit `ProveIrError::CircomDispatch { kind: NewVariant { .. }, span }` at the detection site
4. Pin the new variant in `prove_ir::compiler::tests::circom_dispatch` with a `matches!` assertion
5. If the new variant needs a "did you mean?" suggestion, route through `crate::suggest::find_similar_ir` with a scoped candidate iterator (templates in a namespace, all selective aliases, etc.)

### Extending the VM-mode circom handler

The runtime-side dispatch lives in `cli/src/circom_handler.rs::DefaultCircomWitnessHandler`. To support a new circom feature at runtime:

1. Update `CircomHandle` in `memory/src/heap.rs` if the opcode needs new per-call state
2. Update `CircomCallResult` / `CircomOutputValue` in `vm/src/machine/circom.rs` if the return shape changes
3. Update `DefaultCircomWitnessHandler::invoke` to handle the new case
4. If marshalling into a `Value` needs a new shape, update `marshal_outputs_to_value` in `vm/src/machine/circom.rs`
5. Mirror the compile-time side in `compiler/src/statements/circom_imports.rs::compile_circom_vm_call` so the opcode gets emitted with the right operands
6. Add an end-to-end test in `cli/tests/circom_vm_mode_test.rs` that drives a real `.circom` file through `cli::commands::run::run_file`

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
