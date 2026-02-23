# Achronyme

[![CI](https://github.com/achronyme/achronyme/actions/workflows/ci.yml/badge.svg)](https://github.com/achronyme/achronyme/actions/workflows/ci.yml)
[![Deploy Docs](https://github.com/achronyme/achronyme/actions/workflows/docs.yml/badge.svg)](https://github.com/achronyme/achronyme/actions/workflows/docs.yml)

A programming language for zero-knowledge circuits.

Write readable code. Decide what gets proven. Same language for general execution and ZK circuit compilation.

```
cargo build --release
cargo test --workspace     # 718 unit tests
bash test/run_tests.sh     # 54 integration tests
```

---

## Quick Look

### General-purpose execution

```achronyme
let make_counter = fn(init) {
    mut n = init
    return fn() { n = n + 1; return n }
}
let c = make_counter(0)
print(c())  // 1
print(c())  // 2
```

### ZK circuit

```achronyme
public root
witness leaf
witness path[3]
witness indices[3]

merkle_verify(root, leaf, path, indices)
```

```bash
ach circuit merkle.ach --inputs "root=...,leaf=42,path_0=...,path_1=...,path_2=...,indices_0=0,indices_1=1,indices_2=0"
# → circuit.r1cs + witness.wtns (snarkjs-compatible)
```

### Inline proof generation

```achronyme
let secret = field(42)
let hash = field("17159...")  // poseidon(42, 0)

let p = prove {
    witness secret
    public hash
    assert_eq(poseidon(secret, 0), hash)
}

print(proof_json(p))  // Groth16 proof, verifiable on-chain
```

---

## How It Works

Achronyme has two execution modes from the same source:

**VM mode** (`ach run`) — Full language: closures, recursion, GC, arrays, maps, strings, I/O. Code runs like any scripting language.

**Circuit mode** (`ach circuit`) — Compiles to arithmetic constraints over BN254. No loops at runtime, no I/O — everything is unrolled and flattened into a constraint system for zero-knowledge proofs.

The `prove {}` block bridges both: it runs inside the VM, compiles its body as a circuit, generates a witness from captured variables, and produces a cryptographic proof — all in one expression.

```
Source (.ach)
    │
    ├─► Parser (PEG) → AST
    │       │
    │       ├─► Bytecode → VM          (run mode)
    │       │
    │       └─► SSA IR → Optimize
    │               │
    │           ┌───┴───┐
    │           ▼       ▼
    │        R1CS    Plonkish
    │      (Groth16) (KZG-PlonK)
    │           │       │
    │           ▼       ▼
    │       .r1cs    Gates/Lookups
    │       .wtns    Copy constraints
    │           │       │
    │           └───┬───┘
    │               ▼
    │         Native proof
    │
    └─► prove { } → compile + witness + verify + proof (inline)
```

---

## Language

### Types

| Type | Examples |
|------|---------|
| Int | `42`, `-7` |
| Bool | `true`, `false` |
| String | `"hello"` |
| List | `[1, 2, 3]` |
| Map | `{"a": 1, "b": 2}` |
| Field | `field(42)`, `field("0x2a")` |
| Function | `fn(x) { x + 1 }` |
| Proof | result of `prove { }` |
| Nil | `nil` |

### Control Flow

```achronyme
if x > 0 { print("positive") } else { print("non-positive") }

while n > 0 { n = n - 1 }

for item in list { print(item) }

for i in 0..10 { print(i) }
```

### Functions and Closures

```achronyme
let add = fn(a, b) { a + b }

let fib = fn fib(n) {
    if n < 2 { return n }
    return fib(n - 1) + fib(n - 2)
}

// Closures capture environment
let make_adder = fn(x) { fn(y) { x + y } }
let add5 = make_adder(5)
print(add5(3))  // 8
```

### Field Elements

BN254 scalar field. Montgomery form internally, decimal/hex input.

```achronyme
let a = field(42)
let b = field("0xFF")
let c = field("21888242871839275222246405745257275088548364400416034343698204186575808495617")

let sum = a + b
let prod = a * b
let inv = field(1) / a
```

---

## Circuit Features

### Declarations

```achronyme
public output          // public input (instance)
witness secret         // private input (witness)
witness arr[4]         // witness array (arr_0, arr_1, arr_2, arr_3)
```

### Builtins

| Builtin | Description | R1CS cost | Plonkish cost |
|---------|-------------|-----------|---------------|
| `assert_eq(a, b)` | Enforce equality | 1 | 1 |
| `assert(expr)` | Enforce boolean true | 2 | 2 |
| `poseidon(a, b)` | Poseidon 2-to-1 hash | 361 | 361 |
| `poseidon_many(a, b, c, ...)` | Left-fold Poseidon | 361*(n-1) | 361*(n-1) |
| `mux(cond, a, b)` | Conditional select | 2 | 1 |
| `range_check(x, bits)` | Value fits in N bits | bits+1 | 1 (lookup) |
| `merkle_verify(root, leaf, path, indices)` | Merkle membership proof | ~1090/level | ~1090/level |
| `len(arr)` | Compile-time array length | 0 | 0 |

### Operators in Circuits

| Operation | R1CS | Plonkish |
|-----------|------|----------|
| `+`, `-` | 0 | 0 |
| `*` | 1 | 1 |
| `/` | 2 | 2 |
| `^` (constant exp) | O(log n) | O(log n) |
| `==`, `!=` | 2 | 2 |
| `<`, `<=`, `>`, `>=` | ~760 | ~760 |
| `&&`, `\|\|` | 3 | 3 |
| `!` | 1 | 1 |

### Functions in Circuits

Functions are inlined at each call site. No dynamic dispatch, no recursion.

```achronyme
witness a, b
public out

fn hash_pair(x, y) { poseidon(x, y) }

assert_eq(hash_pair(a, b), out)
```

### Control Flow in Circuits

`if/else` compiles to `mux` (both branches are evaluated). `for` loops are statically unrolled. `while`, `break`, `continue` are rejected at compile time.

```achronyme
witness vals[4]
public total

let sum = vals[0]
let sum = sum + vals[1]
let sum = sum + vals[2]
let sum = sum + vals[3]
assert_eq(sum, total)
```

---

## CLI

```bash
# Run a program
ach run script.ach

# Run with PlonK prove backend
ach run script.ach --prove-backend plonkish

# Compile circuit (in-source declarations)
ach circuit circuit.ach --inputs "x=42,y=7"

# Compile circuit (CLI declarations)
ach circuit circuit.ach --public "out" --witness "a,b" --inputs "out=42,a=6,b=7"

# Plonkish backend
ach circuit circuit.ach --backend plonkish --inputs "x=42,y=7"

# Generate Plonkish proof
ach circuit circuit.ach --backend plonkish --inputs "x=42" --prove

# Compile to bytecode
ach compile script.ach --output script.achb

# Disassemble
ach disassemble script.ach
```

Output `.r1cs` and `.wtns` files are compatible with snarkjs:

```bash
snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit.zkey
snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```

---

## Prove Blocks

`prove {}` compiles a circuit, captures variables from the enclosing scope, generates a witness, and returns a proof — all inline.

```achronyme
let a = field(6)
let b = field(7)
let product = field(42)

let p = prove {
    witness a
    witness b
    public product
    assert_eq(a * b, product)
}
```

Variable names inside `public`/`witness` declarations must match `let` bindings in the outer scope. Integer values are automatically promoted to field elements.

The result is a `Proof` object (Groth16 or PlonK depending on `--prove-backend`). Extract components with `proof_json(p)`, `proof_public(p)`, `proof_vkey(p)`.

If no proving backend is available, the block still compiles the circuit, generates the witness, and verifies constraints locally (returns `nil`).

---

## Optimization Passes

The SSA IR runs four optimization passes before constraint generation:

- **Constant folding** — Evaluates arithmetic on known constants at compile time
- **Dead code elimination** — Removes unused instructions
- **Boolean propagation** — Tracks proven-boolean variables, skips redundant enforcement
- **Taint analysis** — Warns about under-constrained or unused inputs

Disable with `--no-optimize`.

---

## Project Structure

```
achronyme/
├── achronyme-parser/   PEG grammar (pest), AST types, parser
├── ir/                 SSA intermediate representation, optimization passes
├── compiler/           Bytecode compiler, R1CS backend, Plonkish backend
├── vm/                 Register-based VM (61 opcodes, tagged values)
├── memory/             Heap, GC, FieldElement (BN254 Montgomery)
├── constraints/        R1CS/Plonkish systems, Poseidon hash, binary export
├── cli/                CLI, native Groth16 (ark-groth16) & PlonK (halo2-KZG)
└── test/
    ├── vm/             41 VM/interpreter tests (closures, algorithms, stress)
    ├── circuit/        8 circuit compilation tests
    ├── prove/          3 prove block tests
    └── run_tests.sh    Integration test runner
```

---

## Status

- 718 unit tests + 54 integration tests
- 2 ZK backends: R1CS/Groth16 + Plonkish/KZG-PlonK
- Native in-process proof generation (no external tools)
- snarkjs-compatible binary export
- 3 security audits resolved
- Poseidon hash compatible with circomlibjs

## License

GPL-3.0
