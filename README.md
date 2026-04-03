# Achronyme

[![CI](https://github.com/achronyme/achronyme/actions/workflows/ci.yml/badge.svg)](https://github.com/achronyme/achronyme/actions/workflows/ci.yml)

A programming language for zero-knowledge circuits.

Write readable code. Decide what gets proven. Same language for general execution and ZK circuit compilation.

## Install

```bash
curl -fsSL https://achrony.me/install.sh | sh
```

This installs the `ach` binary to `~/.local/bin`. Requires Linux or macOS (x86_64 or aarch64).

### Build from source

```bash
git clone https://github.com/achronyme/achronyme.git
cd achronyme
cargo build --release
cargo test --workspace     # 2,700+ unit tests
bash test/run_tests.sh     # 162 integration tests
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
circuit merkle(root: Public, leaf: Witness, path: Witness Field[3], indices: Witness Field[3]) {
    merkle_verify(root, leaf, path, indices)
}
```

```bash
ach circuit merkle.ach --inputs "root=...,leaf=42,path_0=...,path_1=...,path_2=...,indices_0=0,indices_1=1,indices_2=0"
# → circuit.r1cs + witness.wtns (snarkjs-compatible)
```

### Inline proof generation

```achronyme
let secret = 0p42
let hash = 0p17159...  // poseidon(42, 0)

let p = prove(hash: Public) {
    assert_eq(poseidon(secret, 0), hash)
}

print(proof_json(p))  // Groth16 proof, verifiable on-chain
```

---

## How It Works

Achronyme has two execution modes from the same source:

**VM mode** (`ach run`) — Full language: closures, recursion, GC, arrays, maps, strings, I/O. Code runs like any scripting language.

**Circuit mode** (`ach circuit`) — Compiles to arithmetic constraints over a configurable prime field (BN254, BLS12-381, or Goldilocks). No loops at runtime, no I/O — everything is unrolled and flattened into a constraint system for zero-knowledge proofs. Select the field with `--prime bn254|bls12-381|goldilocks`.

The `prove {}` block bridges both: it runs inside the VM, compiles its body as a circuit, generates a witness from captured variables, and produces a cryptographic proof — all in one expression.

```
Source (.ach)
    │
    ├─► Parser (Pratt) → AST
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
| Field | `0p42`, `0pxFF`, `0pb1010` |
| BigInt256 | `0i256xFF`, `0i256d42` |
| BigInt512 | `0i512xFF`, `0i512d100` |
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

Prime field elements (BN254 by default, configurable via `--prime`). Created with the `0p` prefix:

```achronyme
let a = 0p42
let b = 0pxFF
let c = 0pb1010

let sum = a + b
let prod = a * b
let inv = 0p1 / a
```

### BigInt (VM only)

Fixed-width unsigned integers (256-bit and 512-bit) for cryptographic operations:

```achronyme
let a = 0i256xFF
let b = bigint256(42)
let bits = a.to_bits()
let masked = a.bit_and(b)
```

---

## Circuit Features

### Declarations

Circuit parameters declare visibility and type in the function signature:

```achronyme
circuit example(output: Public, secret: Witness, arr: Witness Field[4]) {
    // output → public input (instance)
    // secret → private input (witness)
    // arr    → witness array (arr_0, arr_1, arr_2, arr_3)
}
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
circuit main(out: Public, a: Witness, b: Witness) {
    fn hash_pair(x, y) { poseidon(x, y) }
    assert_eq(hash_pair(a, b), out)
}
```

### Control Flow in Circuits

`if/else` compiles to `mux` (both branches are evaluated). `for` loops are statically unrolled. `while`, `break`, `continue` are rejected at compile time.

```achronyme
circuit sum_check(total: Public, vals: Witness Field[4]) {
    let sum = vals[0]
    let sum = sum + vals[1]
    let sum = sum + vals[2]
    let sum = sum + vals[3]
    assert_eq(sum, total)
}
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

# Generate Solidity verifier contract
ach circuit circuit.ach --inputs "x=42,y=7" --solidity

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
let a = 0p6
let b = 0p7
let product = 0p42

let p = prove(product: Public) {
    assert_eq(a * b, product)
}
```

Variables listed in the parameter list (e.g. `product: Public`) become public inputs visible to the verifier. All other captured variables (`a`, `b`) are automatically inferred as witnesses. Integer values are automatically promoted to field elements.

The result is a `Proof` object (Groth16 or PlonK depending on `--prove-backend`). Extract components with `proof_json(p)`, `proof_public(p)`, `proof_vkey(p)`. Verify with `verify_proof(p)`.

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
├── achronyme-parser/   Hand-written Pratt lexer + recursive descent parser
├── ir/                 SSA intermediate representation, optimization passes
├── compiler/           Bytecode compiler, R1CS backend, Plonkish backend
├── vm/                 Register-based VM (37 opcodes, prototype method dispatch)
├── memory/             Heap, GC, FieldElement<F> (BN254, BLS12-381, Goldilocks), BigInt
├── constraints/        R1CS/Plonkish systems, Poseidon hash, binary export
├── cli/                CLI, native Groth16 (ark-groth16) & PlonK (halo2-KZG)
├── std/                Standard library (NativeModule: parse_int, join, I/O)
├── ach-macros/         Proc-macros: #[ach_native], #[ach_module]
├── docs/               Documentation site (Astro + Starlight, 83 pages, EN/ES)
└── test/
    ├── vm/             VM/interpreter integration tests
    ├── circuit/        Circuit compilation tests
    ├── prove/          Prove block tests
    └── run_tests.sh    Integration test runner (162 tests)
```

---

## Global Functions

16 global functions are available without imports. Most operations now use [method syntax](#methods).

| Function | Arity | Description |
|----------|-------|-------------|
| `print(...)` | variadic | Print values to stdout |
| `typeof(x)` | 1 | Type name as String |
| `assert(x)` | 1 | Runtime assertion |
| `time()` | 0 | Unix timestamp (ms) |
| `gc_stats()` | 0 | GC statistics as map |
| `poseidon(a, b)` | 2 | Poseidon 2-to-1 hash (BN254) |
| `poseidon_many(a, b, ...)` | variadic | Left-fold Poseidon hash |
| `verify_proof(p)` | 1 | Verify a Groth16 proof |
| `proof_json(p)` | 1 | Extract proof JSON |
| `proof_public(p)` | 1 | Extract public inputs JSON |
| `proof_vkey(p)` | 1 | Extract verifying key JSON |
| `bigint256(x)` | 1 | Construct 256-bit unsigned integer |
| `bigint512(x)` | 1 | Construct 512-bit unsigned integer |
| `from_bits(bits, width)` | 2 | Bit list to BigInt |
| `parse_int(str)` | 1 | Parse string to integer |
| `join(list, sep)` | 2 | Join strings with separator |

## Methods

Values have type-specific methods called with dot syntax: `value.method(args)`.

```achronyme
// String methods
let upper = "hello".to_upper()          // "HELLO"
let words = "a,b,c".split(",")          // ["a", "b", "c"]

// List methods
let doubled = [1, 2, 3].map(fn(n) { n * 2 })  // [2, 4, 6]
let evens = [1, 2, 3, 4].filter(fn(n) { n % 2 == 0 })  // [2, 4]

// Map methods
let m = {name: "Alice", age: 30}
assert(m.contains_key("name"))
m.set("city", "NYC")

// Int methods
assert((-42).abs() == 42)
assert(2.pow(10) == 1024)
```

**50 methods** across 6 types: Int (6), String (14), List (13), Map (8), Field (2), BigInt (7).

**Static namespaces** provide type-level constants: `Int::MAX`, `Int::MIN`, `Field::ZERO`, `Field::ONE`, `Field::ORDER`, `BigInt::from_bits`.

---

## Status

- 2,700+ unit tests + 162 integration tests
- Cross-validated against snarkjs (independent constraint verification)
- 2 ZK backends: R1CS/Groth16 + Plonkish/KZG-PlonK
- Native in-process proof generation (no external tools)
- snarkjs-compatible binary export
- Solidity verifier contract generation
- Poseidon hash compatible with circomlibjs
- Runtime errors with source line numbers
- [Documentation](https://docs.achrony.me)

## License

GPL-3.0
