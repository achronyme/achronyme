# Achronyme

[![CI](https://github.com/achronyme/achronyme/actions/workflows/ci.yml/badge.svg)](https://github.com/achronyme/achronyme/actions/workflows/ci.yml)
[![Deploy Docs](https://github.com/achronyme/achronyme/actions/workflows/docs.yml/badge.svg)](https://github.com/achronyme/achronyme/actions/workflows/docs.yml)

A programming language for zero-knowledge circuits.

Write readable code. Decide what gets proven. Same language for general execution and ZK circuit compilation.

```
cargo build --release
cargo test --workspace     # 970+ unit tests
bash test/run_tests.sh     # 90+ integration tests
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
let secret = 0p42
let hash = 0p17159...  // poseidon(42, 0)

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

BN254 scalar field. Montgomery form internally. Created with the `0p` prefix:

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
let bits = to_bits(a)
let masked = bit_and(a, b)
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

let p = prove {
    witness a
    witness b
    public product
    assert_eq(a * b, product)
}
```

Variable names inside `public`/`witness` declarations must match `let` bindings in the outer scope. Integer values are automatically promoted to field elements.

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
├── vm/                 Register-based VM (40+ opcodes, tagged values)
├── memory/             Heap, GC, FieldElement (BN254 Montgomery), BigInt
├── constraints/        R1CS/Plonkish systems, Poseidon hash, binary export
├── cli/                CLI, native Groth16 (ark-groth16) & PlonK (halo2-KZG)
└── test/
    ├── vm/             VM/interpreter integration tests
    ├── circuit/        Circuit compilation tests
    ├── prove/          Prove block tests
    └── run_tests.sh    Integration test runner
```

---

## Native Functions

| Function | Arity | Description |
|----------|-------|-------------|
| `print(...)` | variadic | Print values to stdout |
| `len(x)` | 1 | Length of String, List, or Map |
| `typeof(x)` | 1 | Type name as String |
| `assert(x)` | 1 | Runtime assertion |
| `time()` | 0 | Unix timestamp (ms) |
| `push(list, item)` | 2 | Append to list |
| `pop(list)` | 1 | Remove last from list |
| `keys(map)` | 1 | Map keys as list |
| `proof_json(p)` | 1 | Extract proof JSON |
| `proof_public(p)` | 1 | Extract public inputs JSON |
| `proof_vkey(p)` | 1 | Extract verifying key JSON |
| `substring(s, start, end)` | 3 | Substring extraction |
| `indexOf(s, sub)` | 2 | Find substring index (-1 if not found) |
| `split(s, delim)` | 2 | Split string into list |
| `trim(s)` | 1 | Trim whitespace |
| `replace(s, search, repl)` | 3 | Replace all occurrences |
| `toUpper(s)` | 1 | Uppercase |
| `toLower(s)` | 1 | Lowercase |
| `chars(s)` | 1 | String to list of characters |
| `poseidon(a, b)` | 2 | Poseidon 2-to-1 hash (BN254) |
| `poseidon_many(a, b, ...)` | variadic | Left-fold Poseidon hash |
| `verify_proof(p)` | 1 | Verify a Groth16 proof |
| `bigint256(x)` | 1 | Construct 256-bit unsigned integer |
| `bigint512(x)` | 1 | Construct 512-bit unsigned integer |
| `to_bits(x)` | 1 | BigInt to bit list (LSB-first) |
| `from_bits(bits, width)` | 2 | Bit list to BigInt |
| `bit_and(a, b)` | 2 | Bitwise AND |
| `bit_or(a, b)` | 2 | Bitwise OR |
| `bit_xor(a, b)` | 2 | Bitwise XOR |
| `bit_not(x)` | 1 | Bitwise NOT |
| `bit_shl(x, n)` | 2 | Shift left |
| `bit_shr(x, n)` | 2 | Shift right |

---

## Status

- 970+ unit tests + 90+ integration tests
- 2 ZK backends: R1CS/Groth16 + Plonkish/KZG-PlonK
- Native in-process proof generation (no external tools)
- snarkjs-compatible binary export
- Solidity verifier contract generation
- Poseidon hash compatible with circomlibjs
- Runtime errors with source line numbers
- [Documentation](https://docs.achrony.me)

## License

GPL-3.0
