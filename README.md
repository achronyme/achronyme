# Achronyme

> A programming language for zero-knowledge circuits with dual execution: full VM (closures, GC, I/O) + optimized circuit compilation (R1CS/Plonkish over BN254).

**703 tests** | **2 backends** | **Native Groth16 & PlonK proofs as first-class values**

---

## What is Achronyme?

Achronyme is a high-level language where the same code can run as a general-purpose program (VM mode) or compile to ZK circuits (circuit mode). Write readable logic, get verifiable proofs.

```achronyme
let secret = field(42)
let hash = field("17159...")  // precomputed poseidon(42, 0)

let proof = prove {
    witness secret
    public hash
    assert_eq(poseidon(secret, 0), hash)
}

print(proof)              // <Proof>
print(proof_json(proof))  // {"pi_a": [...], "pi_b": [...], ...}
```

Unlike zkVMs (SP1, RISC Zero) that prove generic computation expensively, or restrictive DSLs (Circom, Noir) that force you to think in constraints, Achronyme lets you write natural code and decide what gets proven.

---

## Features

### Language
- Functional syntax with `let`, `fn`, `if/else`, `for`, closures, recursion
- Arrays, maps, iterators, first-class functions
- BN254 field elements as native type (`field(42)`, `field("0x2a")`)
- Mark-and-sweep GC with typed arenas

### ZK Circuit Compilation
- **R1CS backend** — native Groth16 proofs via ark-groth16, snarkjs-compatible `.r1cs` / `.wtns` export
- **Plonkish backend** — native KZG-PlonK proofs via halo2 (PSE), custom gates, lookup tables, copy constraints
- SSA intermediate representation with optimization passes (const fold, DCE, boolean propagation)
- Taint analysis: compile-time detection of under-constrained variables
- Builtins: `poseidon`, `poseidon_many`, `mux`, `assert`, `assert_eq`, `range_check`, `merkle_verify`

### VM-ZK Integration
- `prove {}` blocks compile circuits, generate witnesses, and verify at runtime
- Native in-process proof generation for both backends (no external dependencies)
- `--prove-backend r1cs` (default, Groth16) or `--prove-backend plonkish` (KZG-PlonK)
- Proofs are first-class values: `proof_json()`, `proof_public()`, `proof_vkey()`
- KZG params and proving keys cached in `~/.achronyme/cache/`

### Architecture
- NaN-boxed 64-bit tagged values (10 types: Number, Int, Bool, Nil, String, List, Map, Function, Field, Proof)
- Register-based VM with 61 opcodes, 65K stack, upvalue closures
- 7 workspace crates: parser, compiler, ir, vm, memory, constraints, cli

---

## Getting Started

### Prerequisites
- Rust (latest stable)
- No external dependencies — proof generation is fully native

### Build & Test

```bash
cargo build --release
cargo test --workspace  # 703 tests
```

### Run a Program

```bash
# Execute a script
cargo run -- run examples/hello.ach

# With prove {} blocks using Groth16 (default)
cargo run -- run examples/proof.ach

# With prove {} blocks using PlonK (halo2 KZG)
cargo run -- run examples/proof.ach --prove-backend plonkish
```

### Compile a Circuit

```bash
# R1CS: generate .r1cs and .wtns files
cargo run -- circuit circuit.ach \
    --public "root" \
    --witness "leaf,path_0,path_1,path_2" \
    --inputs "leaf=42,root=..."

# Plonkish: compile, verify, and generate KZG-PlonK proof
cargo run -- circuit circuit.ach \
    --backend plonkish \
    --inputs "leaf=42,root=..." \
    --prove

# R1CS files are snarkjs-compatible
snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit.zkey
snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```

---

## Example: Merkle Membership Proof

```achronyme
// Prove you know a leaf in a Merkle tree without revealing it
let leaf = field(42)
let root = field("17843...")

// Witness: the secret path
let path = [field("1234..."), field("5678..."), field("9abc...")]
let indices = [field(0), field(1), field(0)]

let proof = prove {
    witness leaf
    witness path[3]
    witness indices[3]
    public root
    merkle_verify(root, leaf, path, indices)
}

print(proof_json(proof))  // Groth16 proof, verifiable on-chain
```

---

## Project Structure

| Crate | Purpose |
|-------|---------|
| `achronyme-parser` | PEG grammar (pest), lexing, parsing |
| `compiler` | Bytecode compiler + R1CS/Plonkish backends |
| `ir` | SSA intermediate representation, optimization passes |
| `vm` | Register-based virtual machine |
| `memory` | Heap, GC, FieldElement (BN254 Montgomery), ProofObject |
| `constraints` | R1CS/Plonkish constraint systems, Poseidon hash, binary export |
| `cli` | Command-line interface, native Groth16 (ark-groth16) & PlonK (halo2 KZG) proving |

---

## Constraint Costs

| Operation | R1CS Constraints | Plonkish Rows |
|-----------|-----------------|---------------|
| `a + b` | 0 | 0 (deferred) |
| `a * b` | 1 | 1 |
| `a / b` | 2 | 2 |
| `assert_eq(a, b)` | 1 | 1 |
| `assert(expr)` | 2 | 2 |
| `a == b` | 2 (IsZero) | 2 |
| `a < b` | ~760 | ~760 |
| `poseidon(a, b)` | 361 | 361 |
| `range_check(x, n)` | n+1 | 1 (lookup) |
| `mux(c, a, b)` | 2 | 1 |

---

## Status

- **703 tests passing** across 7 crates
- 2 ZK backends with native proof generation (R1CS/Groth16 + Plonkish/KZG-PlonK)
- Full VM-ZK integration (Levels 1-3)
- snarkjs-compatible binary export (R1CS backend)
- 2 complete security audits resolved (C1-4, H1-5, M1-8)

## License

GPL-3.0
