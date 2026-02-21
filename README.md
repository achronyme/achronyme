# Achronyme

> A programming language for zero-knowledge circuits with dual execution: full VM (closures, GC, I/O) + optimized circuit compilation (R1CS/Plonkish over BN254).

**646 tests** | **2 backends** | **Groth16 proofs as first-class values**

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
- **R1CS backend** (Groth16) with snarkjs-compatible `.r1cs` / `.wtns` export
- **Plonkish backend** with custom gates, lookup tables, copy constraints
- SSA intermediate representation with optimization passes (const fold, DCE, boolean propagation)
- Taint analysis: compile-time detection of under-constrained variables
- Builtins: `poseidon`, `poseidon_many`, `mux`, `assert`, `assert_eq`, `range_check`, `merkle_verify`

### VM-ZK Integration
- `prove {}` blocks compile circuits, generate witnesses, and verify at runtime
- Groth16 proof generation via snarkjs with `.zkey` caching
- Proofs are first-class values: `proof_json()`, `proof_public()`, `proof_vkey()`
- Graceful fallback to verify-only when snarkjs is not available

### Architecture
- NaN-boxed 64-bit tagged values (10 types: Number, Int, Bool, Nil, String, List, Map, Function, Field, Proof)
- Register-based VM with 61 opcodes, 65K stack, upvalue closures
- 7 workspace crates: parser, compiler, ir, vm, memory, constraints, cli

---

## Getting Started

### Prerequisites
- Rust (latest stable)
- Node.js + snarkjs (optional, for Groth16 proof generation)

```bash
# Install snarkjs (optional)
npm install -g snarkjs
```

### Build & Test

```bash
cargo build --release
cargo test --workspace  # 646 tests
```

### Run a Program

```bash
# Execute a script
cargo run -- run examples/hello.ach

# With Groth16 proof generation (requires snarkjs)
cargo run -- run examples/proof.ach --ptau path/to/pot12.ptau
```

### Compile a Circuit

```bash
# Generate .r1cs and .wtns files
cargo run -- circuit circuit.ach \
    --public "root" \
    --witness "leaf,path_0,path_1,path_2" \
    --inputs "leaf=42,root=..."

# Use with snarkjs
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
| `cli` | Command-line interface, snarkjs integration |

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

- **646 tests passing** across 7 crates
- 2 ZK backends (R1CS + Plonkish), both audited
- Full VM-ZK integration (Levels 1-3)
- snarkjs-compatible binary export
- 2 complete security audits resolved (C1-4, H1-5, M1-8)

## License

GPL-3.0
