# Tornado cash — multi-file Achronyme demo

Minimal viable zk privacy pool in 3 `.ach` files and an optional
`achronyme.toml`. The entry point is `src/main.ach`; run it with:

```sh
ach run examples/tornado/src/main.ach
```

## What it does

1. **Deposit phase (VM mode)** — 16 simulated users pick random
   `(secret, nullifier)` pairs, publish
   `commitment = Poseidon(secret, nullifier)` as their leaf, and
   the operator builds a depth-4 Merkle tree bottom-up. This is
   pure off-chain bookkeeping — no constraints emitted yet.

2. **Withdraw phase (prove block)** — user 5 publishes only
   `nullifier_hash = Poseidon(nullifier, 0)` and a Groth16 proof.
   The circuit rebuilds the commitment from `(secret, nullifier)`,
   walks the Merkle path, and asserts both (a) the reconstructed
   root equals the published root and (b) the revealed nullifier
   hash matches the derived one. The verifier learns **which
   nullifier was burned** but **not which leaf was withdrawn**,
   giving user 5 a private exit from the pool.

3. **On-chain settlement (out of scope for this demo)** — in a
   real deployment the pool contract keeps a set of known
   nullifier hashes and refuses any withdrawal whose
   `nullifier_hash` is already in the set.

## File layout

```
examples/tornado/
├── README.md
└── src/
    ├── main.ach        — entry point; deposit flow + withdraw prove block
    ├── hash_mod.ach    — commitment / nullifier_hash / hash_node
    └── tree.ach        — depth-4 Merkle root + per-level step helper
```

Both `hash_mod.ach` and `tree.ach` route their hashing through the
circomlib `Poseidon(2)` template via library-mode import. Paths
point at `../../../test/circomlib/circuits/poseidon.circom`
relative to the module that does the import — we don't vendor
circomlib inside `examples/tornado` to keep the demo tree small.

Every exported function in the helper modules is callable from
both VM mode (for off-chain tree construction) and from prove
blocks (for the withdraw proof), because `hash_node` /
`commitment` / `nullifier_hash` forward to a circom template
whose library-mode dispatcher handles both regimes transparently.

## What this demo exercises

This is the first test in the repository that combines **every
layer** of the library-mode circom interop stack in a realistic
zk-protocol shape:

- Multi-file `.ach` module system with selective imports (the
  first test that mixes `.ach` modules with `.circom` imports
  via transitive propagation).
- Imported functions invoked inside `prove {}` blocks — the
  ProveIR compiler inlines module-defined bodies at every call
  site and resolves circom templates against a combined
  dispatch table.
- Multi-output Poseidon chains (20 `Poseidon(2)` invocations in
  VM mode during tree construction, 6 inside the prove block for
  the withdraw proof).
- Native arithmetic `mux` (`d·a + (1 − d)·b`) as a VM-friendly
  substitute for the `mux()` builtin, which currently only
  exists in the ProveIR compiler and would break VM-mode
  compilation of module-level helpers.
- Public Merkle root + public nullifier hash as the only
  disclosed outputs — everything else stays a private witness
  inside the proof.

Constraint count after Achronyme's O1 pass: **2,968 constraints**
(6 circomlib Poseidon invocations ≈ 491 constraints each plus a
thin overhead for the mux arithmetic and nullifier equality
check). Fits comfortably inside a standard Groth16 ptau setup.

## Known limitations

- **`mut` bindings can't be exported across modules.** We work
  around it by making every helper pure.
- **Namespace-style method calls (`tree.merkle_step(...)`) aren't
  resolved by the ProveIR compiler inside prove blocks.** The
  demo uses selective imports (`import { merkle_step } from "./tree.ach"`)
  instead.
- **The direction bits aren't range-checked.** A hardened version
  would add `assert((dir == 0) || (dir == 1))` or route the dirs
  through `Num2Bits(1)`; the demo leaves this out so the
  constraint count matches a vanilla Merkle verifier.
- **circomlib is not vendored** — paths reach into
  `test/circomlib/circuits/` at the repo root. A standalone demo
  would copy or git-submodule the circomlib subset it needs.
