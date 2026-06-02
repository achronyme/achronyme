//! Phase III — Merkle Tree Circuit Vectors (R1CS, BN254 Fr)
//!
//! Parametric depth testing of binary Merkle trees with Poseidon hash (t=3).
//! Depths 1-20, all leaf positions, soundness (wrong leaf/sibling/direction),
//! and constraint count scaling validation.
//!
//! Industry sources:
//!   - gnark std (Apache-2.0): Merkle proof verification gadget
//!     https://github.com/Consensys/gnark
//!     https://github.com/hashcloak/merkle_trees_gnark
//!   - circomlib (GPL-3.0): MerkleTreeChecker.circom
//!     https://github.com/iden3/circomlib
//!   - ZoKrates stdlib (LGPL-3.0): std/hashes/poseidon + merkle
//!     https://zokrates.github.io/toolbox/stdlib.html
//!   - Ethereum Research: constraint benchmarks for Merkle+Poseidon
//!     https://ethresear.ch/t/gas-and-circuit-constraint-benchmarks

#[path = "merkle_vectors/api_position.rs"]
mod api_position;
#[path = "merkle_vectors/deep.rs"]
mod deep;
#[path = "merkle_vectors/depths.rs"]
mod depths;
#[path = "merkle_vectors/export.rs"]
mod export;
#[path = "merkle_vectors/helpers.rs"]
mod helpers;
#[path = "merkle_vectors/scaling_boundaries.rs"]
mod scaling_boundaries;
