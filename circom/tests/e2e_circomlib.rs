mod common;
use common::*;

use std::collections::HashMap;
use std::path::Path;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

#[path = "e2e_circomlib/babyjub_scalar.rs"]
mod babyjub_scalar;
#[path = "e2e_circomlib/boss_fight.rs"]
mod boss_fight;
#[path = "e2e_circomlib/coverage.rs"]
mod coverage;
#[path = "e2e_circomlib/crypto_primitives.rs"]
mod crypto_primitives;
#[path = "e2e_circomlib/hashes.rs"]
mod hashes;
#[path = "e2e_circomlib/l1_collapse.rs"]
mod l1_collapse;
#[path = "e2e_circomlib/merkle_curve_pedersen.rs"]
mod merkle_curve_pedersen;
#[path = "e2e_circomlib/pointbits.rs"]
mod pointbits;
#[path = "e2e_circomlib/simple_gadgets.rs"]
mod simple_gadgets;
