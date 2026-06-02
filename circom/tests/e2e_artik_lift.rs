mod common;
use common::*;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

#[path = "e2e_artik_lift/arrays_ops.rs"]
mod arrays_ops;
#[path = "e2e_artik_lift/bigint_mod.rs"]
mod bigint_mod;
#[path = "e2e_artik_lift/bigint_product.rs"]
mod bigint_product;
#[path = "e2e_artik_lift/bit_tables.rs"]
mod bit_tables;
#[path = "e2e_artik_lift/e2e.rs"]
mod e2e;
#[path = "e2e_artik_lift/nested_mux.rs"]
mod nested_mux;
#[path = "e2e_artik_lift/probes.rs"]
mod probes;
#[path = "e2e_artik_lift/row_and_secp.rs"]
mod row_and_secp;
#[path = "e2e_artik_lift/runtime.rs"]
mod runtime;
#[path = "e2e_artik_lift/secp_values.rs"]
mod secp_values;
#[path = "e2e_artik_lift/smoke.rs"]
mod smoke;

/// Every instruction across all subprograms of a decoded payload.
/// A callee's body lives in its own subprogram, so a structural
/// assertion about emitted ops scans the whole program rather than
/// just the entry subprogram.
fn all_instrs(prog: &artik::Program) -> impl Iterator<Item = &artik::Instr> {
    prog.subprograms.iter().flat_map(|s| s.body.iter())
}
