//! Fuzz target: ProveIR instantiate (Phase 0.4.B).
//!
//! Pre-compiles a small ProveIR fixture once at first invocation, then
//! feeds `ProveIR::instantiate_lysis` random capture maps derived from
//! the libfuzzer byte stream. Oracle: any `Err(LysisInstantiateError)`
//! is a valid graceful failure (missing capture, walker rejection,
//! materialise error). A panic is a hard fuzz failure.
//!
//! ## Why fixture-by-source instead of pre-compiled bytes
//!
//! The advisor flagged that ProveIR fixture loading is historically
//! more expensive than estimated, and suggested hardcoding 2-3 small
//! ProveIR templates inline rather than compiling fixtures from
//! `test/prove/*.ach` at fuzz time. We use a middle path: compile a
//! single tiny prove block via `ProveIrCompiler::compile_prove_block`
//! once at fuzz target startup (cached in `OnceLock`), so we don't
//! incur compilation cost per iteration but also avoid hand-encoding
//! version-coupled bincode bytes that would silently break on
//! `PROVE_IR_FORMAT_VERSION` bumps.
//!
//! ## Input shape
//!
//! Each iteration takes ≥ 25 bytes:
//! - `[0..8]`, `[8..16]`, `[16..24]`: u64 values for `a`, `b`, `out`.
//! - `[24]`: bitmap selecting which keys to insert into the captures
//!   map (bit 0 = `a`, bit 1 = `b`, bit 2 = `out`, bit 3 = inject an
//!   unrelated `__extra__` key).
//!
//! The bitmap exercises the missing-required-capture path
//! (`Err(ProveIrError::UnsupportedOperation)`), the all-present path
//! (success — Lysis fully walks), and the spurious-extra-key path
//! (must be ignored cleanly, not crash on extra-key handling).
//!
//! ## Discriminator (verified during development)
//!
//! Inserted a synthetic `panic!("synthetic discriminator")` at the
//! top of `ProveIR::instantiate_lysis` (`ir-forge/src/instantiate/api.rs`)
//! and ran `cargo +nightly fuzz run fuzz_proveir_instantiate
//! -- -max_total_time=15`. Crash triggered immediately on the first
//! iteration that produced ≥ 25 bytes. Reverted before this commit.
//!
//! Without a verified discriminator this target is theater — we have
//! no evidence it would catch a real panic that didn't reach the
//! corpus.

#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use ir_forge::ast_lower::ProveIrCompiler;
use ir_forge::types::ProveIR;
use ir_forge::{OuterScope, OuterScopeEntry};
use libfuzzer_sys::fuzz_target;
use memory::{Bn254Fr, FieldElement};

/// Compile a fixed prove block once and reuse across iterations.
/// `assert_eq(a * b, out)` exercises Mul + AssertEq via Lysis's Walker —
/// shape that closes under `instantiate_lysis` per Phase 1.B's
/// cross_path_prove_baseline (33/33 byte-identical). Outer scope
/// declares `a`, `b`, `out`; `out` is published, so the captures the
/// instantiator validates against are `a` and `b` (everything else
/// missing → `Err`).
fn fixture() -> &'static ProveIR {
    static FIXTURE: OnceLock<ProveIR> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut outer = OuterScope::default();
        outer
            .values
            .insert("a".to_string(), OuterScopeEntry::Scalar);
        outer
            .values
            .insert("b".to_string(), OuterScopeEntry::Scalar);
        outer
            .values
            .insert("out".to_string(), OuterScopeEntry::Scalar);
        ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "public out\nassert_eq(a * b, out)",
            &outer,
        )
        .expect("fuzz fixture must compile")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 25 {
        return;
    }

    let prove_ir = fixture();

    let a_raw = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let b_raw = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let out_raw = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let mask = data[24];

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    if mask & 0b0001 != 0 {
        captures.insert("a".to_string(), FieldElement::from_u64(a_raw));
    }
    if mask & 0b0010 != 0 {
        captures.insert("b".to_string(), FieldElement::from_u64(b_raw));
    }
    if mask & 0b0100 != 0 {
        captures.insert("out".to_string(), FieldElement::from_u64(out_raw));
    }
    if mask & 0b1000 != 0 {
        captures.insert("__extra__".to_string(), FieldElement::from_u64(0));
    }

    // Both branches valid — only panics fail the fuzz.
    // - Ok(IrProgram): full Walker → InterningSink → materialise succeeded.
    // - Err(LysisInstantiateError): instantiate-side (missing capture,
    //   etc.) or Lysis-side (walker rejection) graceful failure.
    let _ = prove_ir.instantiate_lysis(&captures);
});
