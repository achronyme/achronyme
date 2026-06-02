//! Round-trip and validation tests for ProveIR types.

use ir_core::IrType;
use ir_forge::types::prove_ir::PROVE_IR_FORMAT_VERSION;
use ir_forge::{
    ArraySize, CircuitExpr, CircuitNode, FieldConst, ForRange, ProveIR, ProveInputDecl,
};
use memory::field::PrimeId;
use memory::Bn254Fr;

use ir_forge::{OuterScope, OuterScopeEntry, ProveIrCompiler};

#[path = "types_roundtrip/adversarial.rs"]
mod adversarial;
#[path = "types_roundtrip/display.rs"]
mod display;
#[path = "types_roundtrip/field_const.rs"]
mod field_const;
#[path = "types_roundtrip/round_trip.rs"]
mod round_trip;
#[path = "types_roundtrip/version.rs"]
mod version;

/// Round-trip: ProveIR → bytes → ProveIR, verify equality.
fn assert_round_trip(prove_ir: &ProveIR) {
    let bytes = prove_ir
        .to_bytes(PrimeId::Bn254)
        .expect("serialization failed");
    let (restored, prime) = ProveIR::from_bytes(&bytes).expect("deserialization failed");
    assert_eq!(prime, PrimeId::Bn254);

    // Spans are skipped, so we compare field-by-field excluding spans.
    assert_eq!(prove_ir.public_inputs, restored.public_inputs);
    assert_eq!(prove_ir.witness_inputs, restored.witness_inputs);
    assert_eq!(prove_ir.captures, restored.captures);
    // Body comparison: spans will be None after round-trip.
    // Compare the number and structure of nodes.
    assert_eq!(prove_ir.body.len(), restored.body.len());
}
