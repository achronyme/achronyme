pub(super) use std::collections::HashMap;

pub(super) use ir_core::{Instruction, IrProgram, IrType, SsaVar, Visibility};
pub(super) use ir_forge::{
    ArraySize, CaptureDef, CaptureUsage, CircuitExpr, CircuitNode, ForRange, ProveIR,
    ProveInputDecl, ProveIrError,
};
pub(super) use memory::{Bn254Fr, FieldElement};

pub(super) use ir_forge::{OuterScope, OuterScopeEntry, ProveIrCompiler};

/// Helper: compile source as a circuit and instantiate (no captures).
pub(super) fn compile_and_instantiate(source: &str) -> IrProgram<Bn254Fr> {
    let program = ir_forge::test_utils::compile_circuit(source).unwrap();
    program
        .instantiate_lysis::<Bn254Fr>(&HashMap::new())
        .unwrap()
}

/// Helper: compile source as a prove block with captures and instantiate.
pub(super) fn compile_and_instantiate_with_captures(
    source: &str,
    outer_scope: &[&str],
    captures: &[(&str, u64)],
) -> IrProgram<Bn254Fr> {
    let scope = OuterScope {
        values: outer_scope
            .iter()
            .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
            .collect(),
        ..Default::default()
    };
    let prove_ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(source, &scope).unwrap();
    let cap_map: HashMap<String, FieldElement<Bn254Fr>> = captures
        .iter()
        .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    prove_ir.instantiate_lysis(&cap_map).unwrap()
}
