use super::*;
use crate::bytecode::{decode, encode};

#[test]
fn empty_builder_finishes_to_empty_program() {
    let p = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256).finish();
    assert!(p.is_empty());
    assert_eq!(p.header.const_pool_len, 0);
    assert_eq!(p.header.body_len, 0);
}

#[test]
fn offsets_advance_per_opcode() {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    b.halt();
    assert_eq!(b.current_offset(), 1); // Halt = 1 byte
    b.emit_add(0, 0, 0);
    assert_eq!(b.current_offset(), 5); // + 1 opcode + 3 operands
}

#[test]
fn builder_matches_encoded_body_length() {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    b.load_input(0, 0, Visibility::Witness);
    b.emit_range_check(0, 8);
    b.halt();
    let program = b.finish();

    let bytes = encode(&program);
    let decoded = decode::<Bn254Fr>(&bytes).unwrap();
    assert_eq!(decoded.body.len(), 3);
    assert_eq!(decoded.header.body_len, program.header.body_len);
}

#[test]
fn define_template_populates_template_table() {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    b.define_template(1, 4, 1, 32, 16);
    b.define_template(2, 8, 2, 64, 32);
    let program = b.finish();
    assert_eq!(program.templates.len(), 2);
    assert_eq!(program.templates[0].id, 1);
    assert_eq!(program.templates[1].id, 2);
}

#[test]
fn const_pool_interners_return_indices() {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    let idx0 = b.intern_string("in");
    let idx1 = b.intern_field(FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0]));
    let idx2 = b.intern_artik_bytecode(vec![0xAA, 0xBB]);
    assert_eq!(idx0, 0);
    assert_eq!(idx1, 1);
    assert_eq!(idx2, 2);
    let program = b.finish();
    assert_eq!(program.const_pool.len(), 3);
    assert_eq!(program.header.const_pool_len, 3);
}

#[test]
fn chained_builder_produces_valid_roundtrip() {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    let in_idx = b.intern_string("x");
    b.load_input(0, in_idx, Visibility::Witness)
        .emit_range_check(0, 8)
        .emit_add(1, 0, 0)
        .halt();
    let program = b.finish();

    let bytes = encode(&program);
    let decoded = decode::<Bn254Fr>(&bytes).unwrap();
    assert_eq!(decoded.body.len(), 4);
    assert_eq!(decoded.const_pool.len(), 1);
}

#[test]
fn flags_are_preserved() {
    let p = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256)
        .with_flags(crate::header::FLAG_HAS_WITNESS_CALLS)
        .finish();
    assert_eq!(p.header.flags, crate::header::FLAG_HAS_WITNESS_CALLS);
}
