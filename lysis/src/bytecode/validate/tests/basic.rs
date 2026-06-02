use super::*;

// -----------------------------------------------------------------
// Rule 4 — const bounds
// -----------------------------------------------------------------

#[test]
fn rule4_load_const_in_range_passes() {
    let mut builder = b();
    builder.intern_field(memory::field::FieldElement::<Bn254Fr>::from_canonical([
        0, 0, 0, 0,
    ]));
    builder.load_const(0, 0).halt();
    validate(&builder.finish(), &default_config()).unwrap();
}

#[test]
fn rule4_load_const_out_of_range_rejects() {
    let mut builder = b();
    builder.load_const(0, 5).halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(
        err,
        LysisError::ConstIdxOutOfRange { idx: 5, len: 0, .. }
    ));
}

#[test]
fn rule4_load_input_index_out_of_range_rejects() {
    let mut builder = b();
    builder.load_input(0, 3, Visibility::Witness).halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(err, LysisError::ConstIdxOutOfRange { .. }));
}

#[test]
fn rule4_witness_call_idx_out_of_range_rejects() {
    let mut builder = b();
    builder.emit_witness_call(9, vec![0], vec![1]).halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(err, LysisError::ConstIdxOutOfRange { idx: 9, .. }));
}

// -----------------------------------------------------------------
// Rule 6 — jump targets
// -----------------------------------------------------------------

#[test]
fn rule6_jump_to_next_instr_is_ok() {
    let mut builder = b();
    builder.jump(3); // jump +3 from offset 0 → offset 3
    builder.halt(); // offset 3
    validate(&builder.finish(), &default_config()).unwrap();
}

#[test]
fn rule6_jump_to_negative_rejects() {
    let mut builder = b();
    builder.jump(-10);
    builder.halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(err, LysisError::BadJumpTarget { .. }));
}

#[test]
fn rule6_jump_to_non_opcode_boundary_rejects() {
    let mut builder = b();
    builder.jump(2); // lands in the middle of the next opcode
    builder.halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(err, LysisError::BadJumpTarget { .. }));
}

// -----------------------------------------------------------------
// Rule 7 — templates defined
// -----------------------------------------------------------------

#[test]
fn rule7_instantiate_undefined_rejects() {
    let mut builder = b();
    builder.instantiate_template(99, vec![], vec![]).halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(
        err,
        LysisError::UndefinedTemplate {
            template_id: 99,
            ..
        }
    ));
}

#[test]
fn rule7_loop_rolled_undefined_rejects() {
    let mut builder = b();
    builder.loop_rolled(0, 0, 5, 42).halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(
        err,
        LysisError::UndefinedTemplate {
            template_id: 42,
            ..
        }
    ));
}

// -----------------------------------------------------------------
// Rule 9 — forward dataflow
// -----------------------------------------------------------------

#[test]
fn rule9_write_then_read_is_ok() {
    let mut builder = b();
    builder.intern_string("x");
    builder.load_input(0, 0, Visibility::Witness);
    builder.emit_range_check(0, 8);
    builder.halt();
    validate(&builder.finish(), &default_config()).unwrap();
}

#[test]
fn rule9_read_without_write_rejects() {
    let mut builder = b();
    builder.emit_range_check(5, 8); // r5 never written
    builder.halt();
    let err = validate(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(
        err,
        LysisError::UninitializedRegister { reg: 5, .. }
    ));
}

#[test]
fn rule9_skipped_when_jumps_present() {
    // Linear dataflow bails out at the first Jump — rule 9 becomes
    // a no-op when the program can branch. A proper CFG-based
    // analysis is future work.
    let mut builder = b();
    builder.jump(3); // valid jump to halt at offset 3
    builder.halt();
    check_forward_dataflow(&builder.finish()).unwrap();
}

// -----------------------------------------------------------------
// Rule 10 — reachable return
// -----------------------------------------------------------------

#[test]
fn rule10_body_ends_in_halt_is_ok() {
    let mut builder = b();
    builder.halt();
    validate(&builder.finish(), &default_config()).unwrap();
}

#[test]
fn rule10_body_missing_terminator_rejects() {
    // EnterScope neither reads nor writes registers, so rule 9
    // passes; this lets us actually reach rule 10 and exercise
    // the "no terminator at the end" branch.
    let mut builder = b();
    builder.enter_scope();
    let err = check_reachable_return(&builder.finish()).unwrap_err();
    assert!(matches!(err, LysisError::UnreachableReturn { .. }));
}
