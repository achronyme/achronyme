use super::*;

// ── Resource limits (DoS resistance) ───────────────────────────

#[test]
fn frame_too_large_rejected_by_validator() {
    // `decode` calls `validate`. A hand-built program declaring a
    // frame of `MAX_FRAME_SIZE + 1` must fail validation.
    use crate::ir::MAX_FRAME_SIZE;
    let body = vec![Instr::Return { srcs: Vec::new() }];
    let prog = Program::new(FieldFamily::BnLike256, MAX_FRAME_SIZE + 1, Vec::new(), body);
    let bytes = encode(&prog);
    let err = decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert!(matches!(
        err,
        ArtikError::FrameTooLarge {
            frame_size,
            max,
        } if frame_size == MAX_FRAME_SIZE + 1 && max == MAX_FRAME_SIZE
    ));
}

#[test]
fn alloc_array_too_large_rejected_by_validator() {
    use crate::ir::MAX_ARRAY_LEN;
    let body = vec![
        Instr::AllocArray {
            dst: 0,
            len: MAX_ARRAY_LEN + 1,
            elem: ElemT::IntU32,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = Program::new(FieldFamily::BnLike256, 1, Vec::new(), body);
    let bytes = encode(&prog);
    let err = decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
    assert!(matches!(
        err,
        ArtikError::ArrayTooLarge {
            len,
            max,
        } if len == MAX_ARRAY_LEN + 1 && max == MAX_ARRAY_LEN
    ));
}

#[test]
fn cumulative_array_memory_budget_enforced_at_runtime() {
    // Each AllocArray is below MAX_ARRAY_LEN, but many of them
    // together cross the runtime memory budget. The loop runs
    // until `ArrayMemoryExceeded` fires; without this guard, a
    // malicious bytecode would OOM the host.
    //
    // Layout: a single AllocArray re-executed in a tight loop.
    //   [0] AllocArray dst=0 len=MAX_ARRAY_LEN elem=IntU8
    //   [1] Jump target=0
    let lead = vec![
        Instr::AllocArray {
            dst: 0,
            len: crate::ir::MAX_ARRAY_LEN,
            elem: ElemT::IntU8,
        },
        Instr::Jump { target: 0 },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), lead));
    let err = run_bn(&prog, &[], &mut []).unwrap_err();
    match err {
        ArtikError::ArrayMemoryExceeded { cells, max } => {
            assert_eq!(max, MAX_ARRAY_MEMORY_CELLS);
            assert!(cells > MAX_ARRAY_MEMORY_CELLS);
        }
        other => panic!("expected ArrayMemoryExceeded, got {other:?}"),
    }
}
