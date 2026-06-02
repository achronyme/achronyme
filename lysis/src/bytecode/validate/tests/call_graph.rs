use super::*;

// -----------------------------------------------------------------
// Rule 11 — call graph
// -----------------------------------------------------------------

#[test]
fn rule11_small_acyclic_graph_passes() {
    // Program where rule 11's graph is root → T1, a 1-hop acyclic
    // chain. Called directly: rule 10 would otherwise reject the
    // synthetic template whose body_offset lies inside the
    // DefineTemplate bytes themselves (a consequence of crafting
    // tiny fixtures).
    let mut builder = b();
    builder.define_template(1, 8, 0, 1, 1);
    builder.instantiate_template(1, vec![], vec![]);
    builder.halt();
    check_call_graph(&builder.finish(), &default_config()).unwrap();
}

#[test]
fn rule11_self_loop_rejects() {
    // Craft a program where template 1's body slice covers the
    // very InstantiateTemplate(1) that follows DefineTemplate.
    //
    // Offsets:
    //   0  DefineTemplate(1, bo=13, bl=6)  [13 bytes]
    //   13 InstantiateTemplate(1, [], [])  [5 bytes, inside T1]
    //   18 Halt                            [1 byte, inside T1]
    let mut builder = b();
    builder.define_template(1, 8, 0, 13, 6);
    builder.instantiate_template(1, vec![], vec![]);
    builder.halt();
    let err = check_call_graph(&builder.finish(), &default_config()).unwrap_err();
    assert!(matches!(err, LysisError::CircularTemplateCall { .. }));
}

#[test]
fn rule11_small_chain_within_limit_passes() {
    let cfg = LysisConfig {
        max_call_depth: 4,
        ..Default::default()
    };
    let mut builder = b();
    builder.define_template(1, 4, 0, 100, 1);
    builder.define_template(2, 4, 0, 200, 1);
    builder.instantiate_template(1, vec![], vec![]);
    builder.halt();
    check_call_graph(&builder.finish(), &cfg).unwrap();
}

#[test]
fn rule11_depth_exceeded_rejects() {
    // Root → T1 → T2 is depth 2, exceeds max_call_depth = 1.
    //
    // Offsets:
    //   0  DefineTemplate(1, bo=26, bl=6)  [13 bytes]
    //   13 DefineTemplate(2, bo=32, bl=1)  [13 bytes]
    //   26 InstantiateTemplate(2, [], [])  [5 bytes, inside T1]
    //   31 Halt                            [1 byte, terminates T1]
    //   32 Halt                            [1 byte, T2 body]
    //   33 InstantiateTemplate(1, [], [])  [5 bytes, root level]
    //   38 Halt                            [1 byte, terminates root]
    let cfg = LysisConfig {
        max_call_depth: 1,
        ..Default::default()
    };
    let mut builder = b();
    builder.define_template(1, 4, 0, 26, 6);
    builder.define_template(2, 4, 0, 32, 1);
    builder.instantiate_template(2, vec![], vec![]);
    builder.halt();
    builder.halt();
    builder.instantiate_template(1, vec![], vec![]);
    builder.halt();
    let err = check_call_graph(&builder.finish(), &cfg).unwrap_err();
    assert!(matches!(err, LysisError::MaxCallDepthExceeded { .. }));
}

#[test]
fn rule11_tail_chain_does_not_count_toward_depth() {
    use crate::program::{Instr, Template};

    // Build a linear N-template chain with synthetic offsets ==
    // body positions. Root: DefineTemplate(0..N),
    // InstantiateTemplate(0), Halt. Template i (<N-1) body:
    // InstantiateTemplate(i+1) then — if `non_tail`, a LoadConst —
    // then Return. Leaf: Return. The executor tail-eliminates the
    // `InstantiateTemplate(next); Return` links (runtime depth
    // O(1)); Rule 11 must mirror that, else a debug build rejects
    // the very chains release runs fine.
    fn chain(n: u16, non_tail: bool) -> Program<Bn254Fr> {
        let mut body: Vec<Instr> = Vec::new();
        let push = |op: Opcode, body: &mut Vec<Instr>| {
            let off = body.len() as u32;
            body.push(Instr {
                opcode: op,
                offset: off,
            });
        };
        for id in 0..n {
            push(
                Opcode::DefineTemplate {
                    template_id: id,
                    frame_size: 2,
                    n_params: 0,
                    body_offset: 0,
                    body_len: 0,
                },
                &mut body,
            );
        }
        push(
            Opcode::InstantiateTemplate {
                template_id: 0,
                capture_regs: Box::new(vec![]),
                output_regs: Box::new(vec![]),
            },
            &mut body,
        );
        push(Opcode::Halt, &mut body);
        let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(n as usize);
        for id in 0..n {
            let start = body.len() as u32;
            if id < n - 1 {
                push(
                    Opcode::InstantiateTemplate {
                        template_id: id + 1,
                        capture_regs: Box::new(vec![]),
                        output_regs: Box::new(vec![]),
                    },
                    &mut body,
                );
                if non_tail {
                    push(Opcode::LoadConst { dst: 0, idx: 0 }, &mut body);
                }
            }
            push(Opcode::Return, &mut body);
            ranges.push((start, body.len() as u32 - start));
        }
        let templates = (0..n)
            .map(|id| {
                let (bo, bl) = ranges[id as usize];
                Template {
                    id,
                    frame_size: 2,
                    n_params: 0,
                    body_offset: bo,
                    body_len: bl,
                }
            })
            .collect();
        Program {
            header: crate::header::LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0),
            const_pool: crate::ConstPool::<Bn254Fr>::new(FieldFamily::BnLike256),
            templates,
            body,
        }
    }

    let cfg = LysisConfig {
        max_call_depth: 10,
        ..Default::default()
    };
    // 100 tail links + 1 non-tail root→t0 edge ⇒ longest path 1.
    check_call_graph(&chain(100, false), &cfg)
        .expect("a 100-deep tail-chain must validate (tail edges add 0 depth)");
    // The same chain with a non-tail op per link DOES grow the
    // stack ⇒ must still be rejected — proves only tail edges are
    // zero-counted, not all InstantiateTemplate edges.
    assert!(matches!(
        check_call_graph(&chain(100, true), &cfg).unwrap_err(),
        LysisError::MaxCallDepthExceeded { .. }
    ));
}

// -----------------------------------------------------------------
// Happy path — a realistic Num2Bits-like program
// -----------------------------------------------------------------

#[test]
fn realistic_num2bits_program_passes() {
    let mut builder = b();
    builder.intern_string("in");
    builder
        .load_input(0, 0, Visibility::Witness)
        .emit_decompose(1, 0, 4)
        .emit_range_check(1, 1)
        .emit_range_check(2, 1)
        .emit_range_check(3, 1)
        .emit_range_check(4, 1)
        .halt();
    validate(&builder.finish(), &default_config()).unwrap();
}
