use crate::lowering::template::lower;

// ── FlushTracker integration ────────────────────────────────────

#[test]
fn flush_tracker_records_pending_inline() {
    // Synthetic Circom program where wiring an outer-scope
    // pending component triggers an inline_into call. The
    // FlushTracker, once enabled, records the IR-emission range
    // covering Inner's body. After lowering, the tracker must
    // have AT LEAST one range (more than one is fine — every
    // pending-component inline is recorded).
    let src = r#"
        template Inner() {
            signal input a;
            signal output out;
            out <== a + 1;
        }
        template Outer() {
            signal input x;
            signal output y;
            component c = Inner();
            c.a <== x;
            y <== c.out;
        }
        component main = Outer();
    "#;

    let (program, errors) = crate::parser::parse_circom(src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {:?}", errors);

    let outer = program
        .definitions
        .iter()
        .find_map(|d| match d {
            crate::ast::Definition::Template(t) if t.name == "Outer" => Some(t),
            _ => None,
        })
        .expect("Outer not found");

    let mut ctx = crate::lowering::context::LoweringContext::from_program(&program);
    ctx.flush_tracker.enable();
    assert!(ctx.flush_tracker.is_enabled());

    let _ = lower::lower_template_with_ctx(
        outer,
        &std::collections::HashMap::new(),
        &std::collections::HashMap::new(),
        &[],
        &mut ctx,
    )
    .expect("lower_template failed");

    let ranges = ctx.flush_tracker.take();
    assert!(
        !ranges.is_empty(),
        "FlushTracker should have recorded at least one flush range \
         when wiring `c.a <== x` triggered Inner's inline; got 0 ranges",
    );

    // Each range is a non-empty half-open interval (start < end).
    for &(start, end) in &ranges {
        assert!(
            start < end,
            "FlushTracker recorded an empty/inverted range [{start}, {end})",
        );
    }

    // After take(), recording is disabled and the buffer is empty.
    assert!(!ctx.flush_tracker.is_enabled());
    assert!(ctx.flush_tracker.take().is_empty());
}

#[test]
fn flush_tracker_disabled_records_nothing() {
    // Negative test: the tracker is opt-in. With it left disabled
    // (default state), programs that flush components must record
    // zero ranges — the `enabled` gate in record() is the kill switch.
    let src = r#"
        template Inner() {
            signal input a;
            signal output out;
            out <== a + 1;
        }
        template Outer() {
            signal input x;
            signal output y;
            component c = Inner();
            c.a <== x;
            y <== c.out;
        }
        component main = Outer();
    "#;

    let (program, errors) = crate::parser::parse_circom(src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {:?}", errors);

    let outer = program
        .definitions
        .iter()
        .find_map(|d| match d {
            crate::ast::Definition::Template(t) if t.name == "Outer" => Some(t),
            _ => None,
        })
        .expect("Outer not found");

    let mut ctx = crate::lowering::context::LoweringContext::from_program(&program);
    // No call to enable() — tracker stays quiet.
    assert!(!ctx.flush_tracker.is_enabled());

    let _ = lower::lower_template_with_ctx(
        outer,
        &std::collections::HashMap::new(),
        &std::collections::HashMap::new(),
        &[],
        &mut ctx,
    )
    .expect("lower_template failed");

    assert!(
        ctx.flush_tracker.take().is_empty(),
        "FlushTracker recorded ranges while disabled — the `enabled` \
         gate in record() is broken",
    );
}
