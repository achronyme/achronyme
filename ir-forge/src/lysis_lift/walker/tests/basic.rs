use super::*;

#[test]
fn lowers_empty_body_to_halt_only() {
    let out = run(&[]);
    assert!(out.is_empty());
}
