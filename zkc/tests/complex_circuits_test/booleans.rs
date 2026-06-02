use super::helpers::{both_verify, fe, inputs, r1cs_verify};

#[test]
fn boolean_chain_true() {
    // (a < b) && (c > d) || !(e == f) with a=3,b=7,c=10,d=2,e=1,f=2
    // (3<7)=T && (10>2)=T || !(1==2)=T → T && T || T = T
    let source = r#"
let r = (a < b) && (c > d) || !(e == f)
assert(r)
"#;
    let inp = inputs(&[
        ("a", fe(3)),
        ("b", fe(7)),
        ("c", fe(10)),
        ("d", fe(2)),
        ("e", fe(1)),
        ("f", fe(2)),
    ]);
    both_verify(source, &[], &["a", "b", "c", "d", "e", "f"], &inp);
}

#[test]
fn boolean_chain_false() {
    // (a < b) && (c > d) || !(e == f) with a=7,b=3,c=2,d=10,e=5,f=5
    // (7<3)=F && (2>10)=F || !(5==5)=F → F && F || F = F
    let source = r#"
let r = (a < b) && (c > d) || !(e == f)
assert_eq(r, expected)
"#;
    let inp = inputs(&[
        ("expected", fe(0)),
        ("a", fe(7)),
        ("b", fe(3)),
        ("c", fe(2)),
        ("d", fe(10)),
        ("e", fe(5)),
        ("f", fe(5)),
    ]);
    both_verify(source, &["expected"], &["a", "b", "c", "d", "e", "f"], &inp);
}

#[test]
fn boolean_with_mux() {
    // if (a < b) && !(c == d) { x } else { y }
    // a=3,b=7,c=1,d=2 → (T) && (T) = T → x=100
    let source = r#"
let cond = (a < b) && !(c == d)
let r = if cond { x } else { y }
assert_eq(r, out)
"#;
    let inp = inputs(&[
        ("out", fe(100)),
        ("a", fe(3)),
        ("b", fe(7)),
        ("c", fe(1)),
        ("d", fe(2)),
        ("x", fe(100)),
        ("y", fe(200)),
    ]);
    both_verify(source, &["out"], &["a", "b", "c", "d", "x", "y"], &inp);
}

#[test]
fn boolean_chain_constraint_count() {
    // Complex boolean expression should produce many constraints
    let source = r#"
let r1 = a < b
let r2 = c > d
let r3 = e == f
let r4 = r1 && r2
let r5 = !r3
let r6 = r4 || r5
assert(r6)
"#;
    let inp = inputs(&[
        ("a", fe(3)),
        ("b", fe(7)),
        ("c", fe(10)),
        ("d", fe(2)),
        ("e", fe(1)),
        ("f", fe(2)),
    ]);
    let rc = r1cs_verify(source, &[], &["a", "b", "c", "d", "e", "f"], &inp);
    // 2 IsLt (~760 each) + 1 IsEq (2) + And (3) + Not (1) + Or (3) + Assert (2) ≈ 1531
    assert!(
        rc.cs.num_constraints() > 1500,
        "boolean chain should have >1500 constraints, got {}",
        rc.cs.num_constraints()
    );
}

// ============================================================================
// MEDIUM Priority: Nested For Loops (3 tests)
