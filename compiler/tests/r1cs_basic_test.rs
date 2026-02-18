use compiler::r1cs_backend::R1CSCompiler;
use compiler::r1cs_error::R1CSError;

#[test]
fn test_new_compiler_is_empty() {
    let rc = R1CSCompiler::new();
    assert_eq!(rc.cs.num_variables(), 1); // only ONE wire
    assert_eq!(rc.cs.num_pub_inputs(), 0);
    assert_eq!(rc.cs.num_constraints(), 0);
    assert!(rc.bindings.is_empty());
    assert!(rc.public_inputs.is_empty());
    assert!(rc.witnesses.is_empty());
}

#[test]
fn test_declare_public() {
    let mut rc = R1CSCompiler::new();
    let var = rc.declare_public("root");

    assert_eq!(var.index(), 1); // first public after ONE
    assert_eq!(rc.cs.num_pub_inputs(), 1);
    assert_eq!(rc.public_inputs, vec!["root"]);
    assert_eq!(rc.lookup("root").unwrap(), var);
}

#[test]
fn test_declare_witness() {
    let mut rc = R1CSCompiler::new();
    // Declare a public first to test ordering
    let pub_var = rc.declare_public("out");
    let wit_var = rc.declare_witness("secret");

    assert_eq!(pub_var.index(), 1);
    assert_eq!(wit_var.index(), 2);
    assert_eq!(rc.witnesses, vec!["secret"]);
    assert_eq!(rc.lookup("secret").unwrap(), wit_var);
}

#[test]
fn test_declare_multiple() {
    let mut rc = R1CSCompiler::new();
    let a = rc.declare_public("a");
    let b = rc.declare_public("b");
    let c = rc.declare_witness("c");
    let d = rc.declare_witness("d");

    assert_eq!(a.index(), 1);
    assert_eq!(b.index(), 2);
    assert_eq!(c.index(), 3);
    assert_eq!(d.index(), 4);
    assert_eq!(rc.cs.num_variables(), 5);
    assert_eq!(rc.cs.num_pub_inputs(), 2);
    assert_eq!(rc.public_inputs, vec!["a", "b"]);
    assert_eq!(rc.witnesses, vec!["c", "d"]);
}

#[test]
fn test_lookup_undeclared() {
    let rc = R1CSCompiler::new();
    let err = rc.lookup("nonexistent").unwrap_err();
    match err {
        R1CSError::UndeclaredVariable(name) => assert_eq!(name, "nonexistent"),
        _ => panic!("expected UndeclaredVariable"),
    }
}

#[test]
fn test_lookup_returns_correct_variable() {
    let mut rc = R1CSCompiler::new();
    let x = rc.declare_witness("x");
    let y = rc.declare_witness("y");

    assert_eq!(rc.lookup("x").unwrap(), x);
    assert_eq!(rc.lookup("y").unwrap(), y);
    assert!(rc.lookup("z").is_err());
}

#[test]
fn test_rebinding_overwrites() {
    let mut rc = R1CSCompiler::new();
    let v1 = rc.declare_witness("x");
    let v2 = rc.declare_witness("x"); // rebind same name

    // The binding should point to the latest variable
    assert_eq!(rc.lookup("x").unwrap(), v2);
    assert_ne!(v1, v2);
}
