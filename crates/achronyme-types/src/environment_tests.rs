use super::*;

#[test]
fn test_define_and_get() {
    let mut env = Environment::new();
    env.define("x".to_string(), Value::Number(5.0)).unwrap();
    let val = env.get("x").unwrap();
    assert_eq!(val, Value::Number(5.0));
}

#[test]
fn test_shadowing_in_new_scope() {
    let mut env = Environment::new();

    // Define in global scope
    env.define("x".to_string(), Value::Number(5.0)).unwrap();
    assert_eq!(env.get("x").unwrap(), Value::Number(5.0));

    // Push new scope and shadow
    env.push_scope();
    env.define("x".to_string(), Value::Number(10.0)).unwrap();
    assert_eq!(env.get("x").unwrap(), Value::Number(10.0));

    // Pop scope, back to original
    env.pop_scope();
    assert_eq!(env.get("x").unwrap(), Value::Number(5.0));
}

#[test]
fn test_shadowing_in_same_scope() {
    let mut env = Environment::new();

    // First definition
    env.define("x".to_string(), Value::Number(5.0)).unwrap();
    assert_eq!(env.get("x").unwrap(), Value::Number(5.0));

    // Redefine in same scope (should work now)
    env.define("x".to_string(), Value::Number(10.0)).unwrap();
    assert_eq!(env.get("x").unwrap(), Value::Number(10.0));
}

#[test]
fn test_nested_scopes() {
    let mut env = Environment::new();

    // Global: x=1, y=2
    env.define("x".to_string(), Value::Number(1.0)).unwrap();
    env.define("y".to_string(), Value::Number(2.0)).unwrap();

    // Level 1: x=10 (shadows), z=3
    env.push_scope();
    env.define("x".to_string(), Value::Number(10.0)).unwrap();
    env.define("z".to_string(), Value::Number(3.0)).unwrap();
    assert_eq!(env.get("x").unwrap(), Value::Number(10.0));
    assert_eq!(env.get("y").unwrap(), Value::Number(2.0)); // From global
    assert_eq!(env.get("z").unwrap(), Value::Number(3.0));

    // Level 2: y=20 (shadows)
    env.push_scope();
    env.define("y".to_string(), Value::Number(20.0)).unwrap();
    assert_eq!(env.get("x").unwrap(), Value::Number(10.0)); // From level 1
    assert_eq!(env.get("y").unwrap(), Value::Number(20.0)); // Current level
    assert_eq!(env.get("z").unwrap(), Value::Number(3.0)); // From level 1

    // Pop to level 1
    env.pop_scope();
    assert_eq!(env.get("y").unwrap(), Value::Number(2.0)); // Back to global

    // Pop to global
    env.pop_scope();
    assert_eq!(env.get("x").unwrap(), Value::Number(1.0));
    assert!(env.get("z").is_err()); // z no longer exists
}

#[test]
fn test_get_undefined_fails() {
    let env = Environment::new();
    let result = env.get("x");
    assert!(result.is_err());
}

#[test]
fn test_has() {
    let mut env = Environment::new();
    assert!(!env.has("x"));
    env.define("x".to_string(), Value::Number(5.0)).unwrap();
    assert!(env.has("x"));

    // Should find in outer scope too
    env.push_scope();
    assert!(env.has("x"));
}

#[test]
fn test_set_existing() {
    let mut env = Environment::new();
    env.define("x".to_string(), Value::Number(5.0)).unwrap();
    env.set("x", Value::Number(10.0)).unwrap();
    let val = env.get("x").unwrap();
    assert_eq!(val, Value::Number(10.0));
}

#[test]
fn test_set_in_outer_scope() {
    let mut env = Environment::new();
    env.define("x".to_string(), Value::Number(5.0)).unwrap();

    env.push_scope();
    env.set("x", Value::Number(10.0)).unwrap(); // Shadows in current scope (new semantics)

    // In current scope, we see the new value
    assert_eq!(env.get("x").unwrap(), Value::Number(10.0));

    env.pop_scope();
    // After popping, we see the original value (shadowing, not mutation)
    assert_eq!(env.get("x").unwrap(), Value::Number(5.0));
}

#[test]
fn test_set_undefined_fails() {
    let mut env = Environment::new();
    let result = env.set("x", Value::Number(5.0));
    assert!(result.is_err());
}

#[test]
fn test_clear() {
    let mut env = Environment::new();
    env.define("x".to_string(), Value::Number(5.0)).unwrap();
    env.define("y".to_string(), Value::Number(10.0)).unwrap();
    assert_eq!(env.len(), 2);
    env.clear();
    assert_eq!(env.len(), 0);
    assert!(!env.has("x"));
}

#[test]
fn test_snapshot_flattens_scopes() {
    let mut env = Environment::new();

    // Global: x=1, y=2
    env.define("x".to_string(), Value::Number(1.0)).unwrap();
    env.define("y".to_string(), Value::Number(2.0)).unwrap();

    // Nested: x=10 (shadows), z=3
    env.push_scope();
    env.define("x".to_string(), Value::Number(10.0)).unwrap();
    env.define("z".to_string(), Value::Number(3.0)).unwrap();

    let snapshot = env.snapshot();
    assert_eq!(snapshot.get("x").unwrap(), &Value::Number(10.0)); // Inner value
    assert_eq!(snapshot.get("y").unwrap(), &Value::Number(2.0));
    assert_eq!(snapshot.get("z").unwrap(), &Value::Number(3.0));
}

#[test]
fn test_scope_depth() {
    let mut env = Environment::new();
    assert_eq!(env.scope_depth(), 0);

    env.push_scope();
    assert_eq!(env.scope_depth(), 1);

    env.push_scope();
    assert_eq!(env.scope_depth(), 2);

    env.pop_scope();
    assert_eq!(env.scope_depth(), 1);
}
