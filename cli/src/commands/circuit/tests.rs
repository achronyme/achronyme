use std::collections::HashMap;

use memory::FieldElement;

use super::inputs::{parse_inputs, parse_inputs_toml};

// Type alias to constrain F = Bn254Fr in tests (avoids turbofish noise).
type Fe = FieldElement;

#[test]
fn parse_inputs_positive_decimal() {
    let map: HashMap<String, Fe> = parse_inputs("x=42,y=0").unwrap();
    assert_eq!(map["x"], Fe::from_u64(42));
    assert_eq!(map["y"], Fe::ZERO);
}

#[test]
fn parse_inputs_negative_decimal() {
    let map: HashMap<String, Fe> = parse_inputs("x=-1").unwrap();
    // -1 mod p = p - 1
    assert_eq!(map["x"], Fe::from_u64(1).neg());
}

#[test]
fn parse_inputs_negative_large() {
    let map: HashMap<String, Fe> = parse_inputs("a=-42,b=7").unwrap();
    assert_eq!(map["a"], Fe::from_u64(42).neg());
    assert_eq!(map["b"], Fe::from_u64(7));
}

#[test]
fn parse_inputs_hex() {
    let map: HashMap<String, Fe> = parse_inputs("x=0xFF").unwrap();
    assert_eq!(map["x"], Fe::from_u64(255));
}

#[test]
fn parse_inputs_empty_pair_skipped() {
    let map: HashMap<String, Fe> = parse_inputs("x=1,,y=2").unwrap();
    assert_eq!(map.len(), 2);
}

#[test]
fn parse_inputs_invalid_pair_errors() {
    assert!(parse_inputs::<memory::Bn254Fr>("no_equals").is_err());
}

// --- parse_inputs_toml tests ---

fn write_toml(content: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn toml_scalar_string() {
    let f = write_toml("x = \"42\"\ny = \"0xFF\"");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map["x"], Fe::from_u64(42));
    assert_eq!(map["y"], Fe::from_u64(255));
}

#[test]
fn toml_scalar_integer() {
    let f = write_toml("x = 42\ny = 0");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map["x"], Fe::from_u64(42));
    assert_eq!(map["y"], Fe::ZERO);
}

#[test]
fn toml_negative_string() {
    let f = write_toml("x = \"-1\"");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map["x"], Fe::from_u64(1).neg());
}

#[test]
fn toml_negative_integer() {
    let f = write_toml("x = -42");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map["x"], Fe::from_u64(42).neg());
}

#[test]
fn toml_array_expands_to_indexed() {
    let f = write_toml("path = [\"10\", \"20\", \"30\"]");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map.len(), 3);
    assert_eq!(map["path_0"], Fe::from_u64(10));
    assert_eq!(map["path_1"], Fe::from_u64(20));
    assert_eq!(map["path_2"], Fe::from_u64(30));
}

#[test]
fn toml_array_integer_elements() {
    let f = write_toml("indices = [0, 1, 0]");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map.len(), 3);
    assert_eq!(map["indices_0"], Fe::ZERO);
    assert_eq!(map["indices_1"], Fe::ONE);
    assert_eq!(map["indices_2"], Fe::ZERO);
}

#[test]
fn toml_mixed_scalars_and_arrays() {
    let f = write_toml("root = \"999\"\nleaf = \"1\"\npath = [\"2\", \"3\"]");
    let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
    assert_eq!(map.len(), 4);
    assert_eq!(map["root"], Fe::from_u64(999));
    assert_eq!(map["leaf"], Fe::ONE);
    assert_eq!(map["path_0"], Fe::from_u64(2));
    assert_eq!(map["path_1"], Fe::from_u64(3));
}

#[test]
fn toml_invalid_type_rejected() {
    let f = write_toml("x = true");
    assert!(parse_inputs_toml::<memory::Bn254Fr>(f.path().to_str().unwrap()).is_err());
}

#[test]
fn toml_file_not_found() {
    assert!(parse_inputs_toml::<memory::Bn254Fr>("/tmp/nonexistent_ach_inputs.toml").is_err());
}
