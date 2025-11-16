use achronyme_eval::Evaluator;
use achronyme_types::value::Value;
use std::fs;
use std::path::Path;

fn eval(source: &str) -> Result<Value, String> {
    let mut evaluator = Evaluator::new();
    evaluator.eval_str(source)
}

fn setup_module_files() {
    // Create a temporary test directory
    let test_dir = Path::new("test_type_modules");
    if !test_dir.exists() {
        let _ = fs::create_dir(test_dir); // Ignore error if directory already exists
    }

    // Create a module that exports a type alias
    let type_module_content = r#"
// Module that exports type aliases
type Point = { x: Number, y: Number }
type UserId = Number
type Result = { success: Boolean, value: Number }

// Also export some values
let createPoint = (x, y) => { x: x, y: y }
let origin = { x: 0, y: 0 }

export { Point, UserId, Result, createPoint, origin }
"#;
    fs::write(test_dir.join("types.soc"), type_module_content).unwrap();

    // Create a module that uses imported types
    let user_module_content = r#"
import { Point, createPoint } from "./types"

// Use imported type for annotations
let movePoint = (p: Point, dx: Number, dy: Number): Point =>
    { x: p.x + dx, y: p.y + dy }

export { movePoint }
"#;
    fs::write(test_dir.join("geometry.soc"), user_module_content).unwrap();
}

fn cleanup_module_files() {
    let test_dir = Path::new("test_type_modules");
    if test_dir.exists() {
        let _ = fs::remove_dir_all(test_dir); // Ignore error if cleanup fails
    }
}

#[test]
fn test_export_type_alias() {
    setup_module_files();

    // Test that we can evaluate a module that exports types
    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_modules".to_string()));

    let result = evaluator.eval_str(r#"
        import { Point, createPoint } from "./types"
        let p: Point = createPoint(3, 4)
        p.x + p.y
    "#);

    cleanup_module_files();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(7.0));
}

#[test]
fn test_import_type_alias_used_in_annotation() {
    setup_module_files();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_modules".to_string()));

    let result = evaluator.eval_str(r#"
        import { UserId } from "./types"
        let userId: UserId = 42
        userId
    "#);

    cleanup_module_files();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

#[test]
fn test_import_both_values_and_types() {
    setup_module_files();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_modules".to_string()));

    let result = evaluator.eval_str(r#"
        import { Point, Result, createPoint, origin } from "./types"
        let p: Point = createPoint(1, 2)
        let r: Result = { success: true, value: p.x + p.y + origin.x }
        r.value
    "#);

    cleanup_module_files();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(3.0));
}

#[test]
fn test_export_type_with_alias() {
    // Create temp files for this specific test
    let test_dir = Path::new("test_type_alias_export");
    if !test_dir.exists() {
        fs::create_dir(test_dir).unwrap();
    }

    let module_content = r#"
type InternalPoint = { x: Number, y: Number }
export { InternalPoint as Point }
"#;
    fs::write(test_dir.join("module.soc"), module_content).unwrap();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_alias_export".to_string()));

    let result = evaluator.eval_str(r#"
        import { Point } from "./module"
        let p: Point = { x: 10, y: 20 }
        p.x
    "#);

    fs::remove_dir_all(test_dir).unwrap();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_import_type_with_alias() {
    setup_module_files();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_modules".to_string()));

    let result = evaluator.eval_str(r#"
        import { Point as Vec2D } from "./types"
        let p: Vec2D = { x: 5, y: 10 }
        p.y
    "#);

    cleanup_module_files();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_export_nonexistent_type_error() {
    let result = eval(r#"
        export { NonExistentType }
    "#);

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[test]
fn test_export_type_only_no_values() {
    let test_dir = Path::new("test_type_only_export");
    if !test_dir.exists() {
        fs::create_dir(test_dir).unwrap();
    }

    let module_content = r#"
type Config = { debug: Boolean, timeout: Number }
export { Config }
"#;
    fs::write(test_dir.join("config.soc"), module_content).unwrap();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_only_export".to_string()));

    let result = evaluator.eval_str(r#"
        import { Config } from "./config"
        let cfg: Config = { debug: true, timeout: 3000 }
        cfg.timeout
    "#);

    fs::remove_dir_all(test_dir).unwrap();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(3000.0));
}

#[test]
fn test_complex_type_export() {
    let test_dir = Path::new("test_complex_type_export");
    if !test_dir.exists() {
        fs::create_dir(test_dir).unwrap();
    }

    let module_content = r#"
// Complex types with unions
type Status = String
type Response = { status: Status, data: Number | null }

export { Status, Response }
"#;
    fs::write(test_dir.join("api.soc"), module_content).unwrap();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_complex_type_export".to_string()));

    let result = evaluator.eval_str(r#"
        import { Response } from "./api"
        let res: Response = { status: "ok", data: 42 }
        res.data
    "#);

    fs::remove_dir_all(test_dir).unwrap();

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

#[test]
fn test_import_nonexistent_type_error() {
    setup_module_files();

    let mut evaluator = Evaluator::new();
    evaluator.set_current_file_dir_direct(Some("test_type_modules".to_string()));

    let result = evaluator.eval_str(r#"
        import { NonExistent } from "./types"
        42
    "#);

    cleanup_module_files();

    assert!(result.is_err());
    assert!(result.unwrap_err().contains("is not exported"));
}
