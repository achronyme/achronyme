use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::config::validate_name;

/// Create a new Achronyme project under `base_dir`.
///
/// The project directory `base_dir/<name>` must not already exist.
pub fn init_project(name: &str, template: &str, base_dir: &Path) -> Result<()> {
    validate_name(name)?;

    let dir = base_dir.join(name);
    if dir.exists() {
        anyhow::bail!("directory `{name}` already exists");
    }

    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir)
        .with_context(|| format!("cannot create directory `{}`", src_dir.display()))?;

    // achronyme.toml
    let toml_content = format!(
        r#"[project]
name = "{name}"
version = "0.1.0"

[build]
backend = "r1cs"
"#
    );
    fs::write(dir.join("achronyme.toml"), toml_content).context("cannot write achronyme.toml")?;

    // src/main.ach
    let main_content = match template {
        "vm" => format!(
            r#"// {name}
let message = "Hello from {name}!"
print(message)
"#
        ),
        "prove" => format!(
            r#"// {name}
let a = 6
let b = 7
let result = prove {{
    public out
    witness x
    witness y
    assert_eq(x * y, out)
}}
print("Proof:", result)
"#
        ),
        // "circuit" or default
        _ => format!(
            r#"// {name}
public out
witness a
witness b
assert_eq(a * b, out)
"#
        ),
    };
    fs::write(src_dir.join("main.ach"), main_content).context("cannot write src/main.ach")?;

    // .gitignore
    fs::write(dir.join(".gitignore"), "/build/\n*.r1cs\n*.wtns\n*.achb\n")
        .context("cannot write .gitignore")?;

    eprintln!("Created project `{name}` with template `{template}`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_structure() {
        let tmp = tempfile::tempdir().unwrap();

        init_project("test-proj", "circuit", tmp.path()).unwrap();

        assert!(tmp.path().join("test-proj/achronyme.toml").exists());
        assert!(tmp.path().join("test-proj/src/main.ach").exists());
        assert!(tmp.path().join("test-proj/.gitignore").exists());

        let toml = fs::read_to_string(tmp.path().join("test-proj/achronyme.toml")).unwrap();
        assert!(toml.contains("name = \"test-proj\""));

        let main = fs::read_to_string(tmp.path().join("test-proj/src/main.ach")).unwrap();
        assert!(main.contains("public out"));
        assert!(main.contains("witness a"));
    }

    #[test]
    fn init_vm_template() {
        let tmp = tempfile::tempdir().unwrap();

        init_project("vm-proj", "vm", tmp.path()).unwrap();

        let main = fs::read_to_string(tmp.path().join("vm-proj/src/main.ach")).unwrap();
        assert!(main.contains("print("));
        assert!(!main.contains("public"));
    }

    #[test]
    fn init_prove_template() {
        let tmp = tempfile::tempdir().unwrap();

        init_project("prove-proj", "prove", tmp.path()).unwrap();

        let main = fs::read_to_string(tmp.path().join("prove-proj/src/main.ach")).unwrap();
        assert!(main.contains("prove {"));
        assert!(main.contains("print("));
    }

    #[test]
    fn init_existing_dir_fails() {
        let tmp = tempfile::tempdir().unwrap();

        fs::create_dir(tmp.path().join("exists")).unwrap();
        let err = init_project("exists", "circuit", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn init_invalid_name_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let err = init_project("123bad", "circuit", tmp.path()).unwrap_err();
        assert!(err.to_string().contains("invalid project name"));
    }
}
