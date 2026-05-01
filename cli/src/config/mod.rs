mod resolution;
mod validation;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub use resolution::{resolve_config, CliOverrides};
pub use validation::validate_name;

// ---------------------------------------------------------------------------
// TOML schema (1:1 with file structure)
// ---------------------------------------------------------------------------

/// Top-level `achronyme.toml` representation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AchronymeToml {
    pub project: ProjectSection,
    pub build: Option<BuildSection>,
    pub vm: Option<VmSection>,
    pub circuit: Option<CircuitSection>,
    pub circom: Option<CircomSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSection {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub license: Option<String>,
    pub authors: Option<Vec<String>>,
    pub entry: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildSection {
    pub backend: Option<String>,
    pub optimize: Option<bool>,
    pub error_format: Option<String>,
    pub output: Option<OutputSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    pub r1cs: Option<String>,
    pub wtns: Option<String>,
    pub binary: Option<String>,
    pub solidity: Option<String>,
    pub plonkish_json: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmSection {
    pub prove_backend: Option<String>,
    pub max_heap: Option<String>,
    pub stress_gc: Option<bool>,
    pub gc_stats: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSection {
    pub prime: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircomSection {
    pub libs: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Resolved config (merged CLI + TOML + defaults)
// ---------------------------------------------------------------------------

/// Fully resolved configuration after merging CLI flags, TOML, and defaults.
#[derive(Debug)]
pub struct ProjectConfig {
    pub project_root: Option<PathBuf>,
    pub project_name: Option<String>,
    pub entry: Option<String>,
    pub prime: String,
    pub backend: String,
    pub prove_backend: String,
    pub optimize: bool,
    pub error_format: String,
    pub r1cs_path: String,
    pub wtns_path: String,
    pub binary_path: Option<String>,
    pub solidity_path: Option<String>,
    pub plonkish_json_path: Option<String>,
    pub max_heap: Option<String>,
    pub stress_gc: bool,
    pub gc_stats: bool,
    pub circuit_stats: bool,
    pub circom_lib_dirs: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Walk-up search
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) const TOML_FILENAME: &str = "achronyme.toml";
#[cfg(not(test))]
const TOML_FILENAME: &str = "achronyme.toml";

/// Search for `achronyme.toml` starting from `start_dir`, walking up.
/// Returns the path to the toml file if found.
pub fn find_project_toml(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(TOML_FILENAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Parse and validate an `achronyme.toml` file.
pub fn load_toml(path: &Path) -> Result<AchronymeToml> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let toml: AchronymeToml =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;
    validation::validate(&toml)?;
    Ok(toml)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn find_toml_walks_up() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();
        let toml_path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &toml_path,
            "[project]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let found = find_project_toml(&nested).unwrap();
        assert_eq!(found, toml_path);
    }

    #[test]
    fn find_toml_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(find_project_toml(tmp.path()).is_none());
    }

    #[test]
    fn load_toml_minimal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(&path, "[project]\nname = \"hello\"\nversion = \"1.0.0\"\n").unwrap();
        let toml = load_toml(&path).unwrap();
        assert_eq!(toml.project.name, "hello");
        assert_eq!(toml.project.version, "1.0.0");
        assert!(toml.build.is_none());
    }

    #[test]
    fn load_toml_full() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            r#"
[project]
name = "my-circuit"
version = "0.1.0"
description = "A test circuit"
entry = "src/main.ach"

[build]
backend = "plonkish"
optimize = false
error_format = "json"

[build.output]
r1cs = "build/out.r1cs"
wtns = "build/out.wtns"
binary = "build/{name}.achb"

[vm]
max_heap = "256M"
stress_gc = true
gc_stats = true
"#,
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();
        assert_eq!(toml.project.name, "my-circuit");
        assert_eq!(
            toml.build.as_ref().unwrap().backend.as_deref(),
            Some("plonkish")
        );
        assert_eq!(toml.vm.as_ref().unwrap().max_heap.as_deref(), Some("256M"));
    }

    #[test]
    fn load_toml_with_circom_libs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            r#"
[project]
name = "with-circom"
version = "0.1.0"

[circom]
libs = ["vendor/circomlib/circuits", "lib/custom"]
"#,
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();
        let libs = toml.circom.as_ref().unwrap().libs.as_ref().unwrap();
        assert_eq!(libs.len(), 2);
        assert_eq!(libs[0], "vendor/circomlib/circuits");
        assert_eq!(libs[1], "lib/custom");
    }

    #[test]
    fn load_toml_circom_section_optional() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"no-circom\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();
        assert!(toml.circom.is_none());
    }

    #[test]
    fn unknown_field_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"t\"\nversion = \"0.1.0\"\n\n[crypto]\ncurve = \"bn254\"\n",
        )
        .unwrap();
        // deny_unknown_fields should reject unknown sections
        assert!(load_toml(&path).is_err());
    }
}
