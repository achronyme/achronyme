use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

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
    pub max_heap: Option<String>,
    pub stress_gc: Option<bool>,
    pub gc_stats: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitSection {
    pub public: Option<Vec<String>>,
    pub witness: Option<Vec<String>>,
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
    pub backend: String,
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
    pub public: Vec<String>,
    pub witness: Vec<String>,
}

// ---------------------------------------------------------------------------
// Walk-up search
// ---------------------------------------------------------------------------

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
// Loading & validation
// ---------------------------------------------------------------------------

/// Parse and validate an `achronyme.toml` file.
pub fn load_toml(path: &Path) -> Result<AchronymeToml> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let toml: AchronymeToml =
        toml::from_str(&content).with_context(|| format!("failed to parse {}", path.display()))?;
    validate(&toml)?;
    Ok(toml)
}

/// Validate semantic constraints on the parsed TOML.
fn validate(toml: &AchronymeToml) -> Result<()> {
    validate_name(&toml.project.name)?;
    validate_version(&toml.project.version)?;

    if let Some(ref build) = toml.build {
        if let Some(ref backend) = build.backend {
            if !matches!(backend.as_str(), "r1cs" | "plonkish") {
                anyhow::bail!(
                    "achronyme.toml: invalid build.backend `{backend}` (expected \"r1cs\" or \"plonkish\")"
                );
            }
        }
        if let Some(ref ef) = build.error_format {
            if !matches!(ef.as_str(), "human" | "json" | "short") {
                anyhow::bail!(
                    "achronyme.toml: invalid build.error_format `{ef}` (expected \"human\", \"json\", or \"short\")"
                );
            }
        }
    }

    if let Some(ref vm) = toml.vm {
        if let Some(ref mh) = vm.max_heap {
            if !mh.is_empty() && parse_size(mh).is_none() {
                anyhow::bail!(
                    "achronyme.toml: invalid vm.max_heap `{mh}` (expected e.g. \"256M\", \"1G\", \"512K\")"
                );
            }
        }
    }

    if let Some(ref circuit) = toml.circuit {
        if let Some(ref vars) = circuit.public {
            for v in vars {
                validate_identifier(v, "circuit.public")?;
            }
        }
        if let Some(ref vars) = circuit.witness {
            for v in vars {
                validate_identifier(v, "circuit.witness")?;
            }
        }
    }

    if let Some(ref entry) = toml.project.entry {
        if !entry.ends_with(".ach") && !entry.ends_with(".achb") {
            anyhow::bail!("achronyme.toml: entry `{entry}` must end in .ach or .achb");
        }
    }

    Ok(())
}

/// Validate a project name: `[a-zA-Z_][a-zA-Z0-9_-]*`
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("project name cannot be empty");
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        anyhow::bail!("invalid project name `{name}`: must start with a letter or underscore");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        anyhow::bail!("invalid project name `{name}`: must match [a-zA-Z_][a-zA-Z0-9_-]*");
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<()> {
    // Simple semver: MAJOR.MINOR.PATCH with optional pre-release
    let parts: Vec<&str> = version.splitn(2, '-').collect();
    let core = parts[0];
    let segments: Vec<&str> = core.split('.').collect();
    if segments.len() != 3 {
        anyhow::bail!(
            "achronyme.toml: invalid version `{version}` (expected semver: MAJOR.MINOR.PATCH)"
        );
    }
    for seg in &segments {
        if seg.parse::<u64>().is_err() {
            anyhow::bail!(
                "achronyme.toml: invalid version `{version}` (non-numeric segment `{seg}`)"
            );
        }
    }
    Ok(())
}

fn validate_identifier(name: &str, field: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("achronyme.toml: empty identifier in {field}");
    }
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        anyhow::bail!("achronyme.toml: invalid identifier `{name}` in {field}");
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        anyhow::bail!("achronyme.toml: invalid identifier `{name}` in {field}");
    }
    Ok(())
}

/// Parse a human-readable size string (e.g., "256M", "1G", "512K") into bytes.
fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, multiplier) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1024usize),
        b'M' | b'm' => (&s[..s.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    let num: usize = num_part.parse().ok()?;
    num.checked_mul(multiplier)
}

// ---------------------------------------------------------------------------
// Config resolution
// ---------------------------------------------------------------------------

/// CLI values extracted for config resolution.
/// All fields are `Option` — `None` means "not explicitly set by the user".
pub struct CliOverrides {
    pub path: Option<String>,
    pub error_format: Option<String>,
    pub backend: Option<String>,
    pub optimize: Option<bool>,
    pub r1cs_path: Option<String>,
    pub wtns_path: Option<String>,
    pub solidity_path: Option<String>,
    pub plonkish_json_path: Option<String>,
    pub max_heap: Option<String>,
    pub stress_gc: bool,
    pub gc_stats: bool,
    pub public: Vec<String>,
    pub witness: Vec<String>,
}

/// Merge CLI overrides + TOML + defaults into a `ProjectConfig`.
pub fn resolve_config(
    cli: &CliOverrides,
    toml: Option<&AchronymeToml>,
    project_root: Option<&Path>,
) -> ProjectConfig {
    let project_name = toml.map(|t| t.project.name.clone());

    // Entry: CLI path > toml entry
    let entry = cli.path.clone().or_else(|| {
        toml.and_then(|t| {
            t.project.entry.as_ref().map(|e| {
                if let Some(root) = project_root {
                    root.join(e).to_string_lossy().into_owned()
                } else {
                    e.clone()
                }
            })
        })
    });

    // Backend: CLI > toml > default
    let backend = cli
        .backend
        .clone()
        .or_else(|| toml.and_then(|t| t.build.as_ref()?.backend.clone()))
        .unwrap_or_else(|| "r1cs".to_string());

    // Optimize: CLI > toml > default (true)
    let optimize = cli
        .optimize
        .or_else(|| toml.and_then(|t| t.build.as_ref()?.optimize))
        .unwrap_or(true);

    // Error format: CLI > toml > default
    let error_format = cli
        .error_format
        .clone()
        .or_else(|| toml.and_then(|t| t.build.as_ref()?.error_format.clone()))
        .unwrap_or_else(|| "human".to_string());

    // Output paths: CLI > toml > defaults
    let r1cs_path = cli
        .r1cs_path
        .clone()
        .or_else(|| toml.and_then(|t| t.build.as_ref()?.output.as_ref()?.r1cs.clone()))
        .unwrap_or_else(|| "circuit.r1cs".to_string());

    let wtns_path = cli
        .wtns_path
        .clone()
        .or_else(|| toml.and_then(|t| t.build.as_ref()?.output.as_ref()?.wtns.clone()))
        .unwrap_or_else(|| "witness.wtns".to_string());

    let binary_path = if cli.path.is_some() {
        None
    } else {
        toml.and_then(|t| {
            let tmpl = t.build.as_ref()?.output.as_ref()?.binary.as_ref()?;
            let name = &t.project.name;
            Some(tmpl.replace("{name}", name))
        })
    };

    let solidity_path = cli.solidity_path.clone().or_else(|| {
        toml.and_then(|t| {
            let p = t.build.as_ref()?.output.as_ref()?.solidity.as_ref()?;
            if p.is_empty() {
                None
            } else {
                Some(p.clone())
            }
        })
    });

    let plonkish_json_path = cli.plonkish_json_path.clone().or_else(|| {
        toml.and_then(|t| {
            let p = t.build.as_ref()?.output.as_ref()?.plonkish_json.as_ref()?;
            if p.is_empty() {
                None
            } else {
                Some(p.clone())
            }
        })
    });

    // VM settings: CLI > toml > defaults
    let max_heap = cli.max_heap.clone().or_else(|| {
        toml.and_then(|t| {
            let mh = t.vm.as_ref()?.max_heap.as_ref()?;
            if mh.is_empty() {
                None
            } else {
                Some(mh.clone())
            }
        })
    });

    let stress_gc = if cli.stress_gc {
        true
    } else {
        toml.and_then(|t| t.vm.as_ref()?.stress_gc).unwrap_or(false)
    };

    let gc_stats = if cli.gc_stats {
        true
    } else {
        toml.and_then(|t| t.vm.as_ref()?.gc_stats).unwrap_or(false)
    };

    // Circuit declarations: CLI > toml (non-empty CLI wins)
    let public = if !cli.public.is_empty() {
        cli.public.clone()
    } else {
        toml.and_then(|t| t.circuit.as_ref()?.public.clone())
            .unwrap_or_default()
    };

    let witness = if !cli.witness.is_empty() {
        cli.witness.clone()
    } else {
        toml.and_then(|t| t.circuit.as_ref()?.witness.clone())
            .unwrap_or_default()
    };

    ProjectConfig {
        project_root: project_root.map(|p| p.to_path_buf()),
        project_name,
        entry,
        backend,
        optimize,
        error_format,
        r1cs_path,
        wtns_path,
        binary_path,
        solidity_path,
        plonkish_json_path,
        max_heap,
        stress_gc,
        gc_stats,
        public,
        witness,
    }
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

[circuit]
public = ["x", "y"]
witness = ["w"]
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
        let public = toml.circuit.as_ref().unwrap().public.as_ref().unwrap();
        assert_eq!(public, &["x", "y"]);
    }

    #[test]
    fn validate_invalid_name_digit() {
        assert!(validate_name("3bad").is_err());
    }

    #[test]
    fn validate_invalid_name_space() {
        assert!(validate_name("has space").is_err());
    }

    #[test]
    fn validate_valid_names() {
        validate_name("hello").unwrap();
        validate_name("my-circuit").unwrap();
        validate_name("_private").unwrap();
        validate_name("A_B-c").unwrap();
    }

    #[test]
    fn validate_invalid_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"t\"\nversion = \"0.1.0\"\n\n[build]\nbackend = \"groth\"\n",
        )
        .unwrap();
        assert!(load_toml(&path).is_err());
    }

    #[test]
    fn validate_invalid_version() {
        assert!(validate_version("abc").is_err());
        assert!(validate_version("1.2").is_err());
        validate_version("1.0.0").unwrap();
        validate_version("0.1.0-beta.10").unwrap();
    }

    #[test]
    fn resolve_cli_overrides_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"t\"\nversion = \"0.1.0\"\n\n[build]\nbackend = \"plonkish\"\n",
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();

        let cli = CliOverrides {
            path: None,
            error_format: None,
            backend: Some("r1cs".to_string()),
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            public: vec![],
            witness: vec![],
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        assert_eq!(config.backend, "r1cs"); // CLI wins
    }

    #[test]
    fn resolve_defaults_no_toml() {
        let cli = CliOverrides {
            path: None,
            error_format: None,
            backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            public: vec![],
            witness: vec![],
        };

        let config = resolve_config(&cli, None, None);
        assert_eq!(config.backend, "r1cs");
        assert!(config.optimize);
        assert_eq!(config.error_format, "human");
        assert_eq!(config.r1cs_path, "circuit.r1cs");
        assert_eq!(config.wtns_path, "witness.wtns");
    }

    #[test]
    fn resolve_entry_from_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"t\"\nversion = \"0.1.0\"\nentry = \"src/main.ach\"\n",
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();

        let cli = CliOverrides {
            path: None,
            error_format: None,
            backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            public: vec![],
            witness: vec![],
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        let expected = tmp
            .path()
            .join("src/main.ach")
            .to_string_lossy()
            .into_owned();
        assert_eq!(config.entry.unwrap(), expected);
    }

    #[test]
    fn resolve_name_template_in_binary_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"foo\"\nversion = \"0.1.0\"\n\n[build.output]\nbinary = \"build/{name}.achb\"\n",
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();

        let cli = CliOverrides {
            path: None,
            error_format: None,
            backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            public: vec![],
            witness: vec![],
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        assert_eq!(config.binary_path.unwrap(), "build/foo.achb");
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
