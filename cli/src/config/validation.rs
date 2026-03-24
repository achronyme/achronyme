use anyhow::Result;

use super::AchronymeToml;

/// Validate semantic constraints on the parsed TOML.
pub(super) fn validate(toml: &AchronymeToml) -> Result<()> {
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
        if let Some(ref pb) = vm.prove_backend {
            if !matches!(pb.as_str(), "r1cs" | "plonkish") {
                anyhow::bail!(
                    "achronyme.toml: invalid vm.prove_backend `{pb}` (expected \"r1cs\" or \"plonkish\")"
                );
            }
        }
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
pub(super) fn parse_size(s: &str) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_toml, TOML_FILENAME};
    use std::fs;

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
}
