use std::path::Path;

use super::{AchronymeToml, ProjectConfig};

/// CLI values extracted for config resolution.
/// All fields are `Option` — `None` means "not explicitly set by the user".
pub struct CliOverrides {
    pub path: Option<String>,
    pub error_format: Option<String>,
    pub prime: Option<String>,
    pub backend: Option<String>,
    pub prove_backend: Option<String>,
    pub optimize: Option<bool>,
    pub r1cs_path: Option<String>,
    pub wtns_path: Option<String>,
    pub solidity_path: Option<String>,
    pub plonkish_json_path: Option<String>,
    pub max_heap: Option<String>,
    pub stress_gc: bool,
    pub gc_stats: bool,
    pub circuit_stats: bool,
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

    // Prime: CLI > toml circuit.prime > default "bn254"
    let prime = cli
        .prime
        .clone()
        .or_else(|| toml.and_then(|t| t.circuit.as_ref()?.prime.clone()))
        .unwrap_or_else(|| "bn254".to_string());

    // Backend: CLI > toml > default
    let backend = cli
        .backend
        .clone()
        .or_else(|| toml.and_then(|t| t.build.as_ref()?.backend.clone()))
        .unwrap_or_else(|| "r1cs".to_string());

    // Prove backend: CLI > toml vm.prove_backend > default "r1cs"
    let prove_backend = cli
        .prove_backend
        .clone()
        .or_else(|| toml.and_then(|t| t.vm.as_ref()?.prove_backend.clone()))
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

    let circuit_stats = cli.circuit_stats;

    ProjectConfig {
        project_root: project_root.map(|p| p.to_path_buf()),
        project_name,
        entry,
        prime,
        backend,
        prove_backend,
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
        circuit_stats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_toml, TOML_FILENAME};
    use std::fs;

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
            prime: None,
            backend: Some("r1cs".to_string()),
            prove_backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: false,
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        assert_eq!(config.backend, "r1cs"); // CLI wins
    }

    #[test]
    fn resolve_defaults_no_toml() {
        let cli = CliOverrides {
            path: None,
            error_format: None,
            prime: None,
            backend: None,
            prove_backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: false,
        };

        let config = resolve_config(&cli, None, None);
        assert_eq!(config.prime, "bn254"); // default
        assert_eq!(config.backend, "r1cs");
        assert!(config.optimize);
        assert_eq!(config.error_format, "human");
        assert_eq!(config.r1cs_path, "circuit.r1cs");
        assert_eq!(config.wtns_path, "witness.wtns");
    }

    #[test]
    fn resolve_prime_from_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"t\"\nversion = \"0.1.0\"\n\n[circuit]\nprime = \"goldilocks\"\n",
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();

        let cli = CliOverrides {
            path: None,
            error_format: None,
            prime: None,
            backend: None,
            prove_backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: false,
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        assert_eq!(config.prime, "goldilocks");
    }

    #[test]
    fn resolve_prime_cli_overrides_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(TOML_FILENAME);
        fs::write(
            &path,
            "[project]\nname = \"t\"\nversion = \"0.1.0\"\n\n[circuit]\nprime = \"goldilocks\"\n",
        )
        .unwrap();
        let toml = load_toml(&path).unwrap();

        let cli = CliOverrides {
            path: None,
            error_format: None,
            prime: Some("bls12-381".to_string()),
            backend: None,
            prove_backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: false,
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        assert_eq!(config.prime, "bls12-381"); // CLI wins
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
            prime: None,
            backend: None,
            prove_backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: false,
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
            prime: None,
            backend: None,
            prove_backend: None,
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: false,
        };

        let config = resolve_config(&cli, Some(&toml), Some(tmp.path()));
        assert_eq!(config.binary_path.unwrap(), "build/foo.achb");
    }
}
