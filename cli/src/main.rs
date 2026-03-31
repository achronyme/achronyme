use anyhow::Result;
use clap::Parser;
use cli::commands::ErrorFormat;
use cli::config::{self, CliOverrides};

mod args;

use args::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Init is self-contained, no config loading needed ──
    if let Commands::Init {
        ref name,
        ref template,
    } = cli.command
    {
        let cwd = std::env::current_dir()?;
        return cli::init::init_project(name, template, &cwd);
    }

    // ── Find and load achronyme.toml (unless --no-config) ──
    let (toml, project_root) = if cli.no_config {
        (None, None)
    } else {
        let start_dir = command_start_dir(&cli.command);
        match config::find_project_toml(&start_dir) {
            Some(toml_path) => {
                let root = toml_path.parent().unwrap().to_path_buf();
                let toml = config::load_toml(&toml_path)?;
                (Some(toml), Some(root))
            }
            None => (None, None),
        }
    };

    // ── Build CLI overrides from command-specific fields ──
    let overrides = build_overrides(&cli);

    // ── Resolve merged config ──
    let cfg = config::resolve_config(&overrides, toml.as_ref(), project_root.as_deref());

    // ── Parse error format ──
    let ef = match cfg.error_format.as_str() {
        "json" => ErrorFormat::Json,
        "short" => ErrorFormat::Short,
        "human" => ErrorFormat::Human,
        other => {
            return Err(anyhow::anyhow!(
                "invalid error-format value: `{other}` (expected `human`, `json`, or `short`)"
            ))
        }
    };

    // ── Dispatch ──
    match &cli.command {
        Commands::Init { .. } => unreachable!(),

        Commands::Run { ptau, .. } => {
            let path = cfg.entry.as_deref().ok_or_else(|| {
                anyhow::anyhow!("no input file specified and no `entry` in achronyme.toml")
            })?;
            cli::commands::run::run_file(
                path,
                cfg.stress_gc,
                ptau.as_deref(),
                &cfg.prove_backend,
                cfg.max_heap.as_deref(),
                cfg.gc_stats,
                cfg.circuit_stats,
                ef,
            )
        }

        Commands::Disassemble { .. } => {
            let path = cfg.entry.as_deref().ok_or_else(|| {
                anyhow::anyhow!("no input file specified and no `entry` in achronyme.toml")
            })?;
            cli::commands::disassemble::disassemble_file(path, ef)
        }

        Commands::Compile { output, .. } => {
            let path = cfg.entry.as_deref().ok_or_else(|| {
                anyhow::anyhow!("no input file specified and no `entry` in achronyme.toml")
            })?;
            let out = output.as_deref().or(cfg.binary_path.as_deref());
            cli::commands::compile::compile_file(path, out, ef)
        }

        Commands::Inspect {
            inputs,
            input_file,
            prove,
            port,
            no_open,
            ..
        } => {
            let path = cfg.entry.as_deref().ok_or_else(|| {
                anyhow::anyhow!("no input file specified and no `entry` in achronyme.toml")
            })?;
            cli::commands::inspect::inspect_command(
                path,
                inputs.as_deref(),
                input_file.as_deref(),
                prove.as_deref(),
                *port,
                *no_open,
                ef,
            )
        }

        Commands::Circuit {
            inputs,
            input_file,
            prove,
            dump_ir,
            ..
        } => {
            let path = cfg.entry.as_deref().ok_or_else(|| {
                anyhow::anyhow!("no input file specified and no `entry` in achronyme.toml")
            })?;
            cli::commands::circuit::circuit_command(
                path,
                &cfg.r1cs_path,
                &cfg.wtns_path,
                inputs.as_deref(),
                input_file.as_deref(),
                !cfg.optimize,
                &cfg.backend,
                *prove,
                cfg.solidity_path.as_deref(),
                cfg.plonkish_json_path.as_deref(),
                *dump_ir,
                cfg.circuit_stats,
                ef,
            )
        }
    }
}

/// Determine the starting directory for toml walk-up search.
fn command_start_dir(cmd: &Commands) -> std::path::PathBuf {
    let path_arg = match cmd {
        Commands::Run { path, .. }
        | Commands::Disassemble { path }
        | Commands::Compile { path, .. }
        | Commands::Inspect { path, .. }
        | Commands::Circuit { path, .. } => path.as_deref(),
        Commands::Init { .. } => None,
    };

    if let Some(p) = path_arg {
        let p = std::path::Path::new(p);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                return parent.to_path_buf();
            }
        }
    }

    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}

/// Extract CLI overrides from parsed arguments.
fn build_overrides(cli: &Cli) -> CliOverrides {
    match &cli.command {
        Commands::Run {
            path,
            stress_gc,
            prove_backend,
            max_heap,
            gc_stats,
            circuit_stats,
            ..
        } => CliOverrides {
            path: path.clone(),
            error_format: cli.error_format.clone(),
            prime: None,
            backend: None,
            prove_backend: prove_backend.clone(),
            optimize: None,
            r1cs_path: None,
            wtns_path: None,
            solidity_path: None,
            plonkish_json_path: None,
            max_heap: max_heap.clone(),
            stress_gc: *stress_gc,
            gc_stats: *gc_stats,
            circuit_stats: *circuit_stats,
        },

        Commands::Disassemble { path } => CliOverrides {
            path: path.clone(),
            error_format: cli.error_format.clone(),
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
        },

        Commands::Compile { path, .. } => CliOverrides {
            path: path.clone(),
            error_format: cli.error_format.clone(),
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
        },

        Commands::Circuit {
            path,
            r1cs,
            wtns,
            backend,
            no_optimize,
            solidity,
            plonkish_json,
            circuit_stats,
            ..
        } => CliOverrides {
            path: path.clone(),
            error_format: cli.error_format.clone(),
            prime: None,
            backend: backend.clone(),
            prove_backend: None,
            optimize: no_optimize.map(|no| !no),
            r1cs_path: r1cs.clone(),
            wtns_path: wtns.clone(),
            solidity_path: solidity.clone(),
            plonkish_json_path: plonkish_json.clone(),
            max_heap: None,
            stress_gc: false,
            gc_stats: false,
            circuit_stats: *circuit_stats,
        },

        Commands::Inspect { path, .. } => CliOverrides {
            path: path.clone(),
            error_format: cli.error_format.clone(),
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
        },

        Commands::Init { .. } => unreachable!(),
    }
}
