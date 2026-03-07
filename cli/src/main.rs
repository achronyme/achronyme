use anyhow::Result;
use clap::Parser;
use cli::commands::ErrorFormat;

mod args;

use args::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ef = match cli.error_format.as_str() {
        "json" => ErrorFormat::Json,
        "short" => ErrorFormat::Short,
        "human" => ErrorFormat::Human,
        other => {
            return Err(anyhow::anyhow!(
                "invalid --error-format value: `{other}` (expected `human`, `json`, or `short`)"
            ))
        }
    };

    match &cli.command {
        Commands::Run {
            path,
            stress_gc,
            ptau,
            prove_backend,
        } => cli::commands::run::run_file(path, *stress_gc, ptau.as_deref(), prove_backend, ef),
        Commands::Disassemble { path } => cli::commands::disassemble::disassemble_file(path, ef),
        Commands::Compile { path, output } => {
            cli::commands::compile::compile_file(path, output.as_deref(), ef)
        }
        Commands::Repl => cli::repl::run_repl(),
        Commands::Circuit {
            path,
            r1cs,
            wtns,
            public,
            witness,
            inputs,
            no_optimize,
            backend,
            prove,
            solidity,
        } => cli::commands::circuit::circuit_command(
            path,
            r1cs,
            wtns,
            public,
            witness,
            inputs.as_deref(),
            *no_optimize,
            backend,
            *prove,
            solidity.as_deref(),
            ef,
        ),
    }
}
