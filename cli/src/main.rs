use anyhow::Result;
use clap::Parser;

mod args;

use args::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run {
            path,
            stress_gc,
            ptau,
            prove_backend,
        } => cli::commands::run::run_file(path, *stress_gc, ptau.as_deref(), prove_backend),
        Commands::Disassemble { path } => cli::commands::disassemble::disassemble_file(path),
        Commands::Compile { path, output } => {
            cli::commands::compile::compile_file(path, output.as_deref())
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
        ),
    }
}
