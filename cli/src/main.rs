use anyhow::Result;
use clap::Parser;

mod args;
mod commands;
mod repl;

use args::{Cli, Commands};
use commands::{circuit, compile, disassemble, run};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { path, stress_gc } => run::run_file(path, *stress_gc),
        Commands::Disassemble { path } => disassemble::disassemble_file(path),
        Commands::Compile { path, output } => compile::compile_file(path, output.as_deref()),
        Commands::Repl => repl::run_repl(),
        Commands::Circuit {
            path,
            r1cs,
            wtns,
            public,
            witness,
            inputs,
            no_optimize,
        } => circuit::circuit_command(
            path,
            r1cs,
            wtns,
            public,
            witness,
            inputs.as_deref(),
            *no_optimize,
        ),
    }
}
