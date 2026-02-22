use anyhow::Result;
use clap::Parser;

mod args;
mod commands;
mod groth16;
mod halo2_proof;
mod prove_handler;
mod repl;

use args::{Cli, Commands};
use commands::{circuit, compile, disassemble, run};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { path, stress_gc, ptau, prove_backend } => run::run_file(path, *stress_gc, ptau.as_deref(), prove_backend),
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
            backend,
            prove,
        } => circuit::circuit_command(
            path,
            r1cs,
            wtns,
            public,
            witness,
            inputs.as_deref(),
            *no_optimize,
            backend,
            *prove,
        ),
    }
}
