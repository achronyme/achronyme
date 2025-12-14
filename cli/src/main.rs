use clap::Parser;
use anyhow::Result;

mod args;
mod commands;
mod repl;

use args::{Cli, Commands};
use commands::{run, compile, disassemble};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { path } => run::run_file(path),
        Commands::Disassemble { path } => disassemble::disassemble_file(path),
        Commands::Compile { path, output } => compile::compile_file(path, output.as_deref()),
        Commands::Repl => repl::run_repl(),
    }
}
