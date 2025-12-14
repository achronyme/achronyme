use clap::Parser;
use anyhow::Result;

mod args;
mod runner;
mod repl;

use args::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { path } => runner::run_file(path),
        Commands::Disassemble { path } => runner::disassemble_file(path),
        Commands::Compile { path, output } => runner::compile_file(path, output.as_deref()),
        Commands::Repl => repl::run_repl(),
    }
}
