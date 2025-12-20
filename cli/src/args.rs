use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ach")]
#[command(about = "Achronyme CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a source file or binary
    Run {
        /// Path to the file (.ach or .achb)
        path: String,
        /// Force GC on every allocation (Stress Mode)
        #[arg(long)]
        stress_gc: bool,
    },
    /// Disassemble a source file or binary
    Disassemble {
        /// Path to the file
        path: String,
    },
    /// Compile a source file to binary
    Compile {
        /// Input source file
        path: String,
        /// Output binary file (optional)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Start the REPL
    Repl,
}
