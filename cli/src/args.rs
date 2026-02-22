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
        /// [Deprecated] Ignored — native Groth16 backend does not use ptau files
        #[arg(long, hide = true)]
        ptau: Option<String>,
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
    /// Compile a circuit to .r1cs (and optionally generate .wtns)
    Circuit {
        /// Path to the source file (.ach)
        path: String,
        /// Output .r1cs file path
        #[arg(long, default_value = "circuit.r1cs")]
        r1cs: String,
        /// Output .wtns file path
        #[arg(long, default_value = "witness.wtns")]
        wtns: String,
        /// Public input variable names (comma-separated)
        #[arg(long, value_delimiter = ',')]
        public: Vec<String>,
        /// Witness variable names (comma-separated)
        #[arg(long, value_delimiter = ',')]
        witness: Vec<String>,
        /// Input values as name=value pairs (comma-separated, decimal or 0x hex)
        #[arg(long)]
        inputs: Option<String>,
        /// Disable IR optimization passes
        #[arg(long)]
        no_optimize: bool,
        /// Backend: "r1cs" (default) or "plonkish"
        #[arg(long, default_value = "r1cs")]
        backend: String,
    },
}
