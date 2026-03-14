use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ach", version)]
#[command(about = "Achronyme CLI", long_about = None)]
pub struct Cli {
    /// Diagnostic output format: human (default), json, or short
    #[arg(long, default_value = "human", global = true)]
    pub error_format: String,

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
        /// Backend for prove {} blocks: "r1cs" (default) or "plonkish"
        #[arg(long, default_value = "r1cs")]
        prove_backend: String,
        /// Maximum heap size (e.g., "256M", "1G", "512K", or raw bytes)
        #[arg(long)]
        max_heap: Option<String>,
        /// Print GC statistics to stderr after execution
        #[arg(long)]
        gc_stats: bool,
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
        /// Generate a cryptographic proof (requires --inputs)
        #[arg(long)]
        prove: bool,
        /// Generate a Solidity Groth16 verifier contract at the given path
        #[arg(long)]
        solidity: Option<String>,
        /// Export Plonkish circuit to JSON (includes witness if --inputs is provided)
        #[arg(long)]
        plonkish_json: Option<String>,
        /// Dump the SSA IR (after optimization) and exit without compiling to constraints
        #[arg(long)]
        dump_ir: bool,
    },
}
