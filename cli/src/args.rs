use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ach", version)]
#[command(about = "Achronyme CLI", long_about = None)]
pub struct Cli {
    /// Diagnostic output format: human (default), json, or short
    #[arg(long, global = true)]
    pub error_format: Option<String>,

    /// Prime field: bn254 (default), bls12-381, or goldilocks
    #[arg(long, global = true)]
    pub prime: Option<String>,

    /// Do not load achronyme.toml project configuration
    #[arg(long, global = true)]
    pub no_config: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new Achronyme project
    Init {
        /// Project name
        name: String,
        /// Template: "circuit" (default), "vm", or "prove"
        #[arg(long, default_value = "circuit")]
        template: String,
    },
    /// Run a source file or binary
    Run {
        /// Path to the file (.ach or .achb). If omitted, uses [project].entry from achronyme.toml
        path: Option<String>,
        /// Force GC on every allocation (Stress Mode)
        #[arg(long)]
        stress_gc: bool,
        /// [Deprecated] Ignored — native Groth16 backend does not use ptau files
        #[arg(long, hide = true)]
        ptau: Option<String>,
        /// Backend for prove {} blocks: "r1cs" (default) or "plonkish"
        #[arg(long)]
        prove_backend: Option<String>,
        /// Maximum heap size (e.g., "256M", "1G", "512K", or raw bytes)
        #[arg(long)]
        max_heap: Option<String>,
        /// Print GC statistics to stderr after execution
        #[arg(long)]
        gc_stats: bool,
        /// Print circuit constraint stats for each prove block
        #[arg(long)]
        circuit_stats: bool,
    },
    /// Disassemble a source file or binary
    Disassemble {
        /// Path to the file. If omitted, uses [project].entry from achronyme.toml
        path: Option<String>,
    },
    /// Compile a source file to binary
    Compile {
        /// Input source file. If omitted, uses [project].entry from achronyme.toml
        path: Option<String>,
        /// Output binary file (optional)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Open the interactive circuit inspector in the browser
    Inspect {
        /// Path to the source file (.ach). If omitted, uses [project].entry from achronyme.toml
        path: Option<String>,
        /// Name of the prove block to inspect (runs program via VM to resolve captures)
        #[arg(long)]
        prove: Option<String>,
        /// Input values as name=value pairs (comma-separated, for standalone circuits)
        #[arg(long)]
        inputs: Option<String>,
        /// Input values from a TOML file (for standalone circuits)
        #[arg(long)]
        input_file: Option<String>,
        /// HTTP server port (default: 3000)
        #[arg(long, default_value = "3000")]
        port: u16,
        /// Don't auto-open the browser
        #[arg(long)]
        no_open: bool,
    },
    /// Compile a circuit to .r1cs (and optionally generate .wtns)
    Circuit {
        /// Path to the source file (.ach). If omitted, uses [project].entry from achronyme.toml
        path: Option<String>,
        /// Output .r1cs file path
        #[arg(long)]
        r1cs: Option<String>,
        /// Output .wtns file path
        #[arg(long)]
        wtns: Option<String>,
        /// Input values as name=value pairs (comma-separated, decimal or 0x hex)
        #[arg(long)]
        inputs: Option<String>,
        /// Input values from a TOML file (arrays supported natively)
        #[arg(long)]
        input_file: Option<String>,
        /// Disable IR optimization passes
        #[arg(long)]
        no_optimize: Option<bool>,
        /// Backend: "r1cs" (default) or "plonkish"
        #[arg(long)]
        backend: Option<String>,
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
        /// Print circuit constraint stats breakdown
        #[arg(long)]
        circuit_stats: bool,
    },
}
