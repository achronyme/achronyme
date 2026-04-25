//! Throwaway profiling harness for the SHA-256 circom compile.
//!
//! Run with debug symbols + release opt for perf:
//!
//! ```sh
//! CARGO_PROFILE_RELEASE_DEBUG=true \
//!   cargo build --release -p circom --example profile_sha256_compile
//! perf record -F 99 -g --call-graph dwarf -o /tmp/sha256.perf -- \
//!   target/release/examples/profile_sha256_compile
//! perf report -i /tmp/sha256.perf
//! ```
//!
//! Lives in `examples/` (ignored from production builds, listed in
//! Cargo manifest) so it doesn't drag profiling code into the
//! library surface. Delete once SHA-256 compile perf is acceptable.

use std::path::Path;
use std::time::Instant;

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let start = Instant::now();
    let result = circom::compile_file(&path, &lib_dirs);
    let elapsed = start.elapsed();

    match result {
        Ok(_) => eprintln!("[compile_file] {elapsed:?}  OK"),
        Err(e) => {
            eprintln!("[compile_file] {elapsed:?}  ERROR: {e}");
            std::process::exit(1);
        }
    }
}
