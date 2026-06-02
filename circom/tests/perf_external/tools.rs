use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(crate) fn have(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub(crate) fn snarkjs_available() -> bool {
    // `snarkjs --version` exits non-zero on 0.7.x but still prints version.
    let out = Command::new("npx").args(["snarkjs", "--version"]).output();
    matches!(out, Ok(o) if !o.stdout.is_empty() || !o.stderr.is_empty())
}

pub(crate) fn build_ach_binary() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap();
    let bin = workspace.join("target/release/ach");
    // Always rebuild — `cargo build` is a no-op when the binary is up to
    // date but a real recompile when sources changed since the last
    // benchmark run. A bare existence check here once shipped a stale
    // binary that did not reflect the optimizer change under test, so
    // the benchmark reported baseline numbers for code that had moved on.
    eprintln!("  ensuring ach release binary is up to date...");
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "cli", "--bin", "ach"])
        .current_dir(workspace)
        .status()
        .expect("cargo build failed");
    assert!(status.success(), "cargo build -p cli failed");
    bin
}
