use std::time::Duration;

/// Describes one circuit under test; paths are relative to the workspace root.
pub(crate) struct Circuit {
    pub(crate) name: &'static str,
    /// `.circom` source file.
    pub(crate) circom_src: &'static str,
    /// Library dirs to pass to both `circom -l` and `ach circom --lib`.
    pub(crate) libs: &'static [&'static str],
    /// Produces matching input representations: `(circom_json, ach_toml)`.
    pub(crate) inputs: fn() -> (String, String),
}

pub(crate) struct AchTimings {
    /// `ach circom --r1cs --wtns --input-file` — compile + witness.
    /// `ach circom` always computes witness hints (for `<--`) even without
    /// `--prove`, so measuring a pure compile-only phase isn't possible from
    /// the CLI. This column is the closest apples-to-apples equivalent to
    /// `circom --r1cs --wasm` + `generate_witness.js` combined.
    pub(crate) compile_plus_witness: Duration,
    /// Same plus Groth16 prove + verify.
    pub(crate) full: Duration,
}

pub(crate) struct CircomTimings {
    pub(crate) compile: Duration,
    pub(crate) witness: Duration,
    pub(crate) prove: Duration,
    pub(crate) verify: Duration,
}
