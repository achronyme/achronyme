pub mod commands;
pub mod groth16;
pub mod halo2_proof;
pub mod prove_handler;
pub mod repl;
pub mod solidity;

/// Return the cache directory for Achronyme key material.
///
/// Prefers `$HOME/.achronyme/cache`.  Falls back to a user-scoped
/// temporary directory (`$TMPDIR/achronyme-cache`) rather than the
/// world-writable `/tmp`.
pub fn cache_dir() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home)
            .join(".achronyme")
            .join("cache");
    }
    std::env::temp_dir().join("achronyme-cache")
}
