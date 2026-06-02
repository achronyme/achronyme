use std::process::Command;
use std::time::{Duration, Instant};

/// Run a command and return wall-clock duration. Panics on non-zero exit,
/// printing captured stdout/stderr for diagnostics.
pub(crate) fn run_timed(cmd: &mut Command) -> Duration {
    let label = format!("{cmd:?}");
    let t = Instant::now();
    let output = cmd.output().expect("failed to spawn");
    let elapsed = t.elapsed();
    if !output.status.success() {
        panic!(
            "command failed: {label}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    elapsed
}

pub(crate) fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

pub(crate) fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
