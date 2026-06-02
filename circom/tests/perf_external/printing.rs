use std::time::Duration;

use super::timing::ms;
use super::types::{AchTimings, CircomTimings, Circuit};

pub(crate) fn print_row(circuit: &Circuit, ach: &AchTimings, cir: &CircomTimings, setup: Duration) {
    let cir_cw = cir.compile + cir.witness;
    let cir_full = cir_cw + cir.prove + cir.verify;
    let ach_cw = ms(ach.compile_plus_witness);
    let ach_full = ms(ach.full);
    eprintln!("\n--- {} ---", circuit.name);
    eprintln!(
        "  {:<22} {:>12} {:>14} {:>10}",
        "phase", "achronyme", "circom+snarkjs", "ratio"
    );
    eprintln!(
        "  {:<22} {:>10.2}ms {:>12.2}ms {:>9.2}×",
        "compile + witness",
        ach_cw,
        ms(cir_cw),
        ms(cir_cw) / ach_cw
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "  └─ circom compile",
        "—",
        ms(cir.compile)
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "  └─ node witness",
        "—",
        ms(cir.witness)
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "groth16 prove",
        "(bundled)",
        ms(cir.prove)
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "groth16 verify",
        "(bundled)",
        ms(cir.verify)
    );
    eprintln!(
        "  {:<22} {:>10.2}ms {:>12.2}ms {:>9.2}×",
        "end-to-end",
        ach_full,
        ms(cir_full),
        ms(cir_full) / ach_full
    );
    if !setup.is_zero() {
        eprintln!(
            "  (one-time snarkjs groth16 setup for this circuit: {:.1}s)",
            setup.as_secs_f64()
        );
    }
}
