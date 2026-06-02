// ---------------------------------------------------------------------------
// Examples list — paths relative to the workspace root (`achronyme/`).
// circom_lib_dirs is set per-row when the example imports `.circom`.
// ---------------------------------------------------------------------------

use super::*;

pub(crate) struct Example {
    pub(crate) label: &'static str,
    pub(crate) rel_path: &'static str,
    pub(crate) circom_libs: &'static [&'static str],
    /// Hard wall-clock budget. Tornado-Cash sized circuits get a fatter
    /// budget; unit tests run in milliseconds.
    pub(crate) budget: Duration,
}

pub(crate) const EXAMPLES: &[Example] = &[
    Example {
        label: "proof_of_membership",
        rel_path: "examples/proof_of_membership.ach",
        circom_libs: &[],
        budget: Duration::from_secs(180),
    },
    Example {
        label: "circom_merkle_membership",
        rel_path: "examples/circom_merkle_membership.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(180),
    },
    Example {
        label: "circom_poseidon_chain",
        rel_path: "examples/circom_poseidon_chain.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(180),
    },
    Example {
        label: "tornado_mixer",
        rel_path: "examples/tornado_mixer.ach",
        circom_libs: &[],
        budget: Duration::from_secs(240),
    },
    Example {
        label: "tornado_multifile",
        rel_path: "examples/tornado/src/main.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(300),
    },
    Example {
        label: "test/basic_prove",
        rel_path: "test/prove/basic_prove.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_array_sum",
        rel_path: "test/prove/prove_array_sum.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_assert_message",
        rel_path: "test/prove/prove_assert_message.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_boolean_mux",
        rel_path: "test/prove/prove_boolean_mux.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_capture",
        rel_path: "test/prove/prove_capture.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_chain",
        rel_path: "test/prove/prove_chain.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_comparison",
        rel_path: "test/prove/prove_comparison.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_division",
        rel_path: "test/prove/prove_division.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_for_loop",
        rel_path: "test/prove/prove_for_loop.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_for_loop_nested",
        rel_path: "test/prove/prove_for_loop_nested.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_for_loop_dynamic",
        rel_path: "test/prove/prove_for_loop_dynamic.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_if_else",
        rel_path: "test/prove/prove_if_else.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_outer_fn",
        rel_path: "test/prove/prove_outer_fn.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_outer_fn_circuit",
        rel_path: "test/prove/prove_outer_fn_circuit.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_power",
        rel_path: "test/prove/prove_power.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_range_check",
        rel_path: "test/prove/prove_range_check.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_secret_vote",
        rel_path: "test/prove/prove_secret_vote.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_with_poseidon",
        rel_path: "test/prove/prove_with_poseidon.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/typed_prove",
        rel_path: "test/prove/typed_prove.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/babyadd",
        rel_path: "test/circom_imports/babyadd.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(120),
    },
];
