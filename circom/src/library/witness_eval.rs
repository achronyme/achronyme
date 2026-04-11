//! Evaluate a Circom template off-circuit (VM mode).
//!
//! Runs the ProveIR body against concrete field-typed inputs, producing
//! the witness values the Achronyme VM expects when the user calls an
//! imported Circom template outside a `prove {}` block.

use std::collections::HashMap;

use diagnostics::Span;
use ir::prove_ir::types::FieldConst;
use memory::{FieldBackend, FieldElement};

use crate::ast;
use crate::lowering::template::lower_template;
use crate::witness::{compute_witness_hints_with_captures, WitnessError};

use super::error::{check_param_count, find_template, LibraryError};
use super::instantiate::{iter_multi_index, resolve_output_dims};
use super::metadata::resolve_entry;
use super::types::CircomLibrary;

/// Reason a VM-mode witness evaluation was rejected.
///
/// Shared low-level failures (unknown template, wrong param count,
/// unresolved output dimension) live in [`LibraryError`] and are
/// composed in via the [`WitnessEvalError::Library`] variant.
#[derive(Debug)]
pub enum WitnessEvalError {
    /// Shared library-level failure.
    Library(LibraryError),
    /// Lowering to ProveIR failed.
    Lowering(String),
    /// Witness computation failed (assertion, missing input, etc.).
    Witness(WitnessError),
    /// Output signal value was not populated by the witness hint pass.
    /// Usually indicates that the template body relies on values this
    /// evaluator cannot reconstruct off-circuit.
    MissingOutput { template: String, signal: String },
}

impl std::fmt::Display for WitnessEvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Library(e) => write!(f, "{e}"),
            Self::Lowering(msg) => write!(f, "lowering failed: {msg}"),
            Self::Witness(e) => write!(f, "witness computation failed: {e}"),
            Self::MissingOutput { template, signal } => write!(
                f,
                "witness evaluator did not produce a value for `{template}.{signal}`"
            ),
        }
    }
}

impl std::error::Error for WitnessEvalError {}

impl From<LibraryError> for WitnessEvalError {
    fn from(e: LibraryError) -> Self {
        Self::Library(e)
    }
}

/// Evaluate a Circom template in VM mode (witness-only, no constraint
/// generation) against concrete inputs and template parameter values.
///
/// This is the runtime entry point used when an `.ach` file calls an
/// imported Circom template in VM mode, e.g.:
///
/// ```ach
/// import "poseidon.circom" as P
/// let h = P.Poseidon(2)([0p1, 0p2])   // runs this evaluator
/// ```
///
/// `template_args` are the template parameters in declaration order
/// (e.g. `[2]` for `Poseidon(2)`). `signal_inputs` is keyed by raw
/// signal input names — scalar inputs use the declared name, array
/// inputs use the same `name_i` suffix convention as the rest of the
/// lowering pipeline (e.g. `in_0`, `in_1`, ...).
///
/// Returns a map keyed by output name (scalars) or by `name_i` /
/// `name_i_j` (multi-dim arrays).
pub fn evaluate_template_witness<F: FieldBackend>(
    library: &CircomLibrary,
    template_name: &str,
    template_args: &[u64],
    signal_inputs: &HashMap<String, FieldElement<F>>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessEvalError> {
    // 1. Locate the template and validate argument count — shared
    //    with the instantiation path.
    let template = find_template(library, template_name)?;
    check_param_count(template, template_args.len())?;

    // 2. Synthesize a throwaway MainComponent whose template_args are
    //    numeric literals, so `lower_template` can seed its own
    //    param_values via the existing code path without us adding a
    //    parallel entry point.
    let synth_span = Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    };
    let fake_main = ast::MainComponent {
        public_signals: Vec::new(),
        template_name: template.name.clone(),
        template_args: template_args
            .iter()
            .map(|v| ast::Expr::Number {
                value: v.to_string(),
                span: synth_span.clone(),
            })
            .collect(),
        span: synth_span,
    };

    // 3. Lower the template to ProveIR against the synthesized main.
    let lowered = lower_template(template, Some(&fake_main), &library.program)
        .map_err(|e| WitnessEvalError::Lowering(e.to_string()))?;

    // 4. Run the witness hint pass.
    let captures: HashMap<String, u64> = template
        .params
        .iter()
        .zip(template_args.iter())
        .map(|(name, &v)| (name.clone(), v))
        .collect();
    let env = compute_witness_hints_with_captures(&lowered.prove_ir, signal_inputs, &captures)
        .map_err(WitnessEvalError::Witness)?;

    // 5. Resolve the cached library entry against the concrete
    //    captures so array output dimensions become Const, without
    //    re-walking the template body's AST.
    let mut known_params = HashMap::new();
    for (name, &v) in template.params.iter().zip(template_args.iter()) {
        known_params.insert(name.clone(), FieldConst::from_u64(v));
    }
    let cached = library
        .template(template_name)
        .expect("find_template succeeded, cached entry must exist");
    let entry = resolve_entry(cached, &known_params);

    let mut outputs = HashMap::new();
    for out in &entry.outputs {
        if out.is_scalar() {
            match env.get(&out.name) {
                Some(&val) => {
                    outputs.insert(out.name.clone(), val);
                }
                None => {
                    return Err(WitnessEvalError::MissingOutput {
                        template: template_name.to_string(),
                        signal: out.name.clone(),
                    });
                }
            }
            continue;
        }
        let dims = resolve_output_dims(&out.dimensions).ok_or_else(|| {
            WitnessEvalError::Library(LibraryError::UnresolvedOutputDimension {
                template: template_name.to_string(),
                signal: out.name.clone(),
            })
        })?;
        for index in iter_multi_index(&dims) {
            let suffix = index
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("_");
            let key = format!("{}_{}", out.name, suffix);
            match env.get(&key) {
                Some(&val) => {
                    outputs.insert(key, val);
                }
                None => {
                    return Err(WitnessEvalError::MissingOutput {
                        template: template_name.to_string(),
                        signal: key,
                    });
                }
            }
        }
    }

    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::make_library;
    use super::*;
    use memory::Bn254Fr;

    #[test]
    fn evaluate_witness_square_scalar() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        inputs.insert("x".to_string(), FieldElement::<Bn254Fr>::from_u64(7));
        let outputs = evaluate_template_witness::<Bn254Fr>(&lib, "Square", &[], &inputs)
            .expect("eval should succeed");
        assert_eq!(outputs.len(), 1);
        let y = outputs.get("y").expect("y output");
        assert_eq!(*y, FieldElement::<Bn254Fr>::from_u64(49));
    }

    #[test]
    fn evaluate_witness_num2bits_array_output() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
                var lc = 0;
                var e = 1;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    out[i] * (out[i] - 1) === 0;
                    lc += out[i] * e;
                    e = e + e;
                }
                lc === in;
            }
            "#,
        );
        let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(13));
        let outputs = evaluate_template_witness::<Bn254Fr>(&lib, "Num2Bits", &[4], &inputs)
            .expect("eval should succeed");
        assert_eq!(outputs.len(), 4);
        let expected = [1u64, 0, 1, 1];
        for (i, bit) in expected.iter().enumerate() {
            let key = format!("out_{i}");
            let got = outputs.get(&key).expect("output present");
            assert_eq!(*got, FieldElement::<Bn254Fr>::from_u64(*bit), "bit {i}");
        }
    }

    #[test]
    fn evaluate_witness_unknown_template_errors() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let result = evaluate_template_witness::<Bn254Fr>(&lib, "Cube", &[], &HashMap::new());
        assert!(matches!(
            result,
            Err(WitnessEvalError::Library(
                LibraryError::UnknownTemplate { .. }
            ))
        ));
    }

    #[test]
    fn evaluate_witness_param_count_mismatch() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
        );
        let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
        let result = evaluate_template_witness::<Bn254Fr>(&lib, "Num2Bits", &[], &inputs);
        assert!(matches!(
            result,
            Err(WitnessEvalError::Library(
                LibraryError::ParamCountMismatch {
                    expected: 1,
                    got: 0,
                    ..
                }
            ))
        ));
    }
}
