use std::collections::HashMap;

use akron::{ProveError, ProveHandler, ProveResult};
use memory::FieldElement;

use crate::{walk_circom_hints, ProveBackend, ProveEngine};

impl ProveHandler for ProveEngine {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        // 1. Deserialize ProveIR from bytes
        let (prove_ir, _prime_id) = ir_forge::ProveIR::from_bytes(prove_ir_bytes)
            .map_err(|e| ProveError::IrLowering(format!("ProveIR deserialization: {e}")))?;

        // 2. Instantiate with scope values (captures resolved here)
        //    via Lysis (Walker → InterningSink → materialise). The R1CS
        //    backend drops the program right after constraint emission
        //    and reads none of its metadata maps, so it takes the lean
        //    instantiate — on large circuits the maps are the dominant
        //    share of the materialized program's heap. Flows that keep
        //    the program (Plonkish compile, circuit stats) stay on the
        //    full instantiate.
        let lean = matches!(self.opts.backend, ProveBackend::R1cs) && !self.opts.circuit_stats;
        let program = if lean {
            // Fused pipeline: the pass pipeline runs against the
            // interner's emission events and the program materializes
            // once, already optimized — the unoptimized instruction
            // Vec never exists.
            let bundle = prove_ir
                .instantiate_lysis_lean_sink(scope_values)
                .map_err(|e| ProveError::IrLowering(format!("{e}")))?;
            ir::passes::fused::optimize_lean_sink(bundle).program
        } else {
            let mut program = prove_ir
                .instantiate_lysis(scope_values)
                .map_err(|e| ProveError::IrLowering(format!("{e}")))?;
            ir::passes::optimize(&mut program);
            program
        };

        // 3b. Collect circuit stats if enabled
        if self.opts.circuit_stats {
            let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
            let name = prove_ir.name.as_deref();
            let stats = ir::stats::CircuitStats::from_program(&program, &proven, name);
            self.observer.on_circuit_stats(stats);
        }

        // 4. Build input map from scope_values (public + witness + capture names).
        //    Validate that all required values are present.
        let mut inputs = HashMap::new();
        for input in prove_ir
            .public_inputs
            .iter()
            .chain(prove_ir.witness_inputs.iter())
        {
            match &input.array_size {
                Some(ir_forge::ArraySize::Literal(n)) => {
                    for i in 0..*n {
                        let elem_name = format!("{}_{i}", input.name);
                        let fe = scope_values.get(&elem_name).ok_or_else(|| {
                            ProveError::IrLowering(format!(
                                "variable `{elem_name}` not found in scope"
                            ))
                        })?;
                        inputs.insert(elem_name, *fe);
                    }
                }
                None => {
                    let fe = scope_values.get(&input.name).ok_or_else(|| {
                        ProveError::IrLowering(format!(
                            "variable `{}` not found in scope",
                            input.name
                        ))
                    })?;
                    inputs.insert(input.name.clone(), *fe);
                }
                Some(ir_forge::ArraySize::Capture(_)) => {
                    // Capture-sized arrays: elements were expanded during instantiation.
                    // The individual element names are already in scope_values.
                }
            }
        }
        for cap in &prove_ir.captures {
            let fe = scope_values.get(&cap.name).ok_or_else(|| {
                ProveError::IrLowering(format!("capture `{}` not found in scope", cap.name))
            })?;
            inputs.insert(cap.name.clone(), *fe);
        }

        // 4b. Circom witness hints: templates imported via `import { T } from "x.circom"`
        //     may produce `CircuitNode::WitnessHint { name, hint }` nodes for intermediate
        //     signals that are witness-only (e.g., `IsZero`'s `inv <-- 1/in`). The IR
        //     evaluator treats these as `Instruction::Input { Witness }` wires, so their
        //     values must be computed off-circuit and supplied in the inputs map before
        //     R1CS / Plonkish compilation. Reuses the same `compute_witness_hints` helper
        //     that `ach circom` uses for standalone circuits.
        //
        //     `compute_witness_hints` walks the whole ProveIR body, including the
        //     library-mode wiring `Let`s emitted by `instantiate_template_into`, so the
        //     mangled `{prefix}.sig` names in hint expressions resolve against the
        //     caller-supplied values. The returned map supersets `inputs`; we merge it
        //     back, keeping existing keys authoritative so explicit public / witness
        //     values always win over hint-computed ones.
        //     The same big-integer `<--` hints are lifted into Artik programs
        //     that the R1CS witness fill re-executes. Routing this hint walk
        //     through a shared `ArtikMemo` lets the fill reuse these results
        //     instead of recomputing them; the cache is content-addressed, so
        //     the witness is byte-identical with or without it.
        //
        //     The R1CS path runs the walk after constraint emission (the
        //     hint env then never coexists with the program); the Plonkish
        //     compiler reads the full input map up front, so its walk stays
        //     here.
        match self.opts.backend {
            ProveBackend::R1cs => self.prove_r1cs(program, &prove_ir, inputs),
            ProveBackend::Plonkish => {
                let mut artik_memo = artik::ArtikMemo::<memory::Bn254Fr>::new();
                walk_circom_hints(&prove_ir, &mut inputs, &mut artik_memo)?;
                self.prove_plonkish(&program, &inputs)
            }
        }
    }
}
