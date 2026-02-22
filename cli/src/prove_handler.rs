use std::collections::HashMap;
use std::path::PathBuf;

use compiler::r1cs_backend::R1CSCompiler;
use ir::IrLowering;
use memory::FieldElement;
use vm::{ProveHandler, ProveResult};

/// Default implementation of `ProveHandler` that compiles and verifies
/// prove blocks using the IR→R1CS pipeline, generating native Groth16
/// proofs via ark-groth16.
pub struct DefaultProveHandler {
    cache_dir: PathBuf,
}

impl DefaultProveHandler {
    pub fn new() -> Self {
        let cache_dir = std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".achronyme").join("cache"))
            .unwrap_or_else(|_| PathBuf::from("/tmp/achronyme/cache"));
        Self { cache_dir }
    }
}

impl ProveHandler for DefaultProveHandler {
    fn execute_prove(
        &self,
        source: &str,
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, String> {
        // 1. Strip braces: source comes as "{ witness s\npublic h\n... }"
        let inner = source
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(source);

        // 2. Lower IR (self-contained: extracts public/witness from source)
        let (pub_names, wit_names, mut program) =
            IrLowering::lower_self_contained(inner).map_err(|e| format!("{e}"))?;

        // 3. Optimize
        ir::passes::optimize(&mut program);

        // 4. Build input map from scope_values
        let mut inputs = HashMap::new();
        for name in pub_names.iter().chain(wit_names.iter()) {
            let val = scope_values
                .get(name)
                .ok_or_else(|| format!("prove: variable `{name}` not found in scope"))?;
            inputs.insert(name.clone(), *val);
        }

        // 5. Compile + witness
        let mut r1cs = R1CSCompiler::new();
        let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
        r1cs.set_proven_boolean(proven);
        let witness = r1cs
            .compile_ir_with_witness(&program, &inputs)
            .map_err(|e| format!("{e}"))?;

        // 6. Verify constraints
        r1cs.cs
            .verify(&witness)
            .map_err(|idx| format!("constraint {idx} failed"))?;

        // 7. Generate native Groth16 proof
        crate::groth16::generate_proof(&r1cs.cs, &witness, &self.cache_dir)
    }
}
