use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use compiler::r1cs_backend::R1CSCompiler;
use constraints::export::{write_r1cs, write_wtns};
use ir::IrLowering;
use memory::FieldElement;
use vm::{ProveHandler, ProveResult};

/// Default implementation of `ProveHandler` that compiles and verifies
/// prove blocks using the IR→R1CS pipeline, optionally generating
/// Groth16 proofs via snarkjs.
pub struct DefaultProveHandler {
    cache_dir: PathBuf,
    ptau_path: Option<PathBuf>,
}

impl DefaultProveHandler {
    pub fn new(ptau: Option<&str>) -> Self {
        let cache_dir = std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".achronyme").join("cache"))
            .unwrap_or_else(|_| PathBuf::from("/tmp/achronyme/cache"));
        Self {
            cache_dir,
            ptau_path: ptau.map(PathBuf::from),
        }
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

        // 5. Compile + witness (uses compile_ir_with_witness from Level 1)
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

        // 7. If snarkjs available, generate Groth16 proof
        if snarkjs_available() {
            let result = self.generate_groth16_proof(&r1cs, &witness)?;
            Ok(result)
        } else {
            Ok(ProveResult::VerifiedOnly)
        }
    }
}

impl DefaultProveHandler {
    fn generate_groth16_proof(
        &self,
        r1cs_compiler: &R1CSCompiler,
        witness: &[FieldElement],
    ) -> Result<ProveResult, String> {
        // Create temp directory for this proof
        let tmp = tempfile::tempdir().map_err(|e| format!("failed to create tmpdir: {e}"))?;
        let dir = tmp.path();

        // Write r1cs and wtns
        let r1cs_path = dir.join("circuit.r1cs");
        let wtns_path = dir.join("witness.wtns");

        let r1cs_bytes = write_r1cs(&r1cs_compiler.cs);
        std::fs::write(&r1cs_path, &r1cs_bytes)
            .map_err(|e| format!("failed to write r1cs: {e}"))?;
        std::fs::write(&wtns_path, write_wtns(witness))
            .map_err(|e| format!("failed to write wtns: {e}"))?;

        // Get or create zkey (cached by r1cs hash)
        let (zkey_path, vkey_path) = self.get_or_create_zkey(&r1cs_bytes, &r1cs_path)?;

        // Generate proof
        let proof_path = dir.join("proof.json");
        let public_path = dir.join("public.json");

        run_snarkjs(&[
            "snarkjs",
            "groth16",
            "prove",
            zkey_path.to_str().unwrap(),
            wtns_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
            public_path.to_str().unwrap(),
        ])?;

        // Sanity check: verify the proof
        run_snarkjs(&[
            "snarkjs",
            "groth16",
            "verify",
            vkey_path.to_str().unwrap(),
            public_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
        ])?;

        // Read results
        let proof_json = std::fs::read_to_string(&proof_path)
            .map_err(|e| format!("failed to read proof.json: {e}"))?;
        let public_json = std::fs::read_to_string(&public_path)
            .map_err(|e| format!("failed to read public.json: {e}"))?;
        let vkey_json = std::fs::read_to_string(&vkey_path)
            .map_err(|e| format!("failed to read verification_key.json: {e}"))?;

        Ok(ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        })
    }

    fn get_or_create_zkey(
        &self,
        r1cs_bytes: &[u8],
        r1cs_path: &Path,
    ) -> Result<(PathBuf, PathBuf), String> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        r1cs_bytes.hash(&mut hasher);
        let hash = hasher.finish();

        let cache_subdir = self.cache_dir.join(format!("{hash:016x}"));
        let zkey_path = cache_subdir.join("circuit.zkey");
        let vkey_path = cache_subdir.join("verification_key.json");

        if zkey_path.exists() && vkey_path.exists() {
            return Ok((zkey_path, vkey_path));
        }

        // Create cache directory
        std::fs::create_dir_all(&cache_subdir)
            .map_err(|e| format!("failed to create cache dir: {e}"))?;

        // Prepare ptau
        let ptau_final = if let Some(ref ptau) = self.ptau_path {
            ptau.clone()
        } else {
            // Generate ptau ceremony in cache
            let ptau_0 = cache_subdir.join("pot12_0000.ptau");
            let ptau_1 = cache_subdir.join("pot12_0001.ptau");
            let ptau_f = cache_subdir.join("pot12_final.ptau");

            if !ptau_f.exists() {
                run_snarkjs(&[
                    "snarkjs",
                    "powersoftau",
                    "new",
                    "bn128",
                    "12",
                    ptau_0.to_str().unwrap(),
                ])?;
                let entropy_arg = format!("-e={}", random_entropy());
                run_snarkjs(&[
                    "snarkjs",
                    "powersoftau",
                    "contribute",
                    ptau_0.to_str().unwrap(),
                    ptau_1.to_str().unwrap(),
                    "--name=achronyme",
                    &entropy_arg,
                ])?;
                run_snarkjs(&[
                    "snarkjs",
                    "powersoftau",
                    "prepare",
                    "phase2",
                    ptau_1.to_str().unwrap(),
                    ptau_f.to_str().unwrap(),
                ])?;

                // Clean up intermediate ptau files
                std::fs::remove_file(&ptau_0).ok();
                std::fs::remove_file(&ptau_1).ok();
            }
            ptau_f
        };

        // Groth16 setup
        let zkey_0 = cache_subdir.join("circuit_0000.zkey");
        let zkey_1 = cache_subdir.join("circuit_0001.zkey");

        run_snarkjs(&[
            "snarkjs",
            "groth16",
            "setup",
            r1cs_path.to_str().unwrap(),
            ptau_final.to_str().unwrap(),
            zkey_0.to_str().unwrap(),
        ])?;
        let entropy_arg = format!("-e={}", random_entropy());
        run_snarkjs(&[
            "snarkjs",
            "zkey",
            "contribute",
            zkey_0.to_str().unwrap(),
            zkey_1.to_str().unwrap(),
            "--name=achronyme",
            &entropy_arg,
        ])?;
        run_snarkjs(&[
            "snarkjs",
            "zkey",
            "export",
            "verificationkey",
            zkey_1.to_str().unwrap(),
            vkey_path.to_str().unwrap(),
        ])?;

        // Rename final zkey
        std::fs::rename(&zkey_1, &zkey_path)
            .map_err(|e| format!("failed to rename zkey: {e}"))?;

        // Clean up intermediate zkey
        std::fs::remove_file(&zkey_0).ok();

        Ok((zkey_path, vkey_path))
    }
}

/// Generate 32 bytes of cryptographic randomness, returned as a hex string
/// for use as `-e=<entropy>` in snarkjs ceremonies.
fn random_entropy() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn snarkjs_available() -> bool {
    std::process::Command::new("npx")
        .args(["snarkjs", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_snarkjs(args: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new("npx")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run npx: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "snarkjs {} failed: {}",
            args[1..].join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}
