use anyhow::Result;

use constraints::PoseidonParamsProvider;
use memory::FieldBackend;
use zkc::plonkish_backend::PlonkishCompiler;

// ---------------------------------------------------------------------------
// Trait for BN254-specific operations in generic circuit context.
//
// Solidity verifier generation and halo2 PlonK proof generation are inherently
// BN254-only (EVM precompiles, halo2 library). Flag validation in
// `circuit_command` guarantees these paths only run with BN254, but the generic
// `F` parameter doesn't carry that information. This trait bridges the gap.
// ---------------------------------------------------------------------------

pub(super) trait Bn254Ops: FieldBackend + PoseidonParamsProvider + Sized {
    fn solidity_from_cs(
        _cs: &constraints::r1cs::ConstraintSystem<Self>,
        _cache_dir: &std::path::Path,
    ) -> Result<String, String> {
        Err(format!(
            "Solidity not supported for {}",
            Self::PRIME_ID.name()
        ))
    }

    fn halo2_proof(
        _compiler: PlonkishCompiler<Self>,
        _cache_dir: &std::path::Path,
    ) -> Result<akron::ProveResult, String> {
        Err(format!("halo2 not supported for {}", Self::PRIME_ID.name()))
    }
}

impl Bn254Ops for memory::Bn254Fr {
    fn solidity_from_cs(
        cs: &constraints::r1cs::ConstraintSystem<Self>,
        cache_dir: &std::path::Path,
    ) -> Result<String, String> {
        let vk = proving::groth16_bn254::setup_vk_only(cs, cache_dir)
            .map_err(|e| format!("Groth16 setup failed: {e}"))?;
        Ok(proving::solidity::generate_solidity_verifier(&vk))
    }

    fn halo2_proof(
        compiler: PlonkishCompiler<Self>,
        cache_dir: &std::path::Path,
    ) -> Result<akron::ProveResult, String> {
        proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir)
    }
}

impl Bn254Ops for memory::Bls12_381Fr {}
impl Bn254Ops for memory::GoldilocksFr {}
