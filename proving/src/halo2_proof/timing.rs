use std::path::Path;
use std::time::{Duration, Instant};

use akron::ProveResult;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use rand::rngs::OsRng;
use zkc::plonkish_backend::PlonkishCompiler;

use super::{
    fe_to_halo2, load_or_create_kzg_params, serialize_proof_json, serialize_public_json,
    serialize_vkey_json, AchronymePlonkishCircuit, CircuitParams,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct PlonkishProofTiming {
    pub params: Duration,
    pub keygen_vk: Duration,
    pub keygen_pk: Duration,
    pub prove: Duration,
    pub verify: Duration,
    pub serialize: Duration,
}

pub struct TimedPlonkishProof {
    pub result: ProveResult,
    pub timing: PlonkishProofTiming,
    pub k: u32,
    pub rows: usize,
}

/// Generate a native Plonkish proof using halo2 KZG, taking ownership of the compiler.
pub fn generate_plonkish_proof(
    compiler: PlonkishCompiler,
    cache_dir: &Path,
) -> Result<ProveResult, String> {
    generate_plonkish_proof_timed(compiler, cache_dir).map(|timed| timed.result)
}

/// Generate a native Plonkish proof and report phase timings.
pub fn generate_plonkish_proof_timed(
    compiler: PlonkishCompiler,
    cache_dir: &Path,
) -> Result<TimedPlonkishProof, String> {
    let rows = compiler.num_circuit_rows();
    let k = (((rows + 10) as f64).log2().ceil() as u32).max(4);
    let mut timing = PlonkishProofTiming::default();

    let params = CircuitParams {
        range_table_bits: compiler.range_tables_bits(),
    };
    let instance_values: Vec<Fr> = compiler
        .public_inputs
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let val = compiler.system.assignments.get(compiler.col_instance, i);
            fe_to_halo2(&val)
        })
        .collect::<Result<Vec<Fr>, String>>()?;

    let started = Instant::now();
    let params_path = cache_dir.join("plonkish").join(format!("params_k{k}.bin"));
    let kzg_params = load_or_create_kzg_params(k, &params_path)?;
    timing.params = started.elapsed();

    let keygen_circuit = AchronymePlonkishCircuit {
        params: params.clone(),
        compiler: PlonkishCompiler::new(),
        num_circuit_rows: rows,
    };

    let started = Instant::now();
    let vk = keygen_vk(&kzg_params, &keygen_circuit)
        .map_err(|e| format!("halo2 keygen_vk failed: {e:?}"))?;
    timing.keygen_vk = started.elapsed();

    let started = Instant::now();
    let pk = keygen_pk(&kzg_params, vk.clone(), &keygen_circuit)
        .map_err(|e| format!("halo2 keygen_pk failed: {e:?}"))?;
    timing.keygen_pk = started.elapsed();

    let prove_circuit = AchronymePlonkishCircuit {
        params,
        compiler,
        num_circuit_rows: rows,
    };
    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    let instance_slice: &[Fr] = &instance_values;
    let instances: &[&[Fr]] = &[instance_slice];

    let started = Instant::now();
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        OsRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        AchronymePlonkishCircuit,
    >(
        &kzg_params,
        &pk,
        &[prove_circuit],
        &[instances],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| format!("halo2 proof creation failed: {e:?}"))?;
    let proof_bytes = transcript.finalize();
    timing.prove = started.elapsed();

    let started = Instant::now();
    let mut verifier_transcript =
        Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(proof_bytes.as_slice());
    let strategy = SingleStrategy::new(&kzg_params);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &kzg_params,
        &vk,
        strategy,
        &[instances],
        &mut verifier_transcript,
    )
    .map_err(|e| format!("halo2 proof verification failed: {e:?}"))?;
    timing.verify = started.elapsed();

    let started = Instant::now();
    let proof_json = serialize_proof_json(&proof_bytes, &instance_values, k)?;
    let public_json = serialize_public_json(&instance_values)?;
    let vkey_json = serialize_vkey_json(&vk, k)?;
    timing.serialize = started.elapsed();

    Ok(TimedPlonkishProof {
        result: ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        },
        timing,
        k,
        rows,
    })
}
