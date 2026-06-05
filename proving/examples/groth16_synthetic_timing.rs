use std::str::FromStr;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use constraints::r1cs::{ConstraintSystem, LinearCombination};
use memory::FieldElement;
use proving::groth16::AchronymeCircuit;
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    let constraints = read_usize_env("ACH_PROVER_BENCH_CONSTRAINTS", 4096);
    let repeats = read_usize_env("ACH_PROVER_BENCH_REPEATS", 3);

    let (cs, witness) = synthetic_chain(constraints);
    cs.verify(&witness).expect("synthetic witness must verify");

    println!(
        "constraints={} variables={} public_inputs={} repeats={}",
        cs.num_constraints(),
        cs.num_variables(),
        cs.num_pub_inputs(),
        repeats
    );

    let mut setup_total = Duration::ZERO;
    for i in 0..repeats {
        let mut rng = StdRng::seed_from_u64(0x5eed_0000 + i as u64);
        let start = Instant::now();
        let _ = Groth16::<Bn254>::circuit_specific_setup(setup_circuit(&cs), &mut rng)
            .expect("Groth16 setup failed");
        setup_total += start.elapsed();
    }

    let mut rng = StdRng::seed_from_u64(0x0051_a71c);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit(&cs), &mut rng)
        .expect("Groth16 setup failed");

    let public_inputs = public_inputs(&witness);
    let mut prove_total = Duration::ZERO;
    let mut verify_total = Duration::ZERO;
    for i in 0..repeats {
        let mut rng = StdRng::seed_from_u64(0x9e57_0000 + i as u64);

        let start = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, prove_circuit(&cs, &witness), &mut rng)
            .expect("Groth16 prove failed");
        prove_total += start.elapsed();

        let start = Instant::now();
        let verified =
            Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).expect("Groth16 verify failed");
        verify_total += start.elapsed();
        assert!(verified, "Groth16 proof must verify");
    }

    print_duration("setup", setup_total, repeats);
    print_duration("prove", prove_total, repeats);
    print_duration("verify", verify_total, repeats);
    println!("all_verified=true");
}

fn synthetic_chain(constraint_count: usize) -> (ConstraintSystem, Vec<FieldElement>) {
    assert!(constraint_count >= 2, "need at least two constraints");

    let mut cs = ConstraintSystem::new();
    let public_out = cs.alloc_input();
    let seed_var = cs.alloc_witness();

    let mut witness = vec![
        FieldElement::one(),
        FieldElement::zero(),
        FieldElement::from_u64(7),
    ];
    let mut current_var = seed_var;
    let mut current_value = FieldElement::from_u64(7);

    for i in 0..(constraint_count - 1) {
        let factor = FieldElement::from_u64(3 + (i as u64 % 17));
        let next_var = cs.alloc_witness();
        current_value = current_value.mul(&factor);
        witness.push(current_value);

        cs.enforce(
            LinearCombination::from_variable(current_var),
            LinearCombination::from_constant(factor),
            LinearCombination::from_variable(next_var),
        );
        current_var = next_var;
    }

    witness[public_out.index()] = current_value;
    cs.enforce_equal(
        LinearCombination::from_variable(current_var),
        LinearCombination::from_variable(public_out),
    );

    (cs, witness)
}

fn setup_circuit(cs: &ConstraintSystem) -> AchronymeCircuit {
    AchronymeCircuit {
        cs: cs.clone(),
        witness: None,
    }
}

fn prove_circuit(cs: &ConstraintSystem, witness: &[FieldElement]) -> AchronymeCircuit {
    AchronymeCircuit {
        cs: cs.clone(),
        witness: Some(witness.to_vec()),
    }
}

fn public_inputs(witness: &[FieldElement]) -> Vec<Fr> {
    vec![Fr::from_str(&witness[1].to_decimal_string()).expect("valid BN254 Fr")]
}

fn read_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn print_duration(label: &str, total: Duration, repeats: usize) {
    let total_ms = total.as_secs_f64() * 1000.0;
    println!("{label}_ms_total={total_ms:.3}");
    println!("{label}_ms_avg={:.3}", total_ms / repeats as f64);
}
