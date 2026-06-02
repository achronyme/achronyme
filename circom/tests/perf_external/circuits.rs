use super::inputs::{
    eddsamimcsponge_inputs, eddsaposeidon_inputs, escalarmulany_inputs, mimcsponge_inputs,
    num2bits8_inputs, sha256_64_inputs, smtprocessor_10_inputs, smtverifier_10_inputs,
};
use super::types::Circuit;

pub(crate) const CIRCUITS: &[Circuit] = &[
    Circuit {
        name: "Num2Bits(8)",
        circom_src: "test/circom/num2bits_8.circom",
        libs: &[],
        inputs: num2bits8_inputs,
    },
    Circuit {
        name: "MiMCSponge(2,220,1)",
        circom_src: "test/circomlib/mimcsponge_test.circom",
        libs: &["test/circomlib"],
        inputs: mimcsponge_inputs,
    },
    Circuit {
        name: "EscalarMulAny(254)",
        circom_src: "test/circomlib/escalarmulany254_test.circom",
        libs: &["test/circomlib"],
        inputs: escalarmulany_inputs,
    },
    Circuit {
        name: "SMTVerifier(10)",
        circom_src: "test/circomlib/smtverifier_test.circom",
        libs: &["test/circomlib"],
        inputs: smtverifier_10_inputs,
    },
    Circuit {
        name: "SMTProcessor(10)",
        circom_src: "test/circomlib/smtprocessor_test.circom",
        libs: &["test/circomlib"],
        inputs: smtprocessor_10_inputs,
    },
    Circuit {
        name: "EdDSAPoseidon",
        circom_src: "test/circomlib/eddsaposeidon_test.circom",
        libs: &["test/circomlib"],
        inputs: eddsaposeidon_inputs,
    },
    Circuit {
        name: "EdDSAMiMCSponge",
        circom_src: "test/circomlib/eddsamimcsponge_test.circom",
        libs: &["test/circomlib"],
        inputs: eddsamimcsponge_inputs,
    },
    Circuit {
        name: "Sha256(64)",
        circom_src: "test/circomlib/sha256_test.circom",
        libs: &["test/circomlib"],
        inputs: sha256_64_inputs,
    },
];
