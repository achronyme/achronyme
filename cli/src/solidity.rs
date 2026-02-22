//! Solidity Groth16 verifier contract generator.
//!
//! Generates a Solidity contract that verifies Groth16 proofs on-chain using
//! BN254 precompiles (ecAdd 0x06, ecMul 0x07, ecPairing 0x08).
//! Template follows the snarkjs Groth16 verifier for ecosystem compatibility.

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

/// Convert a base field element to a decimal string for Solidity.
fn fq_to_solidity<F: PrimeField>(f: &F) -> String {
    f.into_bigint().to_string()
}

/// Convert a G1 affine point to (x, y) decimal strings.
/// Returns ("0", "0") for the identity/infinity point.
fn g1_to_solidity(p: &<Bn254 as Pairing>::G1Affine) -> (String, String) {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return ("0".into(), "0".into());
    }
    let x = p.x().expect("non-identity G1 point has x");
    let y = p.y().expect("non-identity G1 point has y");
    (fq_to_solidity(&x), fq_to_solidity(&y))
}

/// Convert a G2 affine point to (x1, x2, y1, y2) decimal strings.
/// Returns ("0","0","0","0") for the identity/infinity point.
///
/// **Critical**: arkworks stores Fq2 as (c0, c1). The EVM ecPairing precompile
/// expects (c1, c0) — imaginary part first. This function emits EVM order.
fn g2_to_solidity(
    p: &<Bn254 as Pairing>::G2Affine,
) -> (String, String, String, String) {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return ("0".into(), "0".into(), "0".into(), "0".into());
    }
    let x = p.x().expect("non-identity G2 point has x");
    let y = p.y().expect("non-identity G2 point has y");
    // EVM order: (x.c1, x.c0, y.c1, y.c0)
    (
        fq_to_solidity(&x.c1),
        fq_to_solidity(&x.c0),
        fq_to_solidity(&y.c1),
        fq_to_solidity(&y.c0),
    )
}

/// Generate a Solidity Groth16 verifier contract embedding the given verification key.
pub fn generate_solidity_verifier(vk: &ark_groth16::VerifyingKey<Bn254>) -> String {
    let num_pub = vk.gamma_abc_g1.len() - 1; // IC has num_pub + 1 elements

    let (alpha_x, alpha_y) = g1_to_solidity(&vk.alpha_g1);
    let (beta_x1, beta_x2, beta_y1, beta_y2) = g2_to_solidity(&vk.beta_g2);
    let (gamma_x1, gamma_x2, gamma_y1, gamma_y2) = g2_to_solidity(&vk.gamma_g2);
    let (delta_x1, delta_x2, delta_y1, delta_y2) = g2_to_solidity(&vk.delta_g2);

    // IC point declarations
    let mut ic_constants = String::new();
    for (i, p) in vk.gamma_abc_g1.iter().enumerate() {
        let (x, y) = g1_to_solidity(p);
        ic_constants.push_str(&format!(
            "    uint256 constant IC{i}x = {x};\n    uint256 constant IC{i}y = {y};\n\n"
        ));
    }

    // IC accumulation: vk_x = IC[0] + sum(input[i] * IC[i+1])
    // Uses _pVk (Yul local), not pVk (Solidity constant).
    let mut ic_accum = String::new();
    ic_accum.push_str("            mstore(_pVk, IC0x)\n");
    ic_accum.push_str("            mstore(add(_pVk, 32), IC0y)\n");
    for i in 1..=num_pub {
        ic_accum.push_str(&format!(
            "\n            g1_mulAccC(_pVk, IC{i}x, IC{i}y, calldataload(add(pubSignals, {})))\n",
            (i - 1) * 32
        ));
    }

    // Field validation calls
    let mut field_checks = String::new();
    for i in 0..num_pub {
        field_checks.push_str(&format!(
            "            checkField(calldataload(add(pubSignals, {})))\n",
            i * 32
        ));
    }

    // Public signals parameter
    let pub_signals_param = if num_pub > 0 {
        format!(", uint[{num_pub}] calldata _pubSignals")
    } else {
        String::new()
    };

    let pub_signals_ref = if num_pub > 0 {
        "\n            let pubSignals := _pubSignals\n"
    } else {
        ""
    };

    // C-3: When no public inputs, _pubSignals doesn't exist — pass 0
    let check_pairing_call = if num_pub > 0 {
        "let isValid := checkPairing(_pA, _pB, _pC, _pubSignals.offset, pMem)"
    } else {
        "let isValid := checkPairing(_pA, _pB, _pC, 0, pMem)"
    };

    format!(
        r#"// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Groth16Verifier {{
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = {alpha_x};
    uint256 constant alphay  = {alpha_y};
    uint256 constant betax1  = {beta_x1};
    uint256 constant betax2  = {beta_x2};
    uint256 constant betay1  = {beta_y1};
    uint256 constant betay2  = {beta_y2};
    uint256 constant gammax1 = {gamma_x1};
    uint256 constant gammax2 = {gamma_x2};
    uint256 constant gammay1 = {gamma_y1};
    uint256 constant gammay2 = {gamma_y2};
    uint256 constant deltax1 = {delta_x1};
    uint256 constant deltax2 = {delta_x2};
    uint256 constant deltay1 = {delta_y1};
    uint256 constant deltay2 = {delta_y2};

{ic_constants}
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC{pub_signals_param}) public view returns (bool) {{
        assembly {{
            function checkField(v) {{
                if iszero(lt(v, r)) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
            }}

            function g1_mulAccC(pR, x, y, s) {{
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
            }}

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {{
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                // IC accumulation writes directly to _pVk below
{pub_signals_ref}{field_checks}{ic_accum}
                // -A
                mstore(add(_pPairing, 0), calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, mod(calldataload(add(pA, 32)), q)), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x (accumulated IC result)
                mstore(add(_pPairing, 384), mload(_pVk))
                mstore(add(_pPairing, 416), mload(add(_pVk, 32)))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, add(_pPairing, 0), 768, add(_pPairing, 0), 0x20)

                isOk := and(success, mload(add(_pPairing, 0)))
            }}

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            {check_pairing_call}

            mstore(0, isValid)
            return(0, 0x20)
        }}
    }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
    };
    use ark_snark::SNARK;
    use ark_std::rand::rngs::OsRng;

    /// Minimal test circuit: a * b = c, where c is a public input.
    #[derive(Clone)]
    struct TestCircuit {
        a: Option<Fr>,
        b: Option<Fr>,
    }

    impl ConstraintSynthesizer<Fr> for TestCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> Result<(), SynthesisError> {
            use ark_ff::Field;
            use ark_relations::r1cs::Variable;

            let a_val = self.a.unwrap_or(Fr::from(3u64));
            let b_val = self.b.unwrap_or(Fr::from(5u64));
            let c_val = a_val * b_val;

            let a = cs.new_witness_variable(|| Ok(a_val))?;
            let b = cs.new_witness_variable(|| Ok(b_val))?;
            let c = cs.new_input_variable(|| Ok(c_val))?;

            // a * b = c
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::from(a),
                ark_relations::r1cs::LinearCombination::from(b),
                ark_relations::r1cs::LinearCombination::from(c),
            )?;

            Ok(())
        }
    }

    fn test_vk() -> ark_groth16::VerifyingKey<Bn254> {
        let circuit = TestCircuit { a: None, b: None };
        let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng).unwrap();
        vk
    }

    #[test]
    fn generate_solidity_produces_valid_structure() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);
        assert!(sol.contains("pragma solidity >=0.8.0 <0.9.0;"));
        assert!(sol.contains("contract Groth16Verifier"));
        assert!(sol.contains("function verifyProof"));
        assert!(sol.contains("SPDX-License-Identifier: GPL-3.0"));
    }

    #[test]
    fn solidity_has_correct_field_constants() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);
        assert!(sol.contains(
            "uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;"
        ));
        assert!(sol.contains(
            "uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;"
        ));
    }

    #[test]
    fn solidity_ic_count_matches_public_inputs() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);
        // 1 public input → IC0 and IC1 present, no IC2
        assert!(sol.contains("IC0x"));
        assert!(sol.contains("IC1x"));
        assert!(!sol.contains("IC2x"));
    }

    #[test]
    fn solidity_g2_coordinates_in_evm_order() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);

        // Verify G2 coordinates are in EVM order (c1, c0) by checking
        // betax1 = x.c1 (imaginary first)
        use ark_ec::AffineRepr;
        let x = vk.beta_g2.x().expect("non-zero");
        let expected_x1 = fq_to_solidity(&x.c1); // imaginary part first for EVM
        let expected_x2 = fq_to_solidity(&x.c0);

        assert!(sol.contains(&format!("uint256 constant betax1  = {expected_x1};")));
        assert!(sol.contains(&format!("uint256 constant betax2  = {expected_x2};")));
    }

    /// Circuit with zero public inputs — only witness variables.
    #[derive(Clone)]
    struct ZeroInputCircuit;

    impl ConstraintSynthesizer<Fr> for ZeroInputCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Fr>,
        ) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
            let b = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
            cs.enforce_constraint(
                ark_relations::r1cs::LinearCombination::from(a),
                ark_relations::r1cs::LinearCombination::zero()
                    + (Fr::from(1u64), ark_relations::r1cs::Variable::One),
                ark_relations::r1cs::LinearCombination::from(b),
            )?;
            Ok(())
        }
    }

    #[test]
    fn solidity_zero_public_inputs_compiles_structurally() {
        let circuit = ZeroInputCircuit;
        let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng).unwrap();
        let sol = generate_solidity_verifier(&vk);

        // No _pubSignals parameter
        assert!(!sol.contains("_pubSignals"));
        // Uses 0 instead of _pubSignals.offset
        assert!(sol.contains("checkPairing(_pA, _pB, _pC, 0, pMem)"));
        // Still has contract and verifyProof
        assert!(sol.contains("contract Groth16Verifier"));
        assert!(sol.contains("function verifyProof"));
        // IC0 present but no IC1
        assert!(sol.contains("IC0x"));
        assert!(!sol.contains("IC1x"));
    }

    #[test]
    fn solidity_ecadd_reads_from_min() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);
        // C-1 fix: ecAdd should read from mIn (not add(mIn, 64))
        assert!(sol.contains("staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)"));
        assert!(!sol.contains("add(mIn, 64), 128"));
    }

    #[test]
    fn solidity_ic_accum_uses_underscore_pvk() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);
        // C-2 fix: IC accumulation should use _pVk (Yul local), not pVk
        assert!(sol.contains("mstore(_pVk, IC0x)"));
        assert!(sol.contains("g1_mulAccC(_pVk,"));
    }

    #[test]
    fn solidity_no_proof_coord_checkfield() {
        let vk = test_vk();
        let sol = generate_solidity_verifier(&vk);
        // H-3 fix: No checkField on proof coordinates _pA, _pB, _pC
        assert!(!sol.contains("checkField(calldataload(add(_pA"));
        assert!(!sol.contains("checkField(calldataload(add(_pB"));
        assert!(!sol.contains("checkField(calldataload(add(_pC"));
        // Public signal checkField should still be in checkPairing
        assert!(sol.contains("checkField(calldataload(add(pubSignals"));
    }
}
