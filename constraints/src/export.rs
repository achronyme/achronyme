/// Binary export for R1CS and witness files (iden3/snarkjs format).
///
/// Produces `.r1cs` (version 1) and `.wtns` (version 2) files that can be
/// consumed directly by `snarkjs` for Groth16 proof generation.

use crate::r1cs::{ConstraintSystem, LinearCombination};
use memory::FieldElement;

/// BN254 scalar field prime in 32-byte little-endian form.
/// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_PRIME_LE: [u8; 32] = {
    // MODULUS limbs (little-endian u64):
    //   [0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029]
    let l0: u64 = 0x43e1f593f0000001;
    let l1: u64 = 0x2833e84879b97091;
    let l2: u64 = 0xb85045b68181585d;
    let l3: u64 = 0x30644e72e131a029;
    let b0 = l0.to_le_bytes();
    let b1 = l1.to_le_bytes();
    let b2 = l2.to_le_bytes();
    let b3 = l3.to_le_bytes();
    [
        b0[0], b0[1], b0[2], b0[3], b0[4], b0[5], b0[6], b0[7],
        b1[0], b1[1], b1[2], b1[3], b1[4], b1[5], b1[6], b1[7],
        b2[0], b2[1], b2[2], b2[3], b2[4], b2[5], b2[6], b2[7],
        b3[0], b3[1], b3[2], b3[3], b3[4], b3[5], b3[6], b3[7],
    ]
};

// ============================================================================
// Helpers
// ============================================================================

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_lc(buf: &mut Vec<u8>, lc: &LinearCombination) {
    write_u32(buf, lc.terms.len() as u32);
    for (var, coeff) in &lc.terms {
        write_u32(buf, var.index() as u32);
        buf.extend_from_slice(&coeff.to_le_bytes());
    }
}

// ============================================================================
// write_r1cs
// ============================================================================

/// Serialize a `ConstraintSystem` to the iden3 `.r1cs` binary format (version 1).
///
/// Wire layout: `[ONE, pub1..pubN, wit1..witM, intermediates...]`
///
/// Section mapping:
/// - `nPubOut` = `num_pub_inputs` (public outputs are the declared public vars)
/// - `nPubIn`  = 0 (no separate "verifier inputs" concept)
/// - `nPrvIn`  = `num_variables - 1 - num_pub_inputs`
pub fn write_r1cs(cs: &ConstraintSystem) -> Vec<u8> {
    let n_wires = cs.num_variables() as u32;
    let n_pub_out = cs.num_pub_inputs() as u32;
    let n_pub_in: u32 = 0;
    let n_prv_in = n_wires - 1 - n_pub_out;
    let n_labels = n_wires as u64;
    let n_constraints = cs.num_constraints() as u32;

    let mut buf = Vec::new();

    // Magic + version + number of sections
    buf.extend_from_slice(b"r1cs");
    write_u32(&mut buf, 1); // version
    write_u32(&mut buf, 3); // n_sections

    // ── Section 1: Header ──────────────────────────────────────────────
    let mut header = Vec::new();
    write_u32(&mut header, 32); // field_size
    header.extend_from_slice(&BN254_PRIME_LE); // prime
    write_u32(&mut header, n_wires);
    write_u32(&mut header, n_pub_out);
    write_u32(&mut header, n_pub_in);
    write_u32(&mut header, n_prv_in);
    write_u64(&mut header, n_labels);
    write_u32(&mut header, n_constraints);

    write_u32(&mut buf, 1); // section type
    write_u64(&mut buf, header.len() as u64);
    buf.extend_from_slice(&header);

    // ── Section 2: Constraints ─────────────────────────────────────────
    let mut constraints_buf = Vec::new();
    for c in cs.constraints() {
        write_lc(&mut constraints_buf, &c.a);
        write_lc(&mut constraints_buf, &c.b);
        write_lc(&mut constraints_buf, &c.c);
    }

    write_u32(&mut buf, 2); // section type
    write_u64(&mut buf, constraints_buf.len() as u64);
    buf.extend_from_slice(&constraints_buf);

    // ── Section 3: Wire2LabelId ────────────────────────────────────────
    let w2l_size = n_wires as u64 * 8;
    write_u32(&mut buf, 3); // section type
    write_u64(&mut buf, w2l_size);
    for i in 0..n_wires {
        write_u64(&mut buf, i as u64);
    }

    buf
}

// ============================================================================
// write_wtns
// ============================================================================

/// Serialize a witness vector to the iden3 `.wtns` binary format (version 2).
///
/// `witness[0]` must be `FieldElement::ONE` (the constant-1 wire).
pub fn write_wtns(witness: &[FieldElement]) -> Vec<u8> {
    let n_witness = witness.len() as u32;

    let mut buf = Vec::new();

    // Magic + version + number of sections
    buf.extend_from_slice(b"wtns");
    write_u32(&mut buf, 2); // version
    write_u32(&mut buf, 2); // n_sections

    // ── Section 1: Header ──────────────────────────────────────────────
    let mut header = Vec::new();
    write_u32(&mut header, 32); // field_size
    header.extend_from_slice(&BN254_PRIME_LE); // prime
    write_u32(&mut header, n_witness);

    write_u32(&mut buf, 1); // section type
    write_u64(&mut buf, header.len() as u64);
    buf.extend_from_slice(&header);

    // ── Section 2: Witness values ──────────────────────────────────────
    let values_size = n_witness as u64 * 32;
    write_u32(&mut buf, 2); // section type
    write_u64(&mut buf, values_size);
    for val in witness {
        buf.extend_from_slice(&val.to_le_bytes());
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{ConstraintSystem, LinearCombination};

    /// Build a simple a * b = c circuit for testing.
    fn make_mul_circuit() -> ConstraintSystem {
        let mut cs = ConstraintSystem::new();
        let c = cs.alloc_input();  // public output, index 1
        let a = cs.alloc_witness(); // index 2
        let b = cs.alloc_witness(); // index 3
        cs.enforce(
            LinearCombination::from_variable(a),
            LinearCombination::from_variable(b),
            LinearCombination::from_variable(c),
        );
        cs
    }

    #[test]
    fn test_r1cs_magic_and_version() {
        let cs = make_mul_circuit();
        let data = write_r1cs(&cs);
        assert_eq!(&data[0..4], b"r1cs");
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 3);
    }

    #[test]
    fn test_r1cs_header_values() {
        let cs = make_mul_circuit();
        let data = write_r1cs(&cs);

        // Section 1 header: type=1 at offset 12, size at 16..24, body starts at 24
        let sec_type = u32::from_le_bytes(data[12..16].try_into().unwrap());
        assert_eq!(sec_type, 1);

        let sec_size = u64::from_le_bytes(data[16..24].try_into().unwrap());
        assert_eq!(sec_size, 64); // 4 + 32 + 4 + 4 + 4 + 4 + 8 + 4 = 64

        let body = &data[24..24 + 64];
        let field_size = u32::from_le_bytes(body[0..4].try_into().unwrap());
        assert_eq!(field_size, 32);

        let prime = &body[4..36];
        assert_eq!(prime, &BN254_PRIME_LE);

        let n_wires = u32::from_le_bytes(body[36..40].try_into().unwrap());
        assert_eq!(n_wires, 4); // ONE, c, a, b

        let n_pub_out = u32::from_le_bytes(body[40..44].try_into().unwrap());
        assert_eq!(n_pub_out, 1); // c

        let n_pub_in = u32::from_le_bytes(body[44..48].try_into().unwrap());
        assert_eq!(n_pub_in, 0);

        let n_prv_in = u32::from_le_bytes(body[48..52].try_into().unwrap());
        assert_eq!(n_prv_in, 2); // a, b

        let n_constraints = u32::from_le_bytes(body[60..64].try_into().unwrap());
        assert_eq!(n_constraints, 1);
    }

    #[test]
    fn test_r1cs_constraint_encoding() {
        let cs = make_mul_circuit();
        let data = write_r1cs(&cs);

        // Section 2 starts after section 1: 12 (file header) + 12 (sec1 header) + 64 (sec1 body) = 88
        let sec2_offset = 88;
        let sec_type = u32::from_le_bytes(data[sec2_offset..sec2_offset + 4].try_into().unwrap());
        assert_eq!(sec_type, 2);

        let body_offset = sec2_offset + 12; // skip type(4) + size(8)

        // A = 1*var(2): nTerms=1, wireId=2, coeff=ONE
        let n_terms_a = u32::from_le_bytes(data[body_offset..body_offset + 4].try_into().unwrap());
        assert_eq!(n_terms_a, 1);
        let wire_id = u32::from_le_bytes(data[body_offset + 4..body_offset + 8].try_into().unwrap());
        assert_eq!(wire_id, 2); // variable a

        // B = 1*var(3): after A's data (4 + 4 + 32 = 40 bytes)
        let b_offset = body_offset + 4 + (4 + 32);
        let n_terms_b = u32::from_le_bytes(data[b_offset..b_offset + 4].try_into().unwrap());
        assert_eq!(n_terms_b, 1);
        let wire_id_b = u32::from_le_bytes(data[b_offset + 4..b_offset + 8].try_into().unwrap());
        assert_eq!(wire_id_b, 3); // variable b

        // C = 1*var(1): after B's data
        let c_offset = b_offset + 4 + (4 + 32);
        let n_terms_c = u32::from_le_bytes(data[c_offset..c_offset + 4].try_into().unwrap());
        assert_eq!(n_terms_c, 1);
        let wire_id_c = u32::from_le_bytes(data[c_offset + 4..c_offset + 8].try_into().unwrap());
        assert_eq!(wire_id_c, 1); // variable c (public output)
    }

    #[test]
    fn test_r1cs_wire2label_identity() {
        let cs = make_mul_circuit();
        let data = write_r1cs(&cs);

        // Section 3 starts after section 2
        // Sec1: 12 + 64 = 76 bytes (header + body), sec2: 12 + constraint data
        // Constraint: 3 LCs, each with 1 term = 3*(4 + 4 + 32) = 120 bytes
        let sec3_offset = 88 + 12 + 120;
        let sec_type = u32::from_le_bytes(data[sec3_offset..sec3_offset + 4].try_into().unwrap());
        assert_eq!(sec_type, 3);

        let body_offset = sec3_offset + 12;
        for i in 0..4u64 {
            let off = body_offset + i as usize * 8;
            let label = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            assert_eq!(label, i);
        }
    }

    #[test]
    fn test_wtns_magic_and_version() {
        let witness = vec![FieldElement::ONE, FieldElement::from_u64(42)];
        let data = write_wtns(&witness);
        assert_eq!(&data[0..4], b"wtns");
        assert_eq!(u32::from_le_bytes(data[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), 2);
    }

    #[test]
    fn test_wtns_header_and_values() {
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(42),
            FieldElement::from_u64(6),
            FieldElement::from_u64(7),
        ];
        let data = write_wtns(&witness);

        // Section 1 body at offset 24 (12 file header + 12 sec header)
        let body = &data[24..];
        let field_size = u32::from_le_bytes(body[0..4].try_into().unwrap());
        assert_eq!(field_size, 32);
        let n_witness = u32::from_le_bytes(body[36..40].try_into().unwrap());
        assert_eq!(n_witness, 4);

        // Section 2: values start at 24 + 40 (sec1 body) + 12 (sec2 header) = 76
        let values_offset = 24 + 40 + 12;
        // First value should be ONE
        let mut one_bytes = [0u8; 32];
        one_bytes[0] = 1;
        assert_eq!(&data[values_offset..values_offset + 32], &one_bytes);
    }

    #[test]
    fn test_bn254_prime_bytes() {
        // Verify BN254_PRIME_LE matches the known MODULUS limbs
        let mut expected = [0u8; 32];
        let modulus: [u64; 4] = [
            0x43e1f593f0000001,
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ];
        for i in 0..4 {
            expected[i * 8..(i + 1) * 8].copy_from_slice(&modulus[i].to_le_bytes());
        }
        assert_eq!(BN254_PRIME_LE, expected);
    }
}
