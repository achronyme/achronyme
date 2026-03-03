use memory::field::MODULUS;
use memory::FieldElement;

/// 80-bit LFSR used to generate Poseidon round constants per the paper.
///
/// Retained as reference for auditing. Production code uses hardcoded
/// circomlibjs constants via [`super::PoseidonParams::bn254_t3`].
pub(super) struct GrainLfsr {
    state: [bool; 80],
}

impl GrainLfsr {
    /// Initialize from Poseidon parameters.
    /// Encoding: [field_type:2][sbox:4][field_size:12][t:12][R_F:10][R_P:10][padding:30]
    pub(super) fn new(field_size: u16, t: u16, r_f: u16, r_p: u16) -> Self {
        let mut bits = [false; 80];
        let mut pos = 0;

        bits[pos] = false;
        bits[pos + 1] = true;
        pos += 2;

        for i in 0..3 {
            bits[pos + i] = false;
        }
        bits[pos + 3] = true;
        pos += 4;

        for i in 0..12 {
            bits[pos + i] = (field_size >> (11 - i)) & 1 == 1;
        }
        pos += 12;

        for i in 0..12 {
            bits[pos + i] = (t >> (11 - i)) & 1 == 1;
        }
        pos += 12;

        for i in 0..10 {
            bits[pos + i] = (r_f >> (9 - i)) & 1 == 1;
        }
        pos += 10;

        for i in 0..10 {
            bits[pos + i] = (r_p >> (9 - i)) & 1 == 1;
        }
        pos += 10;

        for i in 0..30 {
            bits[pos + i] = true;
        }

        let mut lfsr = Self { state: bits };
        for _ in 0..160 {
            lfsr.clock();
        }
        lfsr
    }

    fn clock(&mut self) -> bool {
        let new_bit = self.state[0]
            ^ self.state[13]
            ^ self.state[23]
            ^ self.state[38]
            ^ self.state[51]
            ^ self.state[62];
        for i in 0..79 {
            self.state[i] = self.state[i + 1];
        }
        self.state[79] = new_bit;
        new_bit
    }

    fn next_bit(&mut self) -> bool {
        loop {
            let control = self.clock();
            let candidate = self.clock();
            if control {
                return candidate;
            }
        }
    }

    pub(super) fn next_field_element(&mut self, field_size: usize) -> FieldElement {
        loop {
            let mut bytes = [0u8; 32];
            for bit_idx in 0..field_size {
                let b = self.next_bit();
                if b {
                    let byte_pos = bit_idx / 8;
                    let bit_pos = 7 - (bit_idx % 8);
                    let offset = 32 - field_size.div_ceil(8);
                    bytes[offset + byte_pos] |= 1 << bit_pos;
                }
            }
            bytes.reverse();
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
            }
            if !ge_modulus(&limbs) {
                return FieldElement::from_canonical(limbs);
            }
        }
    }
}

/// Check if limbs >= MODULUS.
fn ge_modulus(limbs: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if limbs[i] > MODULUS[i] {
            return true;
        }
        if limbs[i] < MODULUS[i] {
            return false;
        }
    }
    true
}
