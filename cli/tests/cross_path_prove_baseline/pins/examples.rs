use super::FrozenBaseline;

pub(super) fn pin_proof_of_membership_membership() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            232, 74, 80, 4, 62, 123, 179, 33, 39, 189, 101, 161, 140, 224, 55, 170, 166, 87, 87,
            72, 218, 214, 155, 28, 213, 42, 243, 249, 53, 211, 44, 92,
        ],
        pre_o1_count: 1467,
        post_o1_hash: [
            160, 141, 182, 152, 190, 209, 26, 216, 199, 168, 229, 228, 178, 121, 63, 113, 109, 217,
            33, 144, 183, 111, 15, 26, 212, 108, 177, 126, 103, 151, 148, 144,
        ],
        post_o1_count: 966,
        num_variables: 1472,
        public_inputs: vec!["merkle_root".into()],
    }
}

pub(super) fn pin_proof_of_membership_membership_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            244, 133, 199, 120, 228, 52, 61, 255, 39, 74, 133, 242, 170, 167, 40, 33, 224, 107,
            168, 131, 142, 200, 198, 149, 191, 222, 157, 213, 14, 136, 119, 111,
        ],
        pre_o1_count: 1467,
        post_o1_hash: [
            188, 169, 175, 148, 80, 39, 245, 216, 114, 170, 245, 202, 122, 56, 85, 201, 163, 246,
            228, 205, 195, 145, 44, 244, 113, 129, 170, 16, 246, 193, 235, 59,
        ],
        post_o1_count: 966,
        num_variables: 1472,
        public_inputs: vec!["merkle_root".into()],
    }
}

pub(super) fn pin_circom_merkle_membership() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            166, 73, 159, 70, 139, 195, 225, 185, 116, 158, 216, 76, 199, 20, 239, 59, 21, 71, 238,
            73, 54, 77, 223, 158, 33, 121, 141, 176, 163, 184, 197, 159,
        ],
        pre_o1_count: 1465,
        post_o1_hash: [
            209, 80, 150, 219, 154, 69, 147, 113, 205, 16, 12, 219, 35, 221, 232, 234, 177, 163,
            165, 13, 63, 121, 232, 191, 63, 249, 66, 53, 188, 37, 1, 74,
        ],
        post_o1_count: 717,
        num_variables: 1469,
        public_inputs: vec!["merkle_root".into()],
    }
}

pub(super) fn pin_circom_poseidon_chain() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            137, 145, 158, 23, 212, 176, 214, 194, 125, 162, 2, 84, 217, 106, 35, 84, 120, 19, 90,
            68, 199, 242, 241, 160, 22, 202, 24, 235, 150, 184, 93, 125,
        ],
        pre_o1_count: 2421,
        post_o1_hash: [
            194, 29, 243, 0, 142, 237, 92, 68, 7, 196, 241, 49, 160, 107, 137, 74, 108, 21, 160,
            83, 121, 52, 66, 129, 131, 148, 87, 23, 23, 212, 162, 14,
        ],
        post_o1_count: 1185,
        num_variables: 2423,
        public_inputs: vec!["final_hash".into()],
    }
}

pub(super) fn pin_tornado_mixer_withdrawal() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            34, 52, 73, 190, 29, 5, 48, 126, 247, 68, 3, 132, 238, 36, 192, 2, 189, 180, 90, 170,
            238, 120, 226, 148, 221, 45, 30, 25, 26, 87, 247, 89,
        ],
        pre_o1_count: 1461,
        post_o1_hash: [
            244, 54, 156, 199, 10, 57, 53, 118, 251, 137, 228, 92, 145, 219, 132, 8, 186, 164, 119,
            167, 238, 70, 170, 213, 239, 233, 250, 60, 37, 69, 220, 74,
        ],
        post_o1_count: 963,
        num_variables: 1467,
        public_inputs: vec!["root".into(), "nullifier_hash".into(), "recipient".into()],
    }
}

pub(super) fn pin_tornado_mixer_double_spend_check() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            190, 100, 22, 96, 93, 204, 139, 145, 243, 239, 252, 147, 157, 228, 65, 123, 46, 205,
            10, 227, 156, 107, 53, 205, 180, 130, 162, 133, 255, 138, 241, 162,
        ],
        pre_o1_count: 363,
        post_o1_hash: [
            142, 23, 75, 240, 167, 220, 142, 207, 232, 193, 21, 62, 112, 175, 105, 229, 192, 149,
            254, 170, 76, 130, 125, 140, 90, 13, 241, 122, 151, 135, 15, 34,
        ],
        post_o1_count: 237,
        num_variables: 365,
        public_inputs: vec!["nullifier_hash".into()],
    }
}

pub(super) fn pin_tornado_mixer_withdrawal_2() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            34, 52, 73, 190, 29, 5, 48, 126, 247, 68, 3, 132, 238, 36, 192, 2, 189, 180, 90, 170,
            238, 120, 226, 148, 221, 45, 30, 25, 26, 87, 247, 89,
        ],
        pre_o1_count: 1461,
        post_o1_hash: [
            244, 54, 156, 199, 10, 57, 53, 118, 251, 137, 228, 92, 145, 219, 132, 8, 186, 164, 119,
            167, 238, 70, 170, 213, 239, 233, 250, 60, 37, 69, 220, 74,
        ],
        post_o1_count: 963,
        num_variables: 1467,
        public_inputs: vec![
            "root".into(),
            "nullifier_hash_2".into(),
            "recipient_2".into(),
        ],
    }
}

pub(super) fn pin_tornado_multifile_withdraw() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            23, 166, 200, 155, 86, 117, 200, 29, 200, 238, 21, 201, 23, 36, 81, 132, 211, 164, 110,
            72, 76, 51, 22, 235, 117, 216, 15, 78, 40, 49, 128, 37,
        ],
        pre_o1_count: 2968,
        post_o1_hash: [
            243, 91, 28, 141, 172, 129, 76, 131, 36, 79, 228, 47, 23, 143, 128, 163, 127, 14, 39,
            37, 184, 23, 81, 48, 144, 54, 98, 83, 146, 168, 46, 126,
        ],
        post_o1_count: 1453,
        num_variables: 2979,
        public_inputs: vec!["root".into(), "nh".into()],
    }
}
