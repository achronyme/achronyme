use super::FrozenBaseline;

pub(super) fn pin_prove_range_check_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            212, 224, 33, 236, 243, 175, 169, 150, 44, 75, 58, 88, 108, 109, 218, 126, 170, 174,
            134, 235, 187, 220, 181, 196, 24, 118, 93, 184, 231, 102, 34, 90,
        ],
        pre_o1_count: 9,
        post_o1_hash: [
            70, 180, 244, 221, 25, 109, 208, 1, 227, 189, 139, 77, 82, 2, 247, 216, 132, 124, 108,
            211, 95, 135, 206, 240, 135, 104, 163, 149, 239, 167, 129, 32,
        ],
        post_o1_count: 8,
        num_variables: 10,
        public_inputs: Vec::new(),
    }
}

pub(super) fn pin_prove_range_check_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            97, 143, 110, 218, 73, 46, 35, 49, 121, 199, 212, 39, 7, 245, 188, 130, 124, 80, 121,
            226, 129, 220, 173, 209, 142, 64, 199, 101, 54, 47, 99, 186,
        ],
        pre_o1_count: 17,
        post_o1_hash: [
            170, 68, 139, 200, 255, 234, 125, 87, 240, 193, 137, 232, 164, 50, 251, 243, 32, 32,
            244, 135, 185, 194, 103, 79, 176, 125, 214, 208, 211, 254, 35, 23,
        ],
        post_o1_count: 16,
        num_variables: 18,
        public_inputs: Vec::new(),
    }
}

pub(super) fn pin_prove_secret_vote() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            217, 3, 43, 253, 45, 89, 227, 221, 63, 167, 84, 55, 89, 246, 144, 47, 164, 55, 102,
            215, 142, 63, 82, 4, 156, 129, 34, 140, 235, 187, 75, 167,
        ],
        pre_o1_count: 1463,
        post_o1_hash: [
            76, 29, 150, 19, 127, 41, 121, 187, 92, 225, 116, 7, 174, 120, 249, 90, 18, 228, 157,
            119, 61, 186, 218, 26, 226, 85, 151, 12, 116, 16, 19, 130,
        ],
        post_o1_count: 964,
        num_variables: 1468,
        public_inputs: vec![
            "merkle_root".into(),
            "nullifier".into(),
            "vote".into(),
            "election_id".into(),
        ],
    }
}

pub(super) fn pin_prove_with_poseidon() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            165, 49, 103, 201, 26, 66, 96, 21, 162, 203, 58, 52, 74, 46, 99, 24, 187, 254, 144, 34,
            138, 198, 23, 238, 155, 132, 157, 25, 187, 17, 149, 109,
        ],
        pre_o1_count: 362,
        post_o1_hash: [
            38, 248, 251, 186, 170, 70, 52, 22, 245, 120, 58, 192, 104, 140, 70, 180, 205, 190, 52,
            32, 25, 209, 37, 25, 206, 128, 106, 28, 14, 29, 10, 93,
        ],
        post_o1_count: 240,
        num_variables: 365,
        public_inputs: vec!["h".into()],
    }
}

pub(super) fn pin_typed_prove_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            103, 62, 152, 139, 48, 217, 149, 137, 115, 187, 194, 183, 248, 72, 219, 141, 87, 137,
            70, 171, 47, 208, 201, 102, 207, 129, 89, 127, 117, 150, 91, 3,
        ],
        pre_o1_count: 2,
        post_o1_hash: [
            217, 207, 0, 42, 164, 232, 81, 250, 143, 157, 168, 11, 57, 228, 116, 121, 130, 145,
            135, 226, 135, 69, 167, 2, 249, 146, 0, 235, 213, 88, 217, 30,
        ],
        post_o1_count: 1,
        num_variables: 5,
        public_inputs: vec!["product".into()],
    }
}

pub(super) fn pin_typed_prove_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            94, 193, 186, 192, 174, 58, 212, 59, 247, 175, 186, 51, 158, 178, 161, 113, 19, 35,
            248, 253, 244, 224, 12, 178, 50, 6, 101, 159, 18, 183, 136, 109,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 4,
        public_inputs: vec!["sum".into()],
    }
}

pub(super) fn pin_babyadd() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            224, 43, 28, 98, 93, 4, 94, 227, 144, 108, 216, 117, 242, 21, 146, 103, 68, 219, 236,
            203, 231, 49, 19, 114, 81, 100, 79, 209, 142, 65, 253, 215,
        ],
        pre_o1_count: 4,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 3,
        public_inputs: Vec::new(),
    }
}
