use super::FrozenBaseline;

pub(super) fn pin_prove_for_loop_nested() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            131, 198, 85, 76, 70, 99, 168, 46, 135, 59, 81, 255, 103, 177, 237, 127, 12, 250, 228,
            203, 71, 156, 41, 111, 10, 160, 46, 177, 105, 75, 252, 254,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            131, 198, 85, 76, 70, 99, 168, 46, 135, 59, 81, 255, 103, 177, 237, 127, 12, 250, 228,
            203, 71, 156, 41, 111, 10, 160, 46, 177, 105, 75, 252, 254,
        ],
        post_o1_count: 1,
        num_variables: 2,
        public_inputs: vec!["expected".into()],
    }
}

pub(super) fn pin_prove_for_loop_dynamic() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            99, 41, 87, 14, 200, 72, 232, 183, 138, 226, 94, 200, 12, 145, 136, 198, 220, 36, 237,
            203, 205, 216, 205, 164, 62, 52, 189, 86, 100, 163, 118, 64,
        ],
        pre_o1_count: 5,
        post_o1_hash: [
            23, 69, 36, 227, 97, 0, 218, 10, 79, 141, 159, 241, 70, 37, 129, 184, 99, 120, 206,
            207, 241, 112, 104, 137, 203, 119, 162, 242, 34, 169, 227, 145,
        ],
        post_o1_count: 2,
        num_variables: 4,
        public_inputs: vec!["target_sq".into()],
    }
}

pub(super) fn pin_prove_if_else_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            149, 196, 126, 240, 243, 70, 166, 183, 115, 58, 55, 127, 205, 220, 60, 132, 239, 173,
            99, 134, 162, 49, 127, 93, 185, 139, 97, 140, 123, 231, 58, 119,
        ],
        pre_o1_count: 8,
        post_o1_hash: [
            236, 147, 248, 223, 172, 12, 186, 30, 221, 39, 62, 17, 39, 62, 151, 125, 127, 16, 27,
            75, 105, 57, 91, 44, 95, 141, 44, 168, 93, 155, 202, 101,
        ],
        post_o1_count: 5,
        num_variables: 10,
        public_inputs: vec!["expected".into()],
    }
}

pub(super) fn pin_prove_if_else_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            149, 196, 126, 240, 243, 70, 166, 183, 115, 58, 55, 127, 205, 220, 60, 132, 239, 173,
            99, 134, 162, 49, 127, 93, 185, 139, 97, 140, 123, 231, 58, 119,
        ],
        pre_o1_count: 8,
        post_o1_hash: [
            236, 147, 248, 223, 172, 12, 186, 30, 221, 39, 62, 17, 39, 62, 151, 125, 127, 16, 27,
            75, 105, 57, 91, 44, 95, 141, 44, 168, 93, 155, 202, 101,
        ],
        post_o1_count: 5,
        num_variables: 10,
        public_inputs: vec!["expected_off".into()],
    }
}

pub(super) fn pin_prove_outer_fn_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            134, 125, 211, 250, 52, 228, 176, 186, 18, 9, 47, 0, 74, 21, 129, 130, 57, 115, 89,
            225, 144, 87, 19, 89, 141, 40, 171, 162, 47, 209, 143, 158,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 3,
        public_inputs: vec!["expected".into()],
    }
}

pub(super) fn pin_prove_outer_fn_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            181, 240, 120, 148, 86, 237, 169, 18, 165, 117, 22, 121, 162, 28, 105, 233, 231, 1, 6,
            202, 205, 55, 93, 189, 91, 116, 96, 198, 249, 252, 223, 157,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 5,
        public_inputs: vec!["sum".into()],
    }
}

pub(super) fn pin_prove_outer_fn_circuit() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            128, 62, 41, 169, 3, 94, 128, 125, 250, 1, 33, 138, 96, 116, 112, 9, 22, 110, 102, 42,
            107, 29, 156, 92, 10, 149, 213, 112, 221, 15, 117, 238,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            128, 62, 41, 169, 3, 94, 128, 125, 250, 1, 33, 138, 96, 116, 112, 9, 22, 110, 102, 42,
            107, 29, 156, 92, 10, 149, 213, 112, 221, 15, 117, 238,
        ],
        post_o1_count: 1,
        num_variables: 3,
        public_inputs: vec!["input".into(), "expected".into()],
    }
}

pub(super) fn pin_prove_power() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            131, 134, 99, 127, 20, 4, 83, 89, 93, 121, 186, 33, 20, 191, 103, 193, 210, 16, 183,
            90, 67, 186, 74, 179, 253, 163, 237, 244, 83, 60, 69, 242,
        ],
        pre_o1_count: 4,
        post_o1_hash: [
            239, 87, 19, 175, 190, 236, 243, 252, 115, 171, 13, 53, 125, 35, 235, 246, 214, 191,
            215, 109, 28, 162, 102, 255, 44, 153, 239, 144, 180, 123, 180, 151,
        ],
        post_o1_count: 2,
        num_variables: 6,
        public_inputs: vec!["sq".into(), "cube".into()],
    }
}
