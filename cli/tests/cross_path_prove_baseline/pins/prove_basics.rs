use super::FrozenBaseline;

pub(super) fn pin_basic_prove() -> FrozenBaseline {
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

pub(super) fn pin_prove_array_sum() -> FrozenBaseline {
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
        public_inputs: vec!["total".into()],
    }
}

pub(super) fn pin_prove_assert_message() -> FrozenBaseline {
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

pub(super) fn pin_prove_boolean_mux() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            213, 155, 148, 62, 158, 102, 135, 208, 15, 232, 140, 105, 121, 65, 21, 56, 115, 66, 20,
            79, 60, 96, 210, 10, 94, 69, 129, 191, 88, 251, 200, 156,
        ],
        pre_o1_count: 6,
        post_o1_hash: [
            102, 134, 105, 141, 110, 85, 72, 205, 8, 8, 81, 96, 217, 208, 34, 25, 162, 116, 242,
            155, 170, 231, 56, 4, 182, 128, 149, 164, 97, 140, 239, 135,
        ],
        post_o1_count: 2,
        num_variables: 8,
        public_inputs: vec!["expected".into()],
    }
}

pub(super) fn pin_prove_capture_0() -> FrozenBaseline {
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

pub(super) fn pin_prove_capture_1() -> FrozenBaseline {
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

pub(super) fn pin_prove_chain_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            250, 76, 21, 101, 7, 25, 125, 172, 4, 24, 89, 106, 30, 51, 3, 72, 188, 169, 218, 7,
            179, 210, 5, 57, 26, 222, 232, 133, 133, 221, 51, 211,
        ],
        pre_o1_count: 362,
        post_o1_hash: [
            61, 234, 174, 64, 197, 152, 224, 49, 68, 104, 81, 42, 135, 231, 191, 0, 189, 117, 169,
            72, 202, 116, 203, 3, 177, 1, 33, 187, 50, 47, 152, 206,
        ],
        post_o1_count: 240,
        num_variables: 365,
        public_inputs: vec!["commitment".into()],
    }
}

pub(super) fn pin_prove_chain_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            250, 76, 21, 101, 7, 25, 125, 172, 4, 24, 89, 106, 30, 51, 3, 72, 188, 169, 218, 7,
            179, 210, 5, 57, 26, 222, 232, 133, 133, 221, 51, 211,
        ],
        pre_o1_count: 362,
        post_o1_hash: [
            61, 234, 174, 64, 197, 152, 224, 49, 68, 104, 81, 42, 135, 231, 191, 0, 189, 117, 169,
            72, 202, 116, 203, 3, 177, 1, 33, 187, 50, 47, 152, 206,
        ],
        post_o1_count: 240,
        num_variables: 365,
        public_inputs: vec!["nullifier".into()],
    }
}

pub(super) fn pin_prove_comparison() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            184, 117, 232, 153, 171, 42, 138, 231, 129, 173, 156, 146, 251, 60, 49, 134, 235, 47,
            213, 19, 202, 229, 121, 85, 195, 154, 80, 83, 77, 175, 174, 223,
        ],
        pre_o1_count: 1527,
        post_o1_hash: [
            37, 89, 184, 191, 51, 95, 174, 39, 176, 169, 115, 11, 186, 23, 11, 108, 135, 229, 33,
            100, 204, 121, 104, 19, 83, 112, 250, 89, 119, 34, 63, 184,
        ],
        post_o1_count: 1513,
        num_variables: 1521,
        public_inputs: Vec::new(),
    }
}

pub(super) fn pin_prove_division() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            59, 21, 210, 121, 95, 41, 254, 159, 11, 135, 153, 150, 141, 84, 162, 142, 65, 240, 213,
            172, 109, 107, 254, 247, 240, 255, 113, 152, 17, 75, 16, 155,
        ],
        pre_o1_count: 3,
        post_o1_hash: [
            179, 73, 234, 80, 45, 227, 184, 188, 5, 201, 21, 213, 28, 116, 233, 12, 8, 208, 50,
            164, 151, 180, 206, 235, 50, 83, 154, 47, 203, 190, 136, 215,
        ],
        post_o1_count: 2,
        num_variables: 6,
        public_inputs: vec!["q".into()],
    }
}

pub(super) fn pin_prove_for_loop() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            231, 134, 31, 240, 111, 95, 24, 34, 63, 149, 144, 181, 104, 1, 92, 112, 98, 14, 249,
            232, 104, 41, 44, 255, 153, 19, 241, 164, 196, 169, 123, 97,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 6,
        public_inputs: vec!["total".into()],
    }
}
