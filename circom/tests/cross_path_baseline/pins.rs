//! Pinned canonical-multiset baselines for `cross_path_baseline`.
//!
//! Each function returns the frozen literal for one template. Re-pin
//! via the REGEN flow documented in the parent test file.

use zkc::test_support::FrozenBaseline;

pub(crate) fn pin_num2bits_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            22, 170, 64, 81, 90, 153, 56, 218, 110, 128, 40, 166, 159, 78, 229, 120, 101, 110, 239,
            140, 108, 198, 91, 188, 157, 170, 125, 164, 110, 92, 133, 175,
        ],
        pre_o1_count: 25,
        post_o1_hash: [
            9, 27, 54, 13, 204, 78, 211, 178, 34, 132, 195, 10, 254, 69, 169, 64, 236, 223, 211,
            119, 35, 12, 234, 41, 4, 22, 42, 67, 202, 9, 243, 245,
        ],
        post_o1_count: 9,
        num_variables: 26,
        public_inputs: vec![
            "in".into(),
            "out_0".into(),
            "out_1".into(),
            "out_2".into(),
            "out_3".into(),
            "out_4".into(),
            "out_5".into(),
            "out_6".into(),
            "out_7".into(),
        ],
    }
}

pub(crate) fn pin_iszero() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            52, 44, 65, 177, 195, 202, 234, 59, 202, 203, 18, 224, 74, 209, 11, 144, 20, 106, 123,
            127, 74, 80, 9, 74, 225, 254, 88, 148, 197, 92, 247, 230,
        ],
        pre_o1_count: 4,
        post_o1_hash: [
            217, 70, 234, 155, 128, 234, 125, 16, 14, 196, 247, 114, 143, 130, 24, 228, 234, 171,
            24, 209, 250, 87, 18, 189, 69, 214, 38, 122, 26, 222, 58, 25,
        ],
        post_o1_count: 2,
        num_variables: 6,
        public_inputs: vec!["in".into(), "out".into()],
    }
}

pub(crate) fn pin_lessthan_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            138, 141, 86, 1, 5, 122, 166, 228, 14, 119, 185, 236, 203, 20, 255, 226, 102, 13, 193,
            224, 19, 177, 162, 120, 225, 55, 93, 56, 43, 154, 31, 248,
        ],
        pre_o1_count: 30,
        post_o1_hash: [
            176, 242, 80, 176, 11, 255, 89, 7, 147, 126, 242, 169, 79, 161, 179, 147, 34, 211, 10,
            69, 145, 106, 245, 103, 229, 89, 160, 115, 186, 173, 89, 126,
        ],
        post_o1_count: 9,
        num_variables: 33,
        public_inputs: vec!["in_0".into(), "in_1".into(), "out".into()],
    }
}

pub(crate) fn pin_pedersen_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            83, 47, 226, 200, 86, 3, 177, 90, 255, 16, 70, 233, 97, 159, 132, 255, 26, 107, 74,
            107, 118, 253, 129, 163, 146, 76, 110, 146, 102, 144, 209, 142,
        ],
        pre_o1_count: 30,
        post_o1_hash: [
            240, 198, 55, 137, 174, 219, 237, 91, 127, 203, 92, 102, 200, 22, 173, 135, 156, 228,
            108, 143, 121, 81, 59, 187, 121, 133, 157, 72, 180, 34, 67, 72,
        ],
        post_o1_count: 13,
        num_variables: 57,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

pub(crate) fn pin_escalarmulfix_253() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            8, 52, 148, 216, 41, 153, 46, 152, 92, 155, 189, 54, 144, 227, 141, 190, 35, 124, 57,
            106, 168, 142, 245, 176, 32, 41, 148, 92, 35, 75, 169, 169,
        ],
        pre_o1_count: 27,
        post_o1_hash: [
            228, 230, 80, 210, 118, 228, 106, 181, 76, 203, 19, 68, 189, 116, 36, 68, 99, 143, 30,
            104, 138, 44, 36, 236, 246, 150, 16, 56, 131, 216, 21, 117,
        ],
        post_o1_count: 11,
        num_variables: 44,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

pub(crate) fn pin_escalarmulany_254() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            246, 160, 73, 112, 140, 17, 214, 216, 137, 204, 185, 102, 177, 17, 204, 234, 241, 250,
            51, 134, 191, 164, 218, 93, 148, 62, 7, 122, 165, 211, 205, 231,
        ],
        pre_o1_count: 5325,
        post_o1_hash: [
            170, 59, 95, 44, 114, 177, 134, 98, 20, 201, 138, 61, 6, 235, 142, 86, 11, 12, 35, 78,
            189, 231, 113, 41, 28, 9, 97, 156, 180, 151, 247, 73,
        ],
        post_o1_count: 2310,
        num_variables: 5582,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

pub(crate) fn pin_poseidon_2() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            10, 36, 63, 36, 171, 14, 78, 202, 254, 82, 238, 72, 249, 65, 129, 161, 53, 175, 58,
            247, 57, 84, 45, 85, 122, 194, 235, 2, 168, 85, 53, 178,
        ],
        pre_o1_count: 491,
        post_o1_hash: [
            155, 15, 251, 46, 236, 19, 201, 89, 251, 223, 195, 198, 231, 90, 74, 111, 143, 180,
            211, 114, 108, 97, 185, 104, 99, 19, 105, 1, 65, 75, 254, 155,
        ],
        post_o1_count: 240,
        num_variables: 494,
        public_inputs: vec!["inputs_0".into(), "inputs_1".into(), "out".into()],
    }
}

pub(crate) fn pin_mimcsponge() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            21, 105, 6, 67, 74, 40, 158, 193, 201, 7, 18, 192, 184, 196, 52, 95, 74, 88, 34, 20,
            154, 59, 164, 25, 222, 238, 171, 19, 106, 13, 234, 132,
        ],
        pre_o1_count: 2581,
        post_o1_hash: [
            209, 57, 95, 246, 81, 199, 174, 43, 149, 79, 248, 22, 47, 132, 165, 241, 34, 19, 50,
            27, 154, 52, 143, 147, 33, 94, 35, 228, 122, 106, 158, 80,
        ],
        post_o1_count: 1317,
        num_variables: 2585,
        public_inputs: vec!["outs_0".into()],
    }
}

pub(crate) fn pin_babyjubjub() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            94, 33, 189, 175, 173, 144, 34, 119, 31, 155, 206, 153, 226, 25, 118, 123, 4, 182, 67,
            196, 110, 107, 245, 62, 191, 106, 20, 136, 13, 177, 210, 48,
        ],
        pre_o1_count: 30,
        post_o1_hash: [
            255, 1, 85, 58, 96, 215, 109, 91, 15, 212, 178, 94, 43, 27, 183, 11, 14, 102, 111, 132,
            199, 103, 30, 0, 105, 117, 224, 248, 152, 95, 24, 38,
        ],
        post_o1_count: 15,
        num_variables: 34,
        public_inputs: vec!["xout".into(), "yout".into()],
    }
}

pub(crate) fn pin_pedersen_old_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            211, 50, 45, 195, 124, 51, 201, 112, 210, 13, 114, 37, 146, 153, 121, 4, 236, 197, 96,
            218, 94, 219, 58, 125, 48, 228, 72, 196, 96, 154, 254, 78,
        ],
        pre_o1_count: 37,
        post_o1_hash: [
            167, 177, 144, 32, 220, 107, 139, 158, 58, 130, 88, 180, 64, 88, 177, 232, 121, 185,
            151, 38, 90, 166, 225, 161, 80, 55, 130, 139, 202, 138, 135, 65,
        ],
        post_o1_count: 18,
        num_variables: 46,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

pub(crate) fn pin_eddsaposeidon() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            46, 60, 63, 224, 235, 241, 9, 142, 21, 20, 136, 59, 192, 205, 235, 241, 38, 31, 226,
            81, 139, 249, 252, 4, 67, 3, 48, 16, 103, 117, 21, 224,
        ],
        pre_o1_count: 9719,
        post_o1_hash: [
            240, 149, 78, 219, 114, 124, 39, 198, 10, 186, 154, 82, 176, 223, 127, 71, 178, 235,
            41, 124, 181, 152, 33, 150, 57, 189, 64, 229, 57, 205, 255, 189,
        ],
        post_o1_count: 3965,
        num_variables: 10410,
        public_inputs: vec!["dummy".into()],
    }
}
