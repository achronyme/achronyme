use super::FrozenBaseline;

#[path = "pins/examples.rs"]
mod examples;
#[path = "pins/prove_basics.rs"]
mod prove_basics;
#[path = "pins/prove_control.rs"]
mod prove_control;
#[path = "pins/prove_misc.rs"]
mod prove_misc;

use examples::*;
use prove_basics::*;
use prove_control::*;
use prove_misc::*;

pub(crate) fn pin_for(key: &str) -> Option<FrozenBaseline> {
    Some(match key {
        "proof_of_membership/membership" => pin_proof_of_membership_membership(),
        "proof_of_membership/membership_0" => pin_proof_of_membership_membership_0(),
        "circom_merkle_membership/membership" => pin_circom_merkle_membership(),
        "circom_poseidon_chain/(anonymous #0)" => pin_circom_poseidon_chain(),
        "tornado_mixer/withdrawal" => pin_tornado_mixer_withdrawal(),
        "tornado_mixer/double_spend_check" => pin_tornado_mixer_double_spend_check(),
        "tornado_mixer/withdrawal_2" => pin_tornado_mixer_withdrawal_2(),
        "tornado_multifile/withdraw" => pin_tornado_multifile_withdraw(),
        "test/basic_prove/(anonymous #0)" => pin_basic_prove(),
        "test/prove_array_sum/(anonymous #0)" => pin_prove_array_sum(),
        "test/prove_assert_message/(anonymous #0)" => pin_prove_assert_message(),
        "test/prove_boolean_mux/(anonymous #0)" => pin_prove_boolean_mux(),
        "test/prove_capture/(anonymous #0)" => pin_prove_capture_0(),
        "test/prove_capture/(anonymous #1)" => pin_prove_capture_1(),
        "test/prove_chain/(anonymous #0)" => pin_prove_chain_0(),
        "test/prove_chain/(anonymous #1)" => pin_prove_chain_1(),
        "test/prove_comparison/(anonymous #0)" => pin_prove_comparison(),
        "test/prove_division/(anonymous #0)" => pin_prove_division(),
        "test/prove_for_loop/(anonymous #0)" => pin_prove_for_loop(),
        "test/prove_for_loop_nested/(anonymous #0)" => pin_prove_for_loop_nested(),
        "test/prove_for_loop_dynamic/(anonymous #0)" => pin_prove_for_loop_dynamic(),
        "test/prove_if_else/(anonymous #0)" => pin_prove_if_else_0(),
        "test/prove_if_else/(anonymous #1)" => pin_prove_if_else_1(),
        "test/prove_outer_fn/(anonymous #0)" => pin_prove_outer_fn_0(),
        "test/prove_outer_fn/(anonymous #1)" => pin_prove_outer_fn_1(),
        "test/prove_outer_fn_circuit/tripler" => pin_prove_outer_fn_circuit(),
        "test/prove_power/(anonymous #0)" => pin_prove_power(),
        "test/prove_range_check/(anonymous #0)" => pin_prove_range_check_0(),
        "test/prove_range_check/(anonymous #1)" => pin_prove_range_check_1(),
        "test/prove_secret_vote/(anonymous #0)" => pin_prove_secret_vote(),
        "test/prove_with_poseidon/(anonymous #0)" => pin_prove_with_poseidon(),
        "test/typed_prove/(anonymous #0)" => pin_typed_prove_0(),
        "test/typed_prove/(anonymous #1)" => pin_typed_prove_1(),
        "test/babyadd/(anonymous #0)" => pin_babyadd(),
        _ => return None,
    })
}
