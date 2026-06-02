use super::*;

// ------------------------------------------------------------------
// bits_of_field_const
// ------------------------------------------------------------------

#[test]
fn bits_of_zero_is_zero() {
    assert_eq!(bits_of_field_const(&fc(0)), 0);
}

#[test]
fn bits_of_one_is_one() {
    assert_eq!(bits_of_field_const(&fc(1)), 1);
}

#[test]
fn bits_of_small_values() {
    assert_eq!(bits_of_field_const(&fc(0xff)), 8);
    assert_eq!(bits_of_field_const(&fc(0x100)), 9);
    assert_eq!(bits_of_field_const(&fc(0xffff_ffff)), 32);
    assert_eq!(bits_of_field_const(&fc(0x1_0000_0000)), 33);
}

#[test]
fn bits_of_high_limb() {
    // Set the top bit of limb 0 → bits = 64.
    let v = fc_from_limbs([1u64 << 63, 0, 0, 0]);
    assert_eq!(bits_of_field_const(&v), 64);
    // Set the lowest bit of limb 1 → bits = 65.
    let v = fc_from_limbs([0, 1, 0, 0]);
    assert_eq!(bits_of_field_const(&v), 65);
    // Set the top bit of limb 3 → bits = 256.
    let v = fc_from_limbs([0, 0, 0, 1u64 << 63]);
    assert_eq!(bits_of_field_const(&v), 256);
}

// ------------------------------------------------------------------
// BitWidth::widen / join
// ------------------------------------------------------------------

#[test]
fn widen_saturates_at_field() {
    assert_eq!(BitWidth::widen(0), BitWidth::AtMost(0));
    assert_eq!(BitWidth::widen(32), BitWidth::AtMost(32));
    assert_eq!(BitWidth::widen(253), BitWidth::AtMost(253));
    assert_eq!(BitWidth::widen(254), BitWidth::Field);
    assert_eq!(BitWidth::widen(255), BitWidth::Field);
    assert_eq!(BitWidth::widen(u32::MAX), BitWidth::Field);
}

#[test]
fn join_preserves_exact_when_equal() {
    assert_eq!(
        BitWidth::Exact(8).join(BitWidth::Exact(8)),
        BitWidth::Exact(8)
    );
}

#[test]
fn join_widens_to_atmost_when_unequal_exact() {
    assert_eq!(
        BitWidth::Exact(8).join(BitWidth::Exact(16)),
        BitWidth::AtMost(16)
    );
}

#[test]
fn join_with_field_yields_field() {
    assert_eq!(BitWidth::Exact(8).join(BitWidth::Field), BitWidth::Field);
    assert_eq!(BitWidth::Field.join(BitWidth::AtMost(32)), BitWidth::Field);
}

#[test]
fn to_num_bits_returns_concrete_count() {
    assert_eq!(BitWidth::Exact(8).to_num_bits(), 8);
    assert_eq!(BitWidth::AtMost(32).to_num_bits(), 32);
    assert_eq!(BitWidth::Field.to_num_bits(), FIELD_BITS);
}
