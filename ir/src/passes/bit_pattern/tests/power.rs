use memory::FieldElement;

use super::super::sum::is_power_of_two;

#[test]
fn is_power_of_two_works() {
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(1)),
        Some(0)
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(2)),
        Some(1)
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(4)),
        Some(2)
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(8)),
        Some(3)
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(1 << 63)),
        Some(63)
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(0)),
        None
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(3)),
        None
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(5)),
        None
    );
    assert_eq!(
        is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(6)),
        None
    );
}
