use std::collections::HashMap;

use memory::FieldElement;

mod assertions;
mod basics;
mod errors;

fn empty_inputs() -> HashMap<String, FieldElement> {
    HashMap::new()
}

fn fe(n: u64) -> FieldElement {
    FieldElement::from_u64(n)
}
