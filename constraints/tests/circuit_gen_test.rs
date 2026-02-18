use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use memory::FieldElement;

/// Simulates what the R1CSCompiler will generate for the following Achronyme code:
///
/// fn main(secret_a, secret_b, public_target) {
///     let product = secret_a * secret_b;
///     product == public_target;
/// }
#[test]
fn test_compile_simple_circuit_manually() {
    // 1. Initialize Constraint System
    let mut cs = ConstraintSystem::new();

    // 2. Symbol Table (Simulated)
    // Map variable names to CS Variables
    let mut symbols: std::collections::HashMap<String, Variable> = std::collections::HashMap::new();

    // 3. Compile Function Arguments
    // secret_a -> Witness
    let var_a = cs.alloc_witness();
    symbols.insert("secret_a".to_string(), var_a);

    // secret_b -> Witness
    let var_b = cs.alloc_witness();
    symbols.insert("secret_b".to_string(), var_b);

    // public_target -> Public Input
    let var_target = cs.alloc_input();
    symbols.insert("public_target".to_string(), var_target);

    // 4. Compile Body
    // let product = secret_a * secret_b;
    let lc_a = LinearCombination::from_variable(symbols["secret_a"]);
    let lc_b = LinearCombination::from_variable(symbols["secret_b"]);
    
    // In AST: BinaryOp::Mul(a, b) -> leads to cs.mul_lc
    let var_product = cs.mul_lc(&lc_a, &lc_b); 
    symbols.insert("product".to_string(), var_product);

    // product == public_target
    // In AST: BinaryOp::Eq(product, target) -> leads to cs.enforce_equal
    let lc_product = LinearCombination::from_variable(symbols["product"]);
    let lc_target = LinearCombination::from_variable(symbols["public_target"]);
    
    cs.enforce_equal(lc_product, lc_target);

    // ==========================================================
    // Verification (Prover Side)
    // ==========================================================
    
    // This part effectively simulates the "Witness Calculator" running in the VM
    // The VM would execute the code normally:
    // a = 5, b = 6 -> product = 30.
    
    let val_a = FieldElement::from_u64(5);
    let val_b = FieldElement::from_u64(6);
    let val_target = FieldElement::from_u64(30);
    let val_product = val_a.mul(&val_b);

    // Construct the full witness vector
    // Layout: [ONE, public_target, secret_a, secret_b, product]
    // Index:   0    1              2         3         4
    
    // Verify indices match allocation order
    // Allocation sequence:
    // 0: ONE (reserved)
    // 1: secret_a (witness)
    // 2: secret_b (witness)
    // 3: public_target (input)
    // 4: product (intermediate witness from mul_lc)
    
    assert_eq!(var_a.index(), 1);
    assert_eq!(var_b.index(), 2);
    assert_eq!(var_target.index(), 3);
    assert_eq!(var_product.index(), 4);

    let witness = vec![
        FieldElement::ONE,  // 0
        val_a,              // 1 (secret_a)
        val_b,              // 2 (secret_b)
        val_target,         // 3 (public_target)
        val_product,        // 4 (product)
    ];

    assert!(cs.verify(&witness).is_ok(), "Circuit verification failed");

    // Test invalid witness
    let bad_witness = vec![
        FieldElement::ONE,
        val_a,
        val_b,
        val_target,
        FieldElement::from_u64(31), // Wrong product (e.g. 5*6 != 31)
    ];
    assert!(cs.verify(&bad_witness).is_err(), "Circuit should reject invalid witness");
}
