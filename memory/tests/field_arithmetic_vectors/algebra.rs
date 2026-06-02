use super::*;

// ============================================================================
// Algebraic properties — commutativity
// ============================================================================

macro_rules! commutativity_tests {
    ($op:ident, $method:ident, $( ($name:ident, $a:expr, $b:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                assert_eq!(a.$method(&b), b.$method(&a),
                    "{}: commutativity failed for {} {} {}",
                    stringify!($name), $a, stringify!($method), $b);
            }
        )+
    };
}

commutativity_tests!(
    add,
    add,
    (comm_add_0_1, "0", "1"),
    (comm_add_1_2, "1", "2"),
    (comm_add_42_99, "42", "99"),
    (comm_add_large_small, P_MINUS_1, "7"),
    (comm_add_half_1, HALF_P, "1"),
    (comm_add_large_large, P_MINUS_1, P_MINUS_2),
    (comm_add_3_5, "3", "5"),
    (comm_add_7_13, "7", "13"),
    (comm_add_17_19, "17", "19"),
    (comm_add_23_29, "23", "29"),
    (comm_add_31_37, "31", "37"),
    (comm_add_half_large, HALF_P, P_MINUS_1),
);

commutativity_tests!(
    mul,
    mul,
    (comm_mul_0_1, "0", "1"),
    (comm_mul_1_2, "1", "2"),
    (comm_mul_42_99, "42", "99"),
    (comm_mul_large_small, P_MINUS_1, "7"),
    (comm_mul_half_1, HALF_P, "3"),
    (comm_mul_large_large, P_MINUS_1, P_MINUS_2),
    (comm_mul_3_5, "3", "5"),
    (comm_mul_7_13, "7", "13"),
    (comm_mul_17_19, "17", "19"),
    (comm_mul_23_29, "23", "29"),
    (comm_mul_31_37, "31", "37"),
    (comm_mul_half_large, HALF_P, P_MINUS_1),
);

// ============================================================================
// Algebraic properties — associativity
// ============================================================================

macro_rules! associativity_tests {
    ($method:ident, $( ($name:ident, $a:expr, $b:expr, $c:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                let c = fe($c);
                let lhs = a.$method(&b).$method(&c);
                let rhs = a.$method(&b.$method(&c));
                assert_eq!(lhs, rhs,
                    "{}: associativity failed for ({} {} {}) {} {}",
                    stringify!($name), $a, stringify!($method), $b, stringify!($method), $c);
            }
        )+
    };
}

associativity_tests!(
    add,
    (assoc_add_1_2_3, "1", "2", "3"),
    (assoc_add_large, P_MINUS_1, "5", "7"),
    (assoc_add_half, HALF_P, HALF_P, "1"),
    (assoc_add_zeros, "0", "0", "0"),
    (assoc_add_mixed, "42", P_MINUS_2, "100"),
);

associativity_tests!(
    mul,
    (assoc_mul_2_3_5, "2", "3", "5"),
    (assoc_mul_large, P_MINUS_1, "3", "7"),
    (assoc_mul_ones, "1", "1", "1"),
    (assoc_mul_mixed, "42", "13", "97"),
);

// ============================================================================
// Algebraic properties — distributivity: a * (b + c) == a*b + a*c
// ============================================================================

macro_rules! distributivity_tests {
    ($( ($name:ident, $a:expr, $b:expr, $c:expr) ),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a = fe($a);
                let b = fe($b);
                let c = fe($c);
                let lhs = a.mul(&b.add(&c));
                let rhs = a.mul(&b).add(&a.mul(&c));
                assert_eq!(lhs, rhs,
                    "{}: distributivity failed: {} * ({} + {}) != {} * {} + {} * {}",
                    stringify!($name), $a, $b, $c, $a, $b, $a, $c);
            }
        )+
    };
}

distributivity_tests!(
    (dist_2_3_5, "2", "3", "5"),
    (dist_large, P_MINUS_1, "42", "99"),
    (dist_half, HALF_P, "3", "7"),
    (dist_zero, "0", "1", "2"),
    (dist_one, "1", P_MINUS_1, "1"),
    (dist_mixed, "17", P_MINUS_2, HALF_P),
);
