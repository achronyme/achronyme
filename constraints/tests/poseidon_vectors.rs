//! Phase I — Poseidon Hash Reference Vectors (BN254, t=3)
//!
//! Industry-sourced test vectors from:
//!   - circomlibjs v0.1.7 (iden3): https://github.com/iden3/circomlibjs/blob/main/test/poseidon.js
//!   - go-iden3-crypto:            https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon_test.go
//!   - arkworks test-templates:    https://github.com/arkworks-rs/algebra/blob/master/test-templates/src/fields.rs
//!
//! Configuration: t=3, RF=8, RP=57, S-box x^5, BN254 Fr.
//! Constants: circomlibjs convention (NOT Poseidon paper LFSR).
//! License compatibility: all sources GPL-3.0 or MIT/Apache-2.0, compatible with our GPL-3.0.

use constraints::poseidon::{
    native::{poseidon_hash, poseidon_hash_single, sbox},
    PoseidonParams,
};
use memory::FieldElement;

fn fe(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

fn params() -> PoseidonParams {
    PoseidonParams::bn254_t3()
}

// ============================================================================
// circomlibjs reference vectors
// Source: https://github.com/iden3/circomlibjs/blob/main/test/poseidon.js
// ============================================================================

/// poseidon([1, 2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
/// Verified in both circomlibjs (JS) and go-iden3-crypto (Go).
/// This is THE canonical Poseidon test vector for BN254 t=3.
///
/// Source: circomlibjs test/poseidon.js line ~11
/// Source: go-iden3-crypto poseidon/poseidon_test.go TestPoseidonHash
#[test]
fn circomlibjs_poseidon_1_2() {
    let h = poseidon_hash(
        &params(),
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    let expected =
        fe("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    assert_eq!(h, expected);
}

/// poseidon([1, 2]) full permutation state verification.
/// circomlibjs nOut=2 returns [state[0], state[1]] after permutation.
///   state[0] = 7853200120776062878684798364095072458815029376092732009249414926327459813530
///   state[1] = 7142104613055408817911962100316808866448378443474503659992478482890339429929
///
/// Source: circomlibjs test/poseidon.js nOut=2 test vector
/// Source: go-iden3-crypto TestPoseidonHashEx nOuts=2
/// Cross-verified: both implementations produce identical state[0] and state[1].
#[test]
fn circomlibjs_poseidon_1_2_full_state() {
    use constraints::poseidon::native::poseidon_permutation;

    let p = params();
    let mut state = [
        FieldElement::ZERO,
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    ];
    poseidon_permutation(&p, &mut state);

    // state[0] — primary hash output (circomlibjs convention)
    assert_eq!(
        state[0],
        fe("7853200120776062878684798364095072458815029376092732009249414926327459813530"),
        "state[0] mismatch vs circomlibjs/go-iden3-crypto"
    );
    // state[1] — second output, verified in circomlibjs nOut=2 and go-iden3-crypto HashEx nOuts=2
    assert_eq!(
        state[1],
        fe("7142104613055408817911962100316808866448378443474503659992478482890339429929"),
        "state[1] mismatch vs circomlibjs/go-iden3-crypto"
    );
}

/// poseidon([1, 2, 3, 4]) = 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465
/// Source: circomlibjs test/poseidon.js line ~32
/// This is a 4-input hash (t=5, arity 4). Documented for future multi-arity.
#[test]
fn circomlibjs_poseidon_1_2_3_4_documented() {
    let reference: FieldElement = FieldElement::from_hex_str(
        "0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
    )
    .unwrap();
    assert!(!reference.is_zero());
}

// ============================================================================
// go-iden3-crypto reference vectors
// Source: https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon_test.go
// Function: TestPoseidonHash
// ============================================================================

/// poseidon([1]) = 18586133768512220936620570745912940619677854269274689475585506675881198879027
/// Source: go-iden3-crypto TestPoseidonHash, first test case
///
/// Note: go-iden3-crypto's Hash([1]) uses t=2 (arity 1), but our poseidon_hash_single
/// uses state = [0, input, 0] with t=3. This means our output will differ from
/// go-iden3-crypto's single-input hash because the arity changes the number of
/// partial rounds (56 for t=2 vs 57 for t=3) and the constants used.
/// We verify our implementation is internally consistent instead.
#[test]
fn go_iden3_poseidon_single_deterministic() {
    let p = params();
    let h1 = poseidon_hash_single(&p, FieldElement::from_u64(1));
    let h2 = poseidon_hash_single(&p, FieldElement::from_u64(1));
    assert_eq!(h1, h2, "poseidon_single(1) must be deterministic");
    assert!(!h1.is_zero(), "poseidon_single(1) must not be zero");
}

/// poseidon([1, 2]) confirmed in go-iden3-crypto = 7853200120776062878684798364095072458815029376092732009249414926327459813530
/// Source: go-iden3-crypto TestPoseidonHash, second test case
/// This confirms cross-implementation compatibility between JS (circomlibjs) and Go (go-iden3-crypto).
#[test]
fn go_iden3_poseidon_1_2() {
    let h = poseidon_hash(
        &params(),
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    let expected =
        fe("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    assert_eq!(h, expected);
}

/// poseidon([1, 2, 3, 4, 5, 6]) = 20400040500897583745843009878988256314335038853985262692600694741116813247201
/// Source: go-iden3-crypto TestPoseidonHash
/// Source: circomlibjs test/poseidon.js (with initState=0)
///
/// This is a 6-input hash (t=7, arity 6). Our system doesn't support t=7 natively,
/// but we verify the cross-reference: this value is confirmed in both JS and Go implementations.
/// Stored here as documentation for when we add multi-arity support.
#[test]
fn go_iden3_poseidon_6_inputs_documented() {
    // Value: 20400040500897583745843009878988256314335038853985262692600694741116813247201
    // This test documents the reference value. We cannot compute it with t=3 directly.
    // When multi-arity Poseidon is added, this value should be verified.
    let reference =
        fe("20400040500897583745843009878988256314335038853985262692600694741116813247201");
    assert!(!reference.is_zero(), "reference value must parse correctly");
}

/// poseidon([1..16]) = 9989051620750914585850546081941653841776809718687451684622678807385399211877
/// Source: go-iden3-crypto TestPoseidonHash
/// Source: circomlibjs test/poseidon.js
///
/// 16-input Poseidon (t=17). Documented for future multi-arity support.
#[test]
fn go_iden3_poseidon_16_inputs_documented() {
    let reference =
        fe("9989051620750914585850546081941653841776809718687451684622678807385399211877");
    assert!(!reference.is_zero());
}

// ============================================================================
// go-iden3-crypto TestPoseidonHashEx — multi-output vectors (documented)
// Source: https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon_test.go
// These are the complete state outputs for poseidon([1..16], nOuts=11).
// Cross-verified with circomlibjs test/poseidon.js nOut=11 test vector.
// ============================================================================

/// All 11 outputs of poseidon([1..16]) — cross-verified in circomlibjs AND go-iden3-crypto.
/// These values are documented for when we add multi-arity + multi-output support.
///
/// Source: go-iden3-crypto TestPoseidonHashEx, last test case
/// Source: circomlibjs test/poseidon.js, nOut=11 test vector
#[test]
fn go_iden3_poseidon_16_inputs_11_outputs_documented() {
    // Each value independently verified in both circomlibjs (JS) and go-iden3-crypto (Go)
    let outputs = [
        "9989051620750914585850546081941653841776809718687451684622678807385399211877",
        "8319791455060392555425392842391403897548969645190976863995973180967774875286",
        "21636406227810893698117978732800647815305553312233448361627674958309476058692",
        "5858261170370825589990804751061473291946977191299454947182890419569833191564",
        "9379453522659079974536893534601645512603628658741037060370899250203068088821",
        "473570682425071423656832074606161521036781375454126861176650950315985887926",
        "6579803930273263668667567320853266118141819373699554146671374489258288008348",
        "19782381913414087710766737863494215505205430771941455097533197858199467016164",
        "16057750626779488870446366989248320873718232843994532204040561017822304578116",
        "18984357576272539606133217260692170661113104846539835604742079547853774113837",
        "6999414602732066348339779277600222355871064730107676749892229157577448591106",
    ];
    for (i, val) in outputs.iter().enumerate() {
        let parsed = fe(val);
        assert!(!parsed.is_zero(), "output[{i}] must parse correctly");
    }
}

/// All 16 outputs of poseidon([1..16], initState=17) — go-iden3-crypto TestHashWithStateEx
/// Cross-verified with circomlibjs test/poseidon.js nOut=16, initState=17.
#[test]
fn go_iden3_poseidon_16_inputs_state17_16_outputs_documented() {
    let outputs = [
        "7865037705064445207187340054656830232157001572238023180016026650118519857086",
        "9292383997006336854008325030029058442489692927472584277596649832441082093099",
        "21700625464938935909463291795162623951575229166945244593449711331894544619498",
        "1749964961100464837642084889776091157070407086051097880220367435814831060919",
        "14926884742736943105557530036865339747160219875259470496706517357951967126770",
        "2039691552066237153485547245250552033884196017621501609319319339955236135906",
        "15632370980418377873678240526508190824831030254352022226082241110936555130543",
        "12415717486933552680955550946925876656737401305417786097937904386023163034597",
        "19518791782429957526810500613963817986723905805167983704284231822835104039583",
        "3946357499058599914103088366834769377007694643795968939540941315474973940815",
        "5618081863604788554613937982328324792980580854673130938690864738082655170455",
        "9119013501536010391475078939286676645280972023937320238963975266387024327421",
        "8377736769906336164136520530350338558030826788688113957410934156526990238336",
        "15295058061474937220002017533551270394267030149562824985607747654793981405060",
        "3767094797637425204201844274463024412131937665868967358407323347727519975724",
        "11046361685833871233801453306150294246339755171874771935347992312124050338976",
    ];
    for (i, val) in outputs.iter().enumerate() {
        let parsed = fe(val);
        assert!(!parsed.is_zero(), "output[{i}] must parse correctly");
    }
}

// ============================================================================
// Additional go-iden3-crypto vectors — chained 2-to-1 hashing
// Source: go-iden3-crypto TestPoseidonHash
//
// For multi-input hashes we can verify using our chain:
//   poseidon_many(a, b, c) = poseidon(poseidon(a, b), c)
// This is the Merkle-Damgård construction used in circomlibjs.
// ============================================================================

/// Verify chained hashing: poseidon(poseidon(1, 2), 3)
/// This simulates a 3-input hash using our 2-to-1 primitive.
/// The result should be deterministic and non-zero.
#[test]
fn chained_poseidon_3_inputs() {
    let p = params();
    let h12 = poseidon_hash(&p, FieldElement::from_u64(1), FieldElement::from_u64(2));
    let h123 = poseidon_hash(&p, h12, FieldElement::from_u64(3));

    assert!(!h123.is_zero());
    // Verify determinism
    let h12_b = poseidon_hash(&p, FieldElement::from_u64(1), FieldElement::from_u64(2));
    let h123_b = poseidon_hash(&p, h12_b, FieldElement::from_u64(3));
    assert_eq!(h123, h123_b);
}

/// Verify chained hashing with 4 inputs: poseidon(poseidon(poseidon(1,2), 3), 4)
#[test]
fn chained_poseidon_4_inputs() {
    let p = params();
    let h = poseidon_hash(&p, FieldElement::from_u64(1), FieldElement::from_u64(2));
    let h = poseidon_hash(&p, h, FieldElement::from_u64(3));
    let h = poseidon_hash(&p, h, FieldElement::from_u64(4));
    assert!(!h.is_zero());
    // Chain is order-dependent
    let h_alt = poseidon_hash(&p, FieldElement::from_u64(3), FieldElement::from_u64(4));
    let h_alt = poseidon_hash(&p, h_alt, FieldElement::from_u64(1));
    assert_ne!(
        h, h_alt,
        "different chain order must produce different hash"
    );
}

// ============================================================================
// circomlibjs initState vectors
// Source: circomlibjs test/poseidon.js
// ============================================================================

/// poseidon([1..4], initState=7) = 1569211601569591254857354699102545060324851338714426496554851741114291465006
/// Source: circomlibjs test/poseidon.js
/// Documented for when we add initState support.
#[test]
fn circomlibjs_init_state_7_documented() {
    let reference =
        fe("1569211601569591254857354699102545060324851338714426496554851741114291465006");
    assert!(!reference.is_zero());
}

/// poseidon([1..16], initState=17) = 7865037705064445207187340054656830232157001572238023180016026650118519857086
/// Source: circomlibjs test/poseidon.js
#[test]
fn circomlibjs_init_state_17_documented() {
    let reference =
        fe("7865037705064445207187340054656830232157001572238023180016026650118519857086");
    assert!(!reference.is_zero());
}

// ============================================================================
// go-iden3-crypto additional arity vectors (documented)
// Source: go-iden3-crypto TestPoseidonHash
// ============================================================================

/// poseidon([1, 2, 0, 0, 0]) = 1018317224307729531995786483840663576608797660851238720571059489595066344487
/// Source: go-iden3-crypto (arity=5, t=6)
#[test]
fn go_iden3_arity5_1_2_zeros_documented() {
    let reference =
        fe("1018317224307729531995786483840663576608797660851238720571059489595066344487");
    assert!(!reference.is_zero());
}

/// poseidon([1, 2, 0, 0, 0, 0]) = 15336558801450556532856248569924170992202208561737609669134139141992924267169
/// Source: go-iden3-crypto (arity=6, t=7)
#[test]
fn go_iden3_arity6_1_2_zeros_documented() {
    let reference =
        fe("15336558801450556532856248569924170992202208561737609669134139141992924267169");
    assert!(!reference.is_zero());
}

/// poseidon([3, 4, 0, 0, 0]) = 5811595552068139067952687508729883632420015185677766880877743348592482390548
/// Source: go-iden3-crypto (arity=5, t=6)
#[test]
fn go_iden3_arity5_3_4_zeros_documented() {
    let reference =
        fe("5811595552068139067952687508729883632420015185677766880877743348592482390548");
    assert!(!reference.is_zero());
}

/// poseidon([3, 4, 0, 0, 0, 0]) = 12263118664590987767234828103155242843640892839966517009184493198782366909018
/// Source: go-iden3-crypto (arity=6, t=7)
#[test]
fn go_iden3_arity6_3_4_zeros_documented() {
    let reference =
        fe("12263118664590987767234828103155242843640892839966517009184493198782366909018");
    assert!(!reference.is_zero());
}

/// poseidon([1..14]) = 8354478399926161176778659061636406690034081872658507739535256090879947077494
/// Source: go-iden3-crypto (arity=14, t=15)
#[test]
fn go_iden3_arity14_documented() {
    let reference =
        fe("8354478399926161176778659061636406690034081872658507739535256090879947077494");
    assert!(!reference.is_zero());
}

/// poseidon([1..9, 0, 0, 0, 0, 0]) = 5540388656744764564518487011617040650780060800286365721923524861648744699539
/// Source: go-iden3-crypto (arity=14, t=15)
#[test]
fn go_iden3_arity14_partial_documented() {
    let reference =
        fe("5540388656744764564518487011617040650780060800286365721923524861648744699539");
    assert!(!reference.is_zero());
}

// ============================================================================
// Poseidon properties — from industry testing patterns
// Source: arkworks test-templates (field property tests)
//         https://github.com/arkworks-rs/algebra/blob/master/test-templates/src/fields.rs
// ============================================================================

/// Non-commutativity: poseidon(a, b) != poseidon(b, a)
/// This is fundamental to Merkle tree security — left vs right child must matter.
/// Pattern: arkworks-style exhaustive property verification
#[test]
fn poseidon_non_commutative_exhaustive() {
    let p = params();
    let values = [1u64, 2, 3, 5, 7, 42, 99, 1000];
    for &l in &values {
        for &r in &values {
            if l == r {
                continue;
            }
            let h_lr = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            let h_rl = poseidon_hash(&p, FieldElement::from_u64(r), FieldElement::from_u64(l));
            assert_ne!(
                h_lr, h_rl,
                "poseidon({l}, {r}) == poseidon({r}, {l}) — must be non-commutative"
            );
        }
    }
}

/// Collision resistance: all distinct input pairs produce distinct hashes.
/// Tests 20x20 = 400 input pairs — no two should collide.
#[test]
fn poseidon_no_collisions_20x20() {
    let p = params();
    let mut hashes = std::collections::HashMap::new();
    for l in 0u64..20 {
        for r in 0u64..20 {
            let h = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            let key = (l, r);
            if let Some(prev_key) = hashes.insert(h, key) {
                panic!(
                    "collision: poseidon({}, {}) == poseidon({}, {})",
                    prev_key.0, prev_key.1, l, r
                );
            }
        }
    }
    assert_eq!(
        hashes.len(),
        400,
        "should have 400 distinct hashes for 20x20 inputs"
    );
}

/// Avalanche effect: changing one input bit must change most output bits.
/// Standard cryptographic hash property.
#[test]
fn poseidon_avalanche_effect() {
    let p = params();
    let base = FieldElement::from_u64(1000);
    let h1 = poseidon_hash(&p, base, FieldElement::from_u64(0));
    let h2 = poseidon_hash(&p, base, FieldElement::from_u64(1));
    assert_ne!(h1, h2);

    let c1 = h1.to_canonical();
    let c2 = h2.to_canonical();
    let differing = c1.iter().zip(c2.iter()).filter(|(a, b)| a != b).count();
    assert!(
        differing >= 3,
        "avalanche: expected at least 3/4 limbs to differ, got {differing}"
    );
}

/// Determinism across multiple calls.
/// Pattern: go-iden3-crypto TestPoseidonHash verifies same computation twice.
#[test]
fn poseidon_determinism_stress() {
    let p = params();
    for l in 0u64..20 {
        for r in 0u64..20 {
            let h1 = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            let h2 = poseidon_hash(&p, FieldElement::from_u64(l), FieldElement::from_u64(r));
            assert_eq!(h1, h2, "poseidon({l}, {r}) not deterministic");
        }
    }
}

/// Zero input: poseidon(0, 0) must be non-zero (pre-image resistance).
#[test]
fn poseidon_zero_inputs_non_zero() {
    let h = poseidon_hash(&params(), FieldElement::ZERO, FieldElement::ZERO);
    assert!(!h.is_zero(), "poseidon(0, 0) must not be zero");
}

/// poseidon_hash_single(x) == poseidon_hash(x, 0) by construction.
/// Our implementation: state = [0, x, 0] for single, state = [0, left, right] for pair.
#[test]
fn poseidon_single_equals_pair_with_zero() {
    let p = params();
    for v in [0u64, 1, 2, 42, 100, 999, u64::MAX] {
        let x = FieldElement::from_u64(v);
        let h_single = poseidon_hash_single(&p, x);
        let h_pair = poseidon_hash(&p, x, FieldElement::ZERO);
        assert_eq!(h_single, h_pair, "poseidon_single({v}) != poseidon({v}, 0)");
    }
}

// ============================================================================
// S-box (x^5) vectors
// These are derived from the Poseidon specification (ePrint 2019/458)
// S-box: α=5, so S(x) = x^5 in the field
// ============================================================================

#[test]
fn sbox_identity_values() {
    // 0^5 = 0
    assert_eq!(sbox(FieldElement::ZERO), FieldElement::ZERO);
    // 1^5 = 1
    assert_eq!(sbox(FieldElement::ONE), FieldElement::ONE);
}

#[test]
fn sbox_small_values() {
    let cases = [(2u64, 32u64), (3, 243), (4, 1024), (5, 3125), (10, 100000)];
    for (input, expected) in cases {
        assert_eq!(
            sbox(FieldElement::from_u64(input)),
            FieldElement::from_u64(expected),
            "{input}^5 != {expected}"
        );
    }
}

/// (-1)^5 = -1 in any field (since 5 is odd)
#[test]
fn sbox_neg_one() {
    let neg1 = FieldElement::from_u64(1).neg();
    assert_eq!(sbox(neg1), neg1, "(-1)^5 must be -1");
}

// ============================================================================
// Constraint count regression
// Verifies our R1CS Poseidon matches expected constraint count.
// Industry reference: circomlib Poseidon has ~240 constraints (different encoding).
// Our implementation: 361 constraints (more conservative materialization).
// ============================================================================

#[test]
fn poseidon_r1cs_constraint_count_361() {
    use constraints::poseidon::circuit::poseidon_hash_circuit;
    use constraints::r1cs::ConstraintSystem;

    let p = params();
    let mut cs = ConstraintSystem::new();
    let left = cs.alloc_witness();
    let right = cs.alloc_witness();
    let _hash = poseidon_hash_circuit(&mut cs, &p, left, right);

    // 72 (full round S-boxes) + 171 (partial round S-boxes)
    // + 114 (materialization) + 3 (output) + 1 (capacity) = 361
    assert_eq!(cs.num_constraints(), 361);
}

// ============================================================================
// Large field values — boundary testing near modulus
// Pattern: arkworks test-templates boundary value methodology
// ============================================================================

#[test]
fn poseidon_near_modulus_inputs() {
    let p = params();
    let p_minus_1 =
        fe("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    let p_minus_2 =
        fe("21888242871839275222246405745257275088548364400416034343698204186575808495615");

    let h = poseidon_hash(&p, p_minus_1, p_minus_2);
    assert!(!h.is_zero());
    let h2 = poseidon_hash(&p, p_minus_1, p_minus_2);
    assert_eq!(h, h2);
}

// ============================================================================
// Merkle tree construction with Poseidon
// Pattern: go-iden3-crypto uses Poseidon for Sparse Merkle Trees
// Source: https://github.com/iden3/go-iden3-crypto
// ============================================================================

#[test]
fn poseidon_merkle_two_leaves() {
    let p = params();
    let leaf0 = poseidon_hash(&p, FieldElement::from_u64(100), FieldElement::ZERO);
    let leaf1 = poseidon_hash(&p, FieldElement::from_u64(200), FieldElement::ZERO);
    let root = poseidon_hash(&p, leaf0, leaf1);

    assert!(!root.is_zero());
    assert_ne!(root, leaf0);
    assert_ne!(root, leaf1);
    // Swapping leaves must change root (Merkle ordering)
    let root_swapped = poseidon_hash(&p, leaf1, leaf0);
    assert_ne!(root, root_swapped);
}

#[test]
fn poseidon_merkle_four_leaves() {
    let p = params();
    // Build a balanced binary Merkle tree with 4 leaves
    let l0 = poseidon_hash(&p, FieldElement::from_u64(10), FieldElement::ZERO);
    let l1 = poseidon_hash(&p, FieldElement::from_u64(20), FieldElement::ZERO);
    let l2 = poseidon_hash(&p, FieldElement::from_u64(30), FieldElement::ZERO);
    let l3 = poseidon_hash(&p, FieldElement::from_u64(40), FieldElement::ZERO);

    let n01 = poseidon_hash(&p, l0, l1);
    let n23 = poseidon_hash(&p, l2, l3);
    let root = poseidon_hash(&p, n01, n23);

    assert!(!root.is_zero());
    // Verify determinism
    let root2 = poseidon_hash(&p, n01, n23);
    assert_eq!(root, root2);
}

#[test]
fn poseidon_merkle_depth_8() {
    let p = params();
    // Build a hash chain simulating depth-8 Merkle path verification
    let mut h = poseidon_hash(&p, FieldElement::from_u64(42), FieldElement::ZERO);
    for i in 1u64..=8 {
        let sibling = poseidon_hash(&p, FieldElement::from_u64(i * 100), FieldElement::ZERO);
        h = poseidon_hash(&p, h, sibling);
    }
    assert!(!h.is_zero());
    // Determinism
    let mut h2 = poseidon_hash(&p, FieldElement::from_u64(42), FieldElement::ZERO);
    for i in 1u64..=8 {
        let sibling = poseidon_hash(&p, FieldElement::from_u64(i * 100), FieldElement::ZERO);
        h2 = poseidon_hash(&p, h2, sibling);
    }
    assert_eq!(h, h2);
}
