pragma circom 2.0.0;

include "circuits/smt/smtverifier.circom";

// 10 levels ≈ 1024 leaves, representative SMT size for identity claims.
component main = SMTVerifier(10);
