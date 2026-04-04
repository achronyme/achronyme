pragma circom 2.0.0;

include "./circuits/poseidon.circom";

component main {public [inputs]} = Poseidon(2);
