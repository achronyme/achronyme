pragma circom 2.0.0;

include "circuits/mimcsponge.circom";

// MiMCSponge(2, 220, 1): 2 inputs, 220 rounds, 1 output
// This is the standard production configuration.
component main = MiMCSponge(2, 220, 1);
