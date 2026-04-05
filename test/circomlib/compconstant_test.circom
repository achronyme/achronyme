pragma circom 2.0.0;
include "circuits/compconstant.circom";
include "circuits/bitify.circom";

template TestCC() {
    signal input in;
    signal output out;
    
    component n2b = Num2Bits(254);
    n2b.in <== in;
    
    component cc = CompConstant(10944121435919637611123202872628637544274182200208017171849102093287904247808);
    for (var i = 0; i < 254; i++) {
        cc.in[i] <== n2b.out[i];
    }
    out <== cc.out;
}

component main {public [in]} = TestCC();
