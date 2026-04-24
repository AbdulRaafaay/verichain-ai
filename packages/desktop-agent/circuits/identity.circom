pragma circom 2.0.0;
include "circomlib/circuits/poseidon.circom";

template Identity() {
    signal input privateKey;
    signal input nonce;
    signal output publicKey;

    component pos = Poseidon(1);
    pos.inputs[0] <== privateKey;
    
    publicKey <== pos.out;
}

component main {public [nonce]} = Identity();
