/*
 * Copyright (c) 2023 Harry Kalogirou
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

pragma circom 2.0.1;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/pedersen.circom";
include "../node_modules/circomlib/circuits/mimcsponge.circom";

template Hasher() {
    signal input nullifier;
    signal input secret;

    signal output nullifierHash;
    signal output commitment;

    component commitmentHasher = Pedersen(496);
    component nullifierHasher = Pedersen(248);
    component nullifierBits = Num2Bits(248);
    component secretBits = Num2Bits(248);
    nullifierBits.in <== nullifier;
    secretBits.in <== secret;

    for(var i = 0; i < 248; i++) {
        nullifierHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i] <== nullifierBits.out[i];
        commitmentHasher.in[i + 248] <== secretBits.out[i];
    }

    commitment <== commitmentHasher.out[0];
    nullifierHash <== nullifierHasher.out[0];
}

template Muxer() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}

template Withdraw(height) {
  signal input root;
  signal input nullifierHash;
  signal input recipient;
  
  signal input nullifier;
  signal input secret;
  signal input hashPairings[height];
  signal input hashDirections[height];

  component hasher = Hasher();
  hasher.nullifier <== nullifier;
  hasher.secret <== secret;
  hasher.nullifierHash === nullifierHash;

  // Merkle tree
  component hashers[height];
  component muxers[height];

  for(var i = 0 ; i < height; i++) {
    var hash = i == 0 ? hasher.commitment : hashers[i - 1].outs[0];

    muxers[i] = Muxer();
    muxers[i].in[0] <== hash;
    muxers[i].in[1] <== hashPairings[i];
    muxers[i].s <== hashDirections[i];

    hashers[i] = MiMCSponge(2, 8, 1);
    hashers[i].ins[0] <== muxers[i].out[0];
    hashers[i].ins[1] <== muxers[i].out[1];
    hashers[i].k <== hasher.commitment;
  }

  root === hashers[height - 1].outs[0];
  
  signal recipientSqr;
  recipientSqr <== recipient * recipient;
}

component main {public [root, nullifierHash, recipient]} = Withdraw(31);