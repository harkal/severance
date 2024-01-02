# Severance Smart Contract

Severance is a privacy contract for EOS powered blockchains that was build to prove the
implementation feasibility of a zkSNARKs system running entirely on-chain, writen in C++.

The system implements zero knownledge proofs verifier utilizing zkSNARKS to provide
anonymization services to any token on [EOS/Antelope](https://antelope.io/) blockchains.
In this repo you can find all the verifier code along with specific circuits for the
token implementation.

The code implements the [PLONK](https://eprint.iacr.org/2019/953)
protocol, that requires no special trusted setup. This is the main reason that it was
selected over the more simple and less CPU intensive Groth16 that requires a separate
trusted setup for each circuit.

The contract was compiled with cdt-4.0.0-1 and is deployed at
[pboxpboxpbox](https://bloks.io/account/pboxpboxpbox) on the EOS mainnet.

## Table of Contents

- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Usage

You can use the code in parts or as a whole according to the license agreement below.

## Contributing

Create PRs on this repository

## License

Copyright (c) 2023 Harry Kalogirou

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
