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
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#include <eosio/eosio.hpp>
#include <intx.h>

typedef struct
{
    eosio::g1_point A;
    eosio::g1_point B;
    eosio::g1_point C;
    eosio::g1_point Z;
    eosio::g1_point T1;
    eosio::g1_point T2;
    eosio::g1_point T3;
    eosio::g1_point Wxi;
    eosio::g1_point Wxiw;
    intx::uint256 eval_a;
    intx::uint256 eval_b;
    intx::uint256 eval_c;
    intx::uint256 eval_s1;
    intx::uint256 eval_s2;
    intx::uint256 eval_zw;
    intx::uint256 eval_r;
} proof_t;

typedef struct
{
    intx::uint256 root_hash;
    eosio::checksum256 nullifier_hash;
    eosio::name recipient;
} public_inputs_t;

const eosio::g1_point
make_g1_point(const intx::uint256& x, const intx::uint256& y);
const eosio::g2_point
make_g2_point(const intx::uint256& x1,
              const intx::uint256& x2,
              const intx::uint256& y1,
              const intx::uint256& y2);
eosio::g1_point
parse_g1_point(const std::vector<char>& data, uint32_t idx);

bool
isValidProof(const proof_t& proof,
             std::vector<std::vector<char>>& public_inputs);