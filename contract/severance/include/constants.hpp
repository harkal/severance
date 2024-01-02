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

#include <intx.h>

using namespace intx::literals;

const uint8_t MERKLE_HEIGHT = 31;

const intx::uint256 q =
  21888242871839275222246405745257275088548364400416034343698204186575808495617_u256;
const intx::uint256 qf =
  21888242871839275222246405745257275088696311157297823662689037894645226208583_u256;

const uint16_t PUBLIC = 3;

const intx::uint256 G2x1 =
  10857046999023057135944570762232829481370756359578518086990519993285655852781_u256;
const intx::uint256 G2x2 =
  11559732032986387107991004021392285783925812861821192530917403151452391805634_u256;
const intx::uint256 G2y1 =
  8495653923123431417604973247489272438418190587263600148770280649306958101930_u256;
const intx::uint256 G2y2 =
  4082367875863433681332203403145435568316851327593401208105741076214120093531_u256;
