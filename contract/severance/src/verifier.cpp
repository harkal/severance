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

#include <constants.hpp>
#include <eosio/crypto.hpp>
#include <eosio/crypto_ext.hpp>
#include <verifier.hpp>

using namespace intx;
using namespace eosio;

typedef struct int256_t
{
    uint256 value;
    bool is_negative;
} int256;

uint256
modinv(uint256 a, uint256 b)
{
    if (b <= 1)
        return 0;

    uint256 b0 = b;
    int256 x0 = { 0, false };
    int256 x1 = { 1, false };

    while (a > 1) {
        if (b == 0)
            return 0;
        auto sd = sdivrem(a, b);
        uint256 q = sd.quot;
        uint256 t = b;
        b = sd.rem;
        a = t;

        int256 t2 = x0;
        uint256 qx0 = q * x0.value;
        if (x0.is_negative != x1.is_negative) {
            x0.value = x1.value + qx0;
            x0.is_negative = x1.is_negative;
        } else {
            x0.value = (x1.value > qx0) ? x1.value - qx0 : qx0 - x1.value;
            x0.is_negative =
              (x1.value > qx0) ? x1.is_negative : !x0.is_negative;
        }
        x1 = t2;
    }

    return x1.is_negative ? (b0 - x1.value) : x1.value;
}

const g1_point
make_g1_point(const uint256& x, const uint256& y)
{
    std::vector<char> _x(32);
    std::vector<char> _y(32);

    be::unsafe::store((uint8_t*)_x.data(), x);
    be::unsafe::store((uint8_t*)_y.data(), y);

    return eosio::g1_point{ _x, _y };
}

const g2_point
make_g2_point(const uint256& x1,
              const uint256& x2,
              const uint256& y1,
              const uint256& y2)
{
    std::vector<char> _x(64);
    std::vector<char> _y(64);

    be::unsafe::store((uint8_t*)_x.data(), x2);
    be::unsafe::store((uint8_t*)(_x.data() + 32), x1);
    be::unsafe::store((uint8_t*)_y.data(), y2);
    be::unsafe::store((uint8_t*)(_y.data() + 32), y1);

    return eosio::g2_point{ _x, _y };
}

g1_point
g1_mul(const g1_point& p, const uint256& s)
{
    std::vector<char> _s(32);
    be::unsafe::store((uint8_t*)_s.data(), s);

    return eosio::alt_bn128_mul(p, _s);
}

inline g1_point
g1_add(const g1_point& a, const g1_point& b)
{
    return eosio::alt_bn128_add(a, b);
}

typedef struct
{
    uint256 beta;
    uint256 gamma;
    uint256 alpha;
    uint256 xi;
    uint256 v[6];
    uint256 u;

    uint256 xin;
    uint256 zh;
} challenges_t;

#include <verification_key.hpp>

const eosio::g1_point G1 = make_g1_point(1, 2);
const eosio::g2_point G2 = make_g2_point(G2x1, G2x2, G2y1, G2y2);

inline g1_point
g1_sub(g1_point& a, g1_point& b)
{
    std::vector<char> _s(32);

    uint256 _y = be::unsafe::load<uint256>((uint8_t*)b.y.data());
    be::unsafe::store((uint8_t*)_s.data(), (qf - _y) % qf);

    g1_point _b(b.x, _s);
    return eosio::alt_bn128_add(a, _b);
}

inline g1_point
g1_neg(g1_point& a)
{
    std::vector<char> _s(32);

    uint256 _y = be::unsafe::load<uint256>((uint8_t*)a.y.data());
    be::unsafe::store((uint8_t*)_s.data(), (qf - _y) % qf);

    g1_point _b(a.x, _s);
    return _b;
}

void
printCharArrayAsHex(const char* charArray, size_t size)
{
    const char* hexDigits = "0123456789abcdef";

    for (size_t i = 0; i < size; ++i) {
        unsigned char byte = (unsigned char)charArray[i];
        char hex[3];
        hex[0] = hexDigits[byte >> 4];
        hex[1] = hexDigits[byte & 0x0F];
        hex[2] = '\0';
        print(hex);
        // print(hex, " ");
        // if (i % 32 == 31)
        //    print("\n");
    }
    print("\n");
}

eosio::g1_point
parse_g1_point(const std::vector<char>& data, uint32_t idx)
{
    std::vector<char> x(32);
    std::vector<char> y(32);
    for (int i = 0; i < 32; ++i) {
        x[i] = data[idx + i];
        y[i] = data[idx + 32 + i];
    }
    return eosio::g1_point(x, y);
}

template<typename T>
uint256
hash_to_Fr(const T* data, uint32_t size)
{
    auto checksum = eosio::keccak((const char*)data, size);
    uint256 keccak = be::unsafe::load<uint256>(
      (const uint8_t*)checksum.extract_as_byte_array().data());
    return keccak % q;
}

template<typename T>
uint256
hash_to_Fr(const std::vector<T>& data)
{
    return hash_to_Fr(data.data(), data.size());
}

inline void
insert_to_buffer(std::vector<uint8_t>& buffer, const eosio::g1_point& point)
{
    auto p = point.serialized();
    buffer.insert(buffer.end(), p.begin(), p.end());
}

inline void
insert_to_buffer(std::vector<uint8_t>& buffer, const uint256& x)
{
    uint8_t b[32];
    be::store<uint256>(b, x);
    buffer.insert(buffer.end(), b, b + 32);
}

void
calculate_challenges(const proof_t& proof,
                     const std::vector<std::vector<char>>& public_inputs,
                     challenges_t& ch)
{
    std::vector<uint8_t> buffer;
    buffer.reserve(32 * public_inputs.size());
    for (auto input : public_inputs) {
        buffer.insert(buffer.end(), input.begin(), input.end());
    }

    insert_to_buffer(buffer, proof.A);
    insert_to_buffer(buffer, proof.B);
    insert_to_buffer(buffer, proof.C);
    ch.beta = hash_to_Fr(buffer);

    uint8_t b[32];
    be::store<uint256>(b, ch.beta);
    ch.gamma = hash_to_Fr(b, 32);
    ch.alpha = hash_to_Fr(proof.Z.serialized());

    buffer.clear();
    insert_to_buffer(buffer, proof.T1);
    insert_to_buffer(buffer, proof.T2);
    insert_to_buffer(buffer, proof.T3);
    ch.xi = hash_to_Fr(buffer);

    buffer.clear();
    insert_to_buffer(buffer, proof.eval_a);
    insert_to_buffer(buffer, proof.eval_b);
    insert_to_buffer(buffer, proof.eval_c);
    insert_to_buffer(buffer, proof.eval_s1);
    insert_to_buffer(buffer, proof.eval_s2);
    insert_to_buffer(buffer, proof.eval_zw);
    insert_to_buffer(buffer, proof.eval_r);
    ch.v[0] = hash_to_Fr(buffer);
    for (int i = 1; i < 6; ++i) {
        ch.v[i] = mulmod(ch.v[i - 1], ch.v[0], q);
    }

    buffer.clear();
    insert_to_buffer(buffer, proof.Wxi);
    insert_to_buffer(buffer, proof.Wxiw);
    ch.u = hash_to_Fr(buffer);
}

std::vector<uint256>
calculate_lagrange_evaluations(challenges_t& ch, int public_inputs_size)
{
    uint256 xin = ch.xi;
    uint32_t domain_size = 1;
    for (int i = 0; i < POWER; ++i) {
        domain_size *= 2;
        xin = mulmod(xin, xin, q);
    }
    ch.xin = xin;
    ch.zh = (xin - 1 + q) % q;

    std::vector<uint256> L;
    uint256 w = 1;
    uint256 n = domain_size;
    for (int i = 0; i < std::max(1, public_inputs_size); ++i) {
        uint256 f0 = mulmod(w, ch.zh, q);
        uint256 f1 = mulmod(n, (ch.xi - w + q) % q, q);
        uint256 inv = modinv(f1, q);
        uint256 l = mulmod(f0, inv, q);
        L.push_back(l);
        w = mulmod(w, w1, q);
    }
    return L;
}

uint256
calculate_pl(const std::vector<std::vector<char>>& public_inputs,
             const std::vector<uint256>& L)
{
    uint256 pl = 0;
    for (int i = 0; i < public_inputs.size(); ++i) {
        const uint256 w =
          be::unsafe::load<uint256>((const uint8_t*)public_inputs[i].data());
        pl = (pl - mulmod(w, L[i], q) + q) % q;
    }

    return pl;
}

uint256
calculate_t(const proof_t& proof,
            const challenges_t& ch,
            uint256 pl,
            uint256 l0)
{
    uint256 num = proof.eval_r;
    num = num + pl;

    uint256 e1 = proof.eval_a;
    e1 = e1 + mulmod(ch.beta, proof.eval_s1, q);
    e1 = (e1 + ch.gamma) % q;

    uint256 e2 = proof.eval_b;
    e2 = e2 + mulmod(ch.beta, proof.eval_s2, q);
    e2 = (e2 + ch.gamma) % q;

    uint256 e3 = proof.eval_c;
    e3 = (e3 + ch.gamma) % q;

    uint256 e = mulmod(mulmod(e1, e2, q), e3, q);
    e = mulmod(e, proof.eval_zw, q);
    e = mulmod(e, ch.alpha, q);

    num = (num - e + q) % q;
    num = (num - mulmod(l0, mulmod(ch.alpha, ch.alpha, q), q) + q) % q;

    return mulmod(num, modinv(ch.zh, q), q);
}

eosio::g1_point
calculate_D(const proof_t& proof, const challenges_t& ch, uint256 l0)
{
    eosio::bigint buf(32);

    uint256 s1 = mulmod(mulmod(proof.eval_a, proof.eval_b, q), ch.v[0], q);

    auto res = g1_mul(Qm, s1);

    const uint256 s2 = mulmod(proof.eval_a, ch.v[0], q);
    res = g1_add(res, g1_mul(Ql, s2));

    const uint256 s3 = mulmod(proof.eval_b, ch.v[0], q);
    res = g1_add(res, g1_mul(Qr, s3));

    const uint256 s4 = mulmod(proof.eval_c, ch.v[0], q);
    res = g1_add(res, g1_mul(Qo, s4));

    res = g1_add(res, g1_mul(Qc, ch.v[0]));

    const uint256 beta_xi = mulmod(ch.beta, ch.xi, q);
    const uint256 s6a = addmod(addmod(proof.eval_a, beta_xi, q), ch.gamma, q);
    const uint256 s6b =
      addmod(addmod(proof.eval_b, mulmod(beta_xi, k1, q), q), ch.gamma, q);
    const uint256 s6c =
      addmod(addmod(proof.eval_c, mulmod(beta_xi, k2, q), q), ch.gamma, q);
    const uint256 s6d =
      mulmod(mulmod(l0, mulmod(ch.alpha, ch.alpha, q), q), ch.v[0], q);

    uint256 s6 = mulmod(
      mulmod(s6a, mulmod(s6b, s6c, q), q), mulmod(ch.alpha, ch.v[0], q), q);
    s6 = addmod(s6, s6d, q);
    s6 = addmod(s6, ch.u, q);

    res = g1_add(res, g1_mul(proof.Z, s6));

    const uint256 s7a = addmod(
      addmod(proof.eval_a, mulmod(ch.beta, proof.eval_s1, q), q), ch.gamma, q);
    const uint256 s7b = addmod(
      addmod(proof.eval_b, mulmod(ch.beta, proof.eval_s2, q), q), ch.gamma, q);

    uint256 s7 = mulmod(s7a, s7b, q);
    s7 = mulmod(s7, ch.alpha, q);
    s7 = mulmod(s7, ch.v[0], q);
    s7 = mulmod(s7, ch.beta, q);
    s7 = mulmod(s7, proof.eval_zw, q);
    auto S3s7 = g1_mul(S3, s7);
    res = g1_add(res, g1_neg(S3s7));

    return res;
}

eosio::g1_point
calculate_F(const proof_t& proof, const challenges_t& ch, eosio::g1_point D)
{
    auto res = proof.T1;

    res = g1_add(res, g1_mul(proof.T2, ch.xin));
    res = g1_add(res, g1_mul(proof.T3, mulmod(ch.xin, ch.xin, q)));
    res = g1_add(res, D);
    res = g1_add(res, g1_mul(proof.A, ch.v[1]));
    res = g1_add(res, g1_mul(proof.B, ch.v[2]));
    res = g1_add(res, g1_mul(proof.C, ch.v[3]));
    res = g1_add(res, g1_mul(S1, ch.v[4]));
    res = g1_add(res, g1_mul(S2, ch.v[5]));

    return res;
}

eosio::g1_point
calculate_e(const proof_t& proof, const challenges_t& ch, uint256 t)
{
    auto s = t;

    s = addmod(s, mulmod(ch.v[0], proof.eval_r, q), q);
    s = addmod(s, mulmod(ch.v[1], proof.eval_a, q), q);
    s = addmod(s, mulmod(ch.v[2], proof.eval_b, q), q);
    s = addmod(s, mulmod(ch.v[3], proof.eval_c, q), q);
    s = addmod(s, mulmod(ch.v[4], proof.eval_s1, q), q);
    s = addmod(s, mulmod(ch.v[5], proof.eval_s2, q), q);
    s = addmod(s, mulmod(ch.u, proof.eval_zw, q), q);

    auto res = g1_mul(G1, s);

    return res;
}

bool
isValidPairing(const proof_t& proof,
               const challenges_t& ch,
               eosio::g1_point& E,
               const eosio::g1_point& F)
{
    auto A1 = g1_add(proof.Wxi, g1_mul(proof.Wxiw, ch.u));

    auto B1 = g1_mul(proof.Wxi, ch.xi);
    auto s = mulmod(mulmod(ch.u, ch.xi, q), w1, q);
    B1 = g1_add(B1, g1_mul(proof.Wxiw, s));
    B1 = g1_add(B1, F);
    B1 = g1_add(B1, g1_neg(E));

    std::vector<std::pair<eosio::g1_point, eosio::g2_point>> pairs;
    pairs.push_back(std::make_pair(g1_neg(A1), X2));
    pairs.push_back(std::make_pair(B1, G2));

    return eosio::alt_bn128_pair(pairs) == 0;
}

bool
isValidProof(const proof_t& proof,
             std::vector<std::vector<char>>& public_inputs)
{
    challenges_t challenges;
    calculate_challenges(proof, public_inputs, challenges);
    const auto L =
      calculate_lagrange_evaluations(challenges, public_inputs.size());
    uint256 pl = calculate_pl(public_inputs, L);
    uint256 t = calculate_t(proof, challenges, pl, L[0]);
    eosio::g1_point D = calculate_D(proof, challenges, L[0]);
    eosio::g1_point F = calculate_F(proof, challenges, D);
    eosio::g1_point E = calculate_e(proof, challenges, t);

    return isValidPairing(proof, challenges, E, F);
}
