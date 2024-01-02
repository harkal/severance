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

#include <intx.h>

#include <algorithm>
#include <constants.hpp>
#include <eosio/asset.hpp>
#include <eosio/crypto.hpp>
#include <eosio/crypto_ext.hpp>
#include <eosio/system.hpp>
#include <mimcsponge.hpp>
#include <severance.hpp>
#include <utils.hpp>
#include <verifier.hpp>

using namespace intx;

const symbol PEOS_TOKEN = symbol("PEOS", 4);
const name CONTRACT_SCOPE = "main"_n;

typedef struct
{
    symbol symbol;
    name contract;
    uint64_t quantity_min;
    uint64_t quantity_max;
    uint64_t quantity_step;
} token_info_t;

const token_info_t supported_tokens[] = { { .symbol = PEOS_TOKEN,
                                            .contract = "thepeostoken"_n,
                                            .quantity_min = 1000,
                                            .quantity_max = 1000000000,
                                            .quantity_step = 10 },
                                          { .symbol = symbol("EOS", 4),
                                            .contract = "eosio.token"_n,
                                            .quantity_min = 100000,
                                            .quantity_max = 10000000000,
                                            .quantity_step = 10 } };

static const token_info_t&
get_token_info(const symbol& symbol)
{
    for (const auto& token : supported_tokens) {
        if (token.symbol == symbol) {
            return token;
        }
    }
    check(false, "Unsupported token");
    __builtin_unreachable();
}

static int8_t
get_quantity_step(const token_info_t& token, const asset& quantity)
{
    uint64_t quantity_step = token.quantity_min;
    uint8_t count = -1;
    while (quantity_step <= token.quantity_max &&
           quantity_step <= quantity.amount) {
        quantity_step *= token.quantity_step;
        count++;
    }
    check(count >= 0, "invalid quantity");
    return count;
}

static uint64_t
get_quantity_scope(const asset& quantity)
{
    const auto& token = get_token_info(quantity.symbol);
    const uint8_t quantity_step = get_quantity_step(token, quantity);
    return token.symbol.precision() | token.symbol.code().raw() << 8 |
           (uint64_t)quantity_step << 56;
}

static uint64_t
get_token_scope_ext(const asset& quantity)
{
    const auto& token = get_token_info(quantity.symbol);
    return token.symbol.precision() | token.symbol.code().raw() << 8;
}

uint64_t
severance::calculate_fees(const severance::globalstateext* global_state_ext,
                          asset& quantity)
{
    uint32_t fees =
      global_state_ext->fee_rate * quantity.amount / (10000 * 100);
    return global_state_ext->oracle_rate * fees / 1000000;
}

static proof_t
parse_proof(const std::vector<char>& proof_data)
{
    const uint8_t* proof_data_ptr = (const uint8_t*)proof_data.data();
    return proof_t{
        .A = parse_g1_point(proof_data, 0),
        .B = parse_g1_point(proof_data, 64),
        .C = parse_g1_point(proof_data, 128),
        .Z = parse_g1_point(proof_data, 192),
        .T1 = parse_g1_point(proof_data, 256),
        .T2 = parse_g1_point(proof_data, 320),
        .T3 = parse_g1_point(proof_data, 384),
        .Wxi = parse_g1_point(proof_data, 448),
        .Wxiw = parse_g1_point(proof_data, 512),
        .eval_a = be::unsafe::load<uint256>(proof_data_ptr + 576),
        .eval_b = be::unsafe::load<uint256>(proof_data_ptr + 608),
        .eval_c = be::unsafe::load<uint256>(proof_data_ptr + 640),
        .eval_s1 = be::unsafe::load<uint256>(proof_data_ptr + 672),
        .eval_s2 = be::unsafe::load<uint256>(proof_data_ptr + 704),
        .eval_zw = be::unsafe::load<uint256>(proof_data_ptr + 736),
        .eval_r = be::unsafe::load<uint256>(proof_data_ptr + 768),
    };
}

static public_inputs_t
parse_public_inputs(const std::vector<std::vector<char>>& public_inputs)
{
    checksum256 nullifier_hash;
    unpack(nullifier_hash, public_inputs[1].data(), public_inputs[1].size());
    return public_inputs_t{
        .root_hash = be::unsafe::load<uint256>((uint8_t*)&public_inputs[0]),
        .nullifier_hash = nullifier_hash,
        .recipient = name{ (uint64_t)be::unsafe::load<uint256>(
          (uint8_t*)&public_inputs[2][0]) },
    };
}

[[eosio::action]] void
severance::setrate(asset quantity, asset fees, uint32_t fee_rate)
{
    require_auth(get_self());

    const auto& token = get_token_info(quantity.symbol);
    check(quantity.is_valid(), "invalid quantity");
    check(quantity.amount > 0, "bad quantity");
    check(fees.is_valid(), "invalid fees");
    check(fees.amount > 0, "bad fees");

    // Just to initialize the global state
    const uint64_t quantity_scope = get_quantity_scope(quantity);
    auto global_state = get_global_state(quantity_scope);

    const uint64_t token_scope = get_token_scope_ext(quantity);
    auto global_state_ext = get_global_state_ext(token_scope);
    global_state_ext->oracle_rate = (1000000 * fees.amount) / quantity.amount;
    global_state_ext->fee_rate = fee_rate;
    global_state_ext->oracle_timestamp = eosio::current_time_point();

    set_global_state_ext(token_scope, *global_state_ext);
}

[[eosio::on_notify("*::transfer")]] void
severance::transfer(name owner,
                    name to,
                    eosio::asset quantity,
                    std::string memo)
{
    if (owner == get_self() || to != get_self()) {
        return;
    }

    const auto& token = get_token_info(quantity.symbol);
    check(get_first_receiver() == token.contract ||
            quantity.symbol == PEOS_TOKEN,
          "wrong token contract");
    check(quantity.is_valid(), "invalid quantity");
    check(quantity.amount > 0, "bad amount");

    auto global_fee = get_global_fee();
    if (global_fee.active_deposit == false) {
        global_fee.active_deposit = true;
        global_fee.depositor = owner;
        global_fee.quantity = quantity;
    } else {
        if (quantity.symbol == PEOS_TOKEN) {
            if (global_fee.quantity.symbol == PEOS_TOKEN &&
                global_fee.quantity.amount < 0) {
                global_fee.quantity = quantity;
            } else {
                global_fee.fees = quantity;
            }
        } else {
            global_fee.quantity = quantity;
        }
    }
    set_global_fee(global_fee);
}

[[eosio::action]] void
severance::deposit(name owner,
                   asset quantity,
                   std::vector<char>& commitment_data)
{
    require_auth(owner);
    auto global_fee = get_global_fee();
    const uint64_t quantity_scope = get_quantity_scope(quantity);
    auto global_state = get_global_state(quantity_scope);
    auto global_state_ext = get_global_state_ext(quantity_scope);
    check(global_fee.active_deposit, "no active deposit");
    check(global_fee.depositor == owner, "wrong depositor");
    check(global_fee.quantity == quantity, "wrong quantity");

    const uint64_t required_fees = calculate_fees(global_state_ext, quantity);

    check(global_fee.fees.amount >= required_fees, "not enough fees");

    checksum256 commitment_hash;
    unpack(commitment_hash, commitment_data.data(), commitment_data.size());

    commitment_t commitments_table(get_self(), quantity_scope);
    auto idx = commitments_table.get_index<"hash"_n>();
#if 1
    check(idx.find(commitment_hash) == idx.end(), "commitment already exists");
#endif

    commitments_table.emplace(owner, [&](auto& row) {
        row.id = commitments_table.available_primary_key();
        row.hash = commitment_hash;
    });

    uint256 commitment =
      be::unsafe::load<uint256>((uint8_t*)commitment_data.data());

    uint256 left, right;
    uint256 current_hash = commitment;
    uint32_t current_index = global_state->next_leaf_index;
    uint8_t hash_directions[MERKLE_HEIGHT];
    uint256 hash_pairs[MERKLE_HEIGHT];

    for (int i = 0; i < MERKLE_HEIGHT; i++) {

        if (current_index % 2 == 0) {
            left = current_hash;
            right = level_defaults[i];
            hash_pairs[i] = right;
            hash_directions[i] = 0;
        } else {
            left = get_last_level_hash(quantity_scope, i);
            right = current_hash;
            hash_pairs[i] = left;
            hash_directions[i] = 1;
        }

        set_last_level_hash(quantity_scope, i, current_hash);

        current_hash = MiMC5Sponge::MiMC5Sponge(left, right, commitment);
        current_index /= 2;
    }

    roothash_t roothashes_table(get_self(), quantity_scope);
    roothashes_table.emplace(owner, [&](auto& row) {
        row.id = roothashes_table.available_primary_key();
        le::unsafe::store<uint256>((uint8_t*)row.root_hash.data(),
                                   current_hash);
        uint128_t t = *(uint128_t*)row.root_hash.data();
        *(uint128_t*)row.root_hash.data() =
          *(uint128_t*)(row.root_hash.data() + 1);
        *(uint128_t*)(row.root_hash.data() + 1) = t;
    });

    global_state->next_leaf_index++;
    set_global_state(quantity_scope, *global_state);

    global_fee.active_deposit = false;
    global_fee.accumulated_fees.amount += global_fee.fees.amount;
    global_fee.fees = asset(0, symbol("PEOS", 4));
    global_fee.quantity.amount = 0;
    set_global_fee(global_fee);
}

[[eosio::action]] void
severance::withdraw(std::vector<char>& proof_data,
                    std::vector<std::vector<char>>& public_inputs,
                    name owner,
                    name to,
                    eosio::asset quantity,
                    std::string memo)
{
    require_auth(owner);

    const auto& token = get_token_info(quantity.symbol);
    check(quantity.is_valid(), "invalid quantity");
    check(quantity.amount > 0, "bad amount");
    check(memo.size() < 256, "memo size too big");

    const uint64_t quantity_scope = get_quantity_scope(quantity);
    roothash_t roothashes_table(get_self(), quantity_scope);
    auto roothashes_idx = roothashes_table.get_index<"hash"_n>();
    checksum256 root_hash; // = public_inputs[0];
    root_hash = unpack<checksum256>(public_inputs[0]);

    check(roothashes_idx.find(root_hash) != roothashes_idx.end(),
          "root hash not found");

    const auto proof = parse_proof(proof_data);

    check(isValidProof(proof, public_inputs), "Invalid proof");

    auto inputs = parse_public_inputs(public_inputs);
    check(inputs.recipient == to, "wrong recipient");

    nullifier_t nullifiers_table(get_self(), quantity_scope);
    auto idx = nullifiers_table.get_index<"hash"_n>();
    check(idx.find(inputs.nullifier_hash) == idx.end(), "already cashed out");

    nullifiers_table.emplace(owner, [&](auto& row) {
        row.id = nullifiers_table.available_primary_key();
        row.hash = inputs.nullifier_hash;
    });

    action{
        permission_level{ get_self(), "active"_n },
        token.contract,
        "transfer"_n,
        std::make_tuple(get_self(), to, quantity, memo),
    }
      .send();
}

#ifdef ALLOW_RESET
ACTION
severance::reset(name scope)
{
    require_auth(get_self());

    commitment_t commitments_table(get_self(), scope.value);
    auto iter = commitments_table.begin();
    while (iter != commitments_table.end()) {
        commitments_table.erase(iter);
        iter = commitments_table.begin();
    }

    global_states_t global_state_table(get_self(), scope.value);
    if (global_state_table.begin() != global_state_table.end()) {
        global_state_table.erase(global_state_table.begin());
    }

    global_states_ext_t global_state_ext_table(
      get_self(), scope.value & 0x00ffffffffffffff);
    if (global_state_ext_table.begin() != global_state_ext_table.end()) {
        global_state_ext_table.erase(global_state_ext_table.begin());
    }

    global_fee_t global_fee_table(get_self(), CONTRACT_SCOPE.value);
    if (global_fee_table.begin() != global_fee_table.end()) {
        global_fee_table.erase(global_fee_table.begin());
    }

    roothash_t roothash_table(get_self(), scope.value);
    auto iter3 = roothash_table.begin();
    while (iter3 != roothash_table.end()) {
        roothash_table.erase(iter3);
        iter3 = roothash_table.begin();
    }
}
#endif

severance::globalstate*
severance::get_global_state(uint64_t scope)
{
    if (global_state_cache) {
        return global_state_cache;
    }
    global_states_t global_state_table(get_self(), scope);
    if (global_state_table.begin() == global_state_table.end()) {
        global_state_table.emplace(get_self(), [&](auto& row) {
            row.id = 0;
            row.next_leaf_index = 0;
            row.last_level_hashes = std::vector<char>(MERKLE_HEIGHT * 32, 0);
        });
    }
    global_state_cache = new globalstate();
    *global_state_cache = *(global_state_table.begin());
    return global_state_cache;
}

void
severance::set_global_state(uint64_t scope, const severance::globalstate& gs)
{
    global_states_t global_state_table(get_self(), scope);
    global_state_table.modify(
      global_state_table.begin(), get_self(), [&](auto& row) { row = gs; });
}

severance::globalfee
severance::get_global_fee()
{
    global_fee_t global_fee_table(get_self(), CONTRACT_SCOPE.value);
    if (global_fee_table.begin() == global_fee_table.end()) {
        global_fee_table.emplace(get_self(), [&](auto& row) {
            row.id = 0;
            row.fees = asset(0, symbol("PEOS", 4));
            row.accumulated_fees = asset(0, symbol("PEOS", 4));
        });
    }

    return *(global_fee_table.begin());
}

void
severance::set_global_fee(const severance::globalfee& gf)
{
    global_fee_t global_fee_table(get_self(), CONTRACT_SCOPE.value);
    global_fee_table.modify(
      global_fee_table.begin(), get_self(), [&](auto& row) { row = gf; });
}

severance::globalstateext*
severance::get_global_state_ext(uint64_t scope)
{
    if (global_state_ext_cache) {
        return global_state_ext_cache;
    }
    scope &= 0x00ffffffffffffff;
    global_states_ext_t global_state_table_ext(get_self(), scope);
    if (global_state_table_ext.begin() == global_state_table_ext.end()) {
        global_state_table_ext.emplace(get_self(), [&](auto& row) {
            row.id = 0;
            row.oracle_rate = 0;
            row.fee_rate = 0;
            row.oracle_timestamp = eosio::time_point();
        });
    }
    global_state_ext_cache = new globalstateext();
    *global_state_ext_cache = *(global_state_table_ext.begin());
    return global_state_ext_cache;
}

void
severance::set_global_state_ext(uint64_t scope,
                                const severance::globalstateext& gs)
{
    scope &= 0x00ffffffffffffff;
    global_states_ext_t global_state_table_ext(get_self(), scope);
    global_state_table_ext.modify(
      global_state_table_ext.begin(), get_self(), [&](auto& row) { row = gs; });
}

uint256
severance::get_last_level_hash(uint64_t scope, int level)
{
    auto global_state = get_global_state(scope);

    return be::unsafe::load<uint256>(
      (const uint8_t*)global_state->last_level_hashes.data() + level * 32);
}

void
severance::set_last_level_hash(uint64_t scope, int level, uint256 hash)
{
    auto global_state = get_global_state(scope);

    be::unsafe::store<uint256>(
      (uint8_t*)global_state->last_level_hashes.data() + level * 32, hash);
}
