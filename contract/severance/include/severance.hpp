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

using namespace eosio;
using namespace intx::literals;

// #define ALLOW_RESET

CONTRACT severance : public contract
{
  private:
  public:
    using contract::contract;

    [[eosio::action]] void setrate(
      asset quantity, asset fees, uint32_t fee_rate);

    [[eosio::on_notify("*::transfer")]] void transfer(
      name owner, name to, asset quantity, std::string memo);

    [[eosio::action]] void deposit(
      name owner, asset quantity, std::vector<char> & commitment_data);
    [[eosio::action]] void withdraw(std::vector<char> & proof_data,
                                    std::vector<std::vector<char>> &
                                      public_inputs,
                                    name owner,
                                    name to,
                                    eosio::asset quantity,
                                    std::string memo);

#ifdef ALLOW_RESET
    ACTION reset(name scope);
#endif

  private:
    struct [[eosio::table]] commitment
    {
        uint64_t id;
        checksum256 hash;
        uint64_t primary_key() const { return id; }
        checksum256 by_hash() const { return hash; }
    };

    struct [[eosio::table]] nullifier
    {
        uint64_t id;
        checksum256 hash;
        uint64_t primary_key() const { return id; }
        checksum256 by_hash() const { return hash; }
    };

    struct [[eosio::table]] roothash
    {
        uint64_t id;
        checksum256 root_hash;

        uint64_t primary_key() const { return id; }
        checksum256 by_hash() const { return root_hash; }
    };

    struct [[eosio::table]] globalstate
    {
        uint64_t id;
        uint32_t next_leaf_index;
        std::vector<char> last_level_hashes;
        bool active_deposit;
        name depositor;
        asset quantity;

        uint64_t primary_key() const { return id; }
    };

    struct [[eosio::table]] globalstateext
    {
        uint64_t id;
        uint32_t oracle_rate;
        uint32_t fee_rate; // 1% = 10000
        eosio::time_point oracle_timestamp;

        uint64_t primary_key() const { return id; }
    };

    struct [[eosio::table]] globalfee
    {
        uint64_t id;
        bool active_deposit;
        name depositor;
        asset quantity;
        asset fees;
        asset accumulated_fees;

        uint64_t primary_key() const { return id; }
    };

    typedef eosio::multi_index<
      "commitment"_n,
      commitment,
      indexed_by<"hash"_n,
                 const_mem_fun<commitment, checksum256, &commitment::by_hash>>>
      commitment_t;
    typedef eosio::multi_index<
      "nullifier"_n,
      nullifier,
      indexed_by<"hash"_n,
                 const_mem_fun<nullifier, checksum256, &nullifier::by_hash>>>
      nullifier_t;

    typedef eosio::multi_index<
      "roothash"_n,
      roothash,
      indexed_by<"hash"_n,
                 const_mem_fun<roothash, checksum256, &roothash::by_hash>>>
      roothash_t;

    typedef eosio::multi_index<"globalstate"_n, globalstate> global_states_t;
    typedef eosio::multi_index<"globalstatee"_n, globalstateext>
      global_states_ext_t;
    typedef eosio::multi_index<"globalfee"_n, globalfee> global_fee_t;

    severance::globalstate* get_global_state(uint64_t scope);
    void set_global_state(uint64_t scope, const globalstate& gs);
    severance::globalstate* global_state_cache = nullptr;

    severance::globalstateext* get_global_state_ext(uint64_t scope);
    void set_global_state_ext(uint64_t scope,
                              const severance::globalstateext& gs);
    severance::globalstateext* global_state_ext_cache = nullptr;

    severance::globalfee get_global_fee();
    void set_global_fee(const severance::globalfee& gf);

    static uint64_t calculate_fees(
      const severance::globalstateext* global_state_ext, asset& quantity);

    intx::uint256 get_last_level_hash(uint64_t scope, int level);
    void set_last_level_hash(uint64_t scope, int level, intx::uint256 hash);

    const intx::uint256 level_defaults[32] = {
        30238598704088929952843927706569847911599885956104611274912160341490286246718_u256,
        25348422377004321007059927731081793746945139569114277883447014548301570270860_u256,
        16401820946464185137346357874373090990568111992633083038764169830345921227085_u256,
        7508103525080351137382699802863531575643180572162613318007798684988341228268_u256,
        17960896985569549954477100205393164871173002812946988710438960683597028440922_u256,
        29464911409920719015583702742677733245455761112275208147876304472374171736419_u256,
        20365738626542439140784808616660262904197432804351602887389291635706005230479_u256,
        50094012655666739741757742535708299725511612220888959669209674245779430795631_u256,
        84481084991077554297473579297547823130151822028357513698940834088946031994428_u256,
        65009568646014927574600477453219176146218298364363007468316186649830384869270_u256,
        74568519575760023398099891318741317344911244404916721780423199270529518060223_u256,
        28474002570249281395440345236610297023194847909993280485202899395592828940126_u256,
        40230313923982849562834343028524642933574573334910634629678156674487064379057_u256,
        16463665069615288234635515866443739209783239800818597114164287502048789052464_u256,
        39326964221197219404313764098995068225350845039661696346190141178267408599237_u256,
        56128881384580835253363759507703601545282399300749662091723162625648919231395_u256,
        71651674210086931308216423199077829219568676225701481144725097391774503208581_u256,
        11291812394179869221746248061886328562378471618543727288534038397673199316212_u256,
        91768241568601166219390796547719868152960074702606000299649710606134403570387_u256,
        113866854053749903300333619484139229603952452549894060841070478621193462325348_u256,
        12900939506777163752908550726884953820264260341613592165124627336667450505012_u256,
        77792729128822647523914437850871477814352129948361548129548545876643770001468_u256,
        8550899905673560156874502538901844408321725334814212168646676121448800494749_u256,
        68075794184097345106241543125282550400004595546658124757342479691208462448155_u256,
        52051519765640516569026227651220681577251574921757729650704331930922152451705_u256,
        60439906622495289412129553804980598395101411861085333741828968014406524398960_u256,
        43838341704056268159122126764160763495039233876411520978708515517865358045820_u256,
        20769327482353150733803221965915847256410246352105945946711490529511199296334_u256,
        90854336653446787628791047493176183662724257943649508657425729023284934684385_u256,
        104113848206815522990854469768913042028817956314155575532193413111187726944706_u256,
        99687557887186228995941237085927827806810202766788290430077136634416942660613_u256,
        7333656426618417692843107199562353793827654602322450949288455009300229501943_u256
    };
};