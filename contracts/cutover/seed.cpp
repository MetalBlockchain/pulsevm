// Fixture-only seeder for cutover ceremony tests. NEVER DEPLOY TO MAINNET.
//
// The local fixture chain carries no system `producers` table, so the
// cutover contract's init would find an empty schedule. This helper writes
// synthetic rows under code `eosio` / scope `eosio` with the exact binary
// layout the ceremony reads (shared schedule_view.hpp guarantees it):
// the 8-field mainnet shape, no authority tail.

#include <eosio/eosio.hpp>

#include "schedule_view.hpp"

namespace seed {

CONTRACT seed : public eosio::contract {
  public:
    using eosio::contract::contract;

    // Table type for the synthetic `eosio.producers` row (shared layout in
    // schedule_view.hpp). NOTE: CDT abigen emits actions only — the ABI
    // table/struct entries come from finalize_abi.py, which Leap needs even
    // for hex row queries.
    using producers_table =
        eosio::multi_index<"producers"_n, schedule_view::producer_row>;

    // Store one producers row: owner, float64 votes, 33-byte K1 key,
    // active flag. Head-only, exactly the live mainnet shape.
    ACTION setprod(const eosio::name &owner, double votes,
                   const std::vector<char> &key, bool active) {
        require_auth(get_self());
        eosio::check(key.size() == 33, "seed: key must be 33 compressed bytes");
        eosio::check(votes == votes && votes >= 0.0 && votes < 1.0e30,
                     "seed: votes must be a usable float");
        producers_table schedule(eosio::name("eosio"),
                                                       eosio::name("eosio").value);
        std::array<char, 33> key_bytes;
        std::copy(key.begin(), key.end(), key_bytes.begin());
        // Alternative 0 is K1; the two array alternatives are identical
        // types, so the index must be explicit.
        eosio::public_key producer_key(std::in_place_index<0>, key_bytes);
        auto it = schedule.find(owner.value);
        if (it == schedule.end()) {
            schedule.emplace(get_self(), [&](auto &row) {
                row.owner = owner;
                row.total_votes = votes;
                row.producer_key = producer_key;
                row.is_active = active;
                row.url = "";
                row.unpaid_blocks = 0;
                row.last_claim_time = 0;
                row.location = 0;
            });
        } else {
            schedule.modify(it, eosio::same_payer, [&](auto &row) {
                row.total_votes = votes;
                row.producer_key = producer_key;
                row.is_active = active;
            });
        }
    }

    ACTION clear(const eosio::name &owner) {
        require_auth(get_self());
        producers_table schedule(eosio::name("eosio"),
                                                       eosio::name("eosio").value);
        auto it = schedule.find(owner.value);
        eosio::check(it != schedule.end(), "seed: no such row");
        schedule.erase(it);
    }
};

EOSIO_DISPATCH(seed, (setprod)(clear))

} // namespace seed
