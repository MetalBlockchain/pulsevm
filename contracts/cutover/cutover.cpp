// XPR -> A-Chain cutover ceremony contract.
//
// The old validator set commits on-chain to a cutover height H: the contract
// freezes the live schedule at init, tallies block-signing-key signatures
// over the cutover digest, and flips a finalized flag at strict 2/3+1
// weight. The A-Chain restore gate reads this state from the checkpoint and
// re-verifies the tally; vote timing comes from the actions' inclusion
// blocks, which are XPR consensus.
//
// Design notes (see docs/xpr-halt-ceremony.md):
// - Membership and weights come from the live `eosio.producers` table read
//   in-contract at init: the roster is never prover-supplied. Scope and code
//   are both hardcoded to `eosio`; the table must exist or init aborts.
// - Only 1-of-1 single-key authorities are supported. init fails closed on
//   any threshold != 1, key count != 1, non-K1 key, or authority key !=
//   schedule key. Multisig schedules need a new ceremony, loudly, not a
//   silent tally of the wrong keys.
// - Weights are u128 truncated from float64 total_votes (finite,
//   non-negative, and below 1e30, checked). XPR mainnet magnitudes (1e20+)
//   saturate u64, so u64 tallying would collapse stake into a member count.
//   The A-Chain verifier uses the identical conversion; tallies agree
//   bit-for-bit.
// - The vote digest is byte-identical to the A-Chain halt-declaration
//   digest: domain || source-chain-id || H-be32 || member-count-be32 || per
//   member (producer-len-be32 || producer-utf8 || key-compressed ||
//   weight-be128), members in byte-lexicographic name order. One BP
//   signature serves both the on-chain vote and the off-chain declaration.
// - init is permissionless and re-runnable while no vote has landed. A
//   wrong-H init cannot forge a quorum (votes bind the stored H; BPs only
//   sign the coordinated digest), so griefing affects liveness only, never
//   safety. Once the first vote lands the freeze is locked.
// - One cutover: init runs once per freeze, votes close at finalized, and
//   the contract holds no admin key. There is nothing to upgrade.

#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

#include "schedule_view.hpp"

namespace cutover {

using schedule_view::compressed_key;
using schedule_view::name_to_string;
using schedule_view::system_producers_table;

// PULSEVM-XPR-HALT-DECLARATION-v1: must match HALT_DECLARATION_DOMAIN in
// pulsevm_chain_types::migration.
static constexpr char declaration_domain[] = "PULSEVM-XPR-HALT-DECLARATION-v1";

// Frozen ceremony state (singleton). Table typedefs live inside the
// contract class so abigen emits them into the ABI (get_table_rows needs
// the table definitions to decode rows).
struct [[eosio::table]] ceremony {
    uint64_t id = 0; // always 0: one ceremony per contract
    uint32_t h = 0;  // cutover height H
    eosio::checksum256 source_chain_id;
    unsigned __int128 total_weight = 0;
    unsigned __int128 voted_weight = 0;
    bool finalized = false;
    eosio::checksum256 declaration_digest;
    uint64_t primary_key() const { return id; }
};

// One frozen roster member, keyed by producer name value (table iteration
// order); vote-time ordering is byte-lexicographic over the name string,
// matching the A-Chain declaration builder.
struct [[eosio::table]] member {
    eosio::name producer;
    eosio::public_key key;
    unsigned __int128 weight;
    bool voted = false;
    uint64_t primary_key() const { return producer.value; }
};

// Table iteration order is packed-uint64 order; the digest below re-sorts
// byte-wise over canonical name strings (schedule_view::name_to_string),
// matching the A-Chain declaration builder, so table order never leaks
// into digests.

static void append_be32(std::vector<char> &out, uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xff));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

static void append_be128(std::vector<char> &out, unsigned __int128 value) {
    for (int i = 15; i >= 0; --i) {
        out.push_back(static_cast<char>((value >> (i * 8)) & 0xff));
    }
}

CONTRACT cutover : public eosio::contract {
  public:
    using eosio::contract::contract;
    using ceremony_singleton = eosio::singleton<"ceremony"_n, ceremony>;
    using member_table = eosio::multi_index<"members"_n, member>;

    // Freeze the live schedule for cutover height H. Re-runnable while no
    // vote has landed (voted_weight == 0); afterwards the freeze is locked.
    ACTION init(uint32_t h, const eosio::checksum256 &source_chain_id) {
        ceremony_singleton state(get_self(), get_self().value);
        if (state.exists()) {
            auto current = state.get();
            eosio::check(current.voted_weight == 0,
                         "cutover already collecting votes; freeze is locked");
            state.remove();
            // Fall through and re-freeze. Rows are re-created below; the
            // caller pays RAM for its own freeze.
            member_table members(get_self(), get_self().value);
            for (auto it = members.begin(); it != members.end();) {
                it = members.erase(it);
            }
        }
        system_producers_table schedule(eosio::name("eosio"), eosio::name("eosio").value);
        unsigned __int128 total = 0;
        uint32_t count = 0;
        // Collect active members first so the digest order (byte-wise name
        // order) is independent of table iteration.
        struct frozen {
            std::string producer;
            eosio::public_key key;
            unsigned __int128 weight;
        };
        std::vector<frozen> set;
        for (const auto &row : schedule) {
            if (!row.head.is_active) {
                continue;
            }
            const std::string producer_name = name_to_string(row.head.owner.value);
            // Enforce the 1-of-1 single-key precondition explicitly from
            // the raw tail bytes (PFR cannot reflect the variant).
            const auto authority_key =
                schedule_view::parse_authority_tail(row.tail, producer_name);
            eosio::check(authority_key == compressed_key(row.head.producer_key),
                         "cutover: producer authority key differs from schedule key");
            // NaN fails self-equality; infinities fail the upper bound.
            // (CDT 1.8 has no std::isfinite for contracts.)
            eosio::check(row.head.total_votes == row.head.total_votes && row.head.total_votes >= 0.0 &&
                             row.head.total_votes < 1.0e30,
                         "cutover: producer vote weight is not a usable float");
            unsigned __int128 weight = static_cast<unsigned __int128>(row.head.total_votes);
            set.push_back({name_to_string(row.head.owner.value), row.head.producer_key, weight});
            total += weight;
            ++count;
        }
        eosio::check(count > 0, "cutover: live schedule has no active producers");
        eosio::check(total > 0, "cutover: live schedule carries no weight");
        std::sort(set.begin(), set.end(), [](const frozen &a, const frozen &b) {
            return a.producer < b.producer;
        });
        member_table members(get_self(), get_self().value);
        std::vector<char> message(declaration_domain,
                                  declaration_domain + sizeof(declaration_domain) - 1);
        const auto chain_bytes = source_chain_id.extract_as_byte_array();
        message.insert(message.end(), chain_bytes.begin(), chain_bytes.end());
        append_be32(message, h);
        append_be32(message, count);
        for (const auto &entry : set) {
            members.emplace(get_self(), [&](auto &row) {
                row.producer = eosio::name(entry.producer);
                row.key = entry.key;
                row.weight = entry.weight;
            });
            append_be32(message, static_cast<uint32_t>(entry.producer.size()));
            message.insert(message.end(), entry.producer.begin(), entry.producer.end());
            const auto key_bytes = compressed_key(entry.key);
            message.insert(message.end(), key_bytes.begin(), key_bytes.end());
            append_be128(message, entry.weight);
        }
        eosio::checksum256 digest =
            eosio::sha256(message.data(), static_cast<uint32_t>(message.size()));
        state.set(
            ceremony{0, h, source_chain_id, total, 0, false, digest},
            get_self());
    }

    // Record one producer's vote: signature over the frozen declaration
    // digest by the frozen schedule key. Permissionless: the signature is
    // the authorization, so anyone may relay votes.
    ACTION vote(const eosio::name &producer, const eosio::signature &sig) {
        ceremony_singleton state(get_self(), get_self().value);
        eosio::check(state.exists(), "cutover: no frozen ceremony; init first");
        auto frozen = state.get();
        eosio::check(!frozen.finalized, "cutover: tally already finalized");
        member_table members(get_self(), get_self().value);
        auto it = members.find(producer.value);
        eosio::check(it != members.end(),
                     "cutover: producer is not in the frozen validator set");
        eosio::check(!it->voted, "cutover: producer already voted");
        eosio::public_key recovered = eosio::recover_key(frozen.declaration_digest, sig);
        // Compare compressed bytes, not variants: the frozen keys are
        // always K1, and this stays exact even if recovery tags R1.
        eosio::check(compressed_key(recovered) == compressed_key(it->key),
                     "cutover: signature is not from the frozen schedule key");
        members.modify(it, eosio::same_payer, [&](auto &row) { row.voted = true; });
        frozen.voted_weight += it->weight;
        if (frozen.voted_weight * 3 > frozen.total_weight * 2) {
            frozen.finalized = true;
        }
        state.set(frozen, get_self());
    }
};

EOSIO_DISPATCH(cutover, (init)(vote))

} // namespace cutover
