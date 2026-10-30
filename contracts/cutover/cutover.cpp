// XPR -> A-Chain cutover ceremony contract.
//
// The old validator set commits on-chain to a cutover height H: the contract
// freezes the coordinated active schedule at init, tallies block-signing-key
// signatures over the cutover digest, and flips a finalized flag at strict
// 2/3+1 count quorum. The A-Chain restore gate reads this state from the
// checkpoint and re-verifies the tally; vote timing comes from the actions'
// inclusion blocks, which are XPR consensus.
//
// Design notes (see docs/xpr-halt-ceremony.md):
// - The frozen set is the ACTIVE SCHEDULE (names, schedule keys, version),
//   supplied by the coordinator at init: one member, one vote. Vote-weight
//   (`total_votes`) tracking is gone — it drifted every block, let a handful
//   of producers clear quorum alone, and let standby churn brick the freeze.
//   Standbys are simply not in the quorum whether or not they are active.
// - The freeze is prover-supplied, so honesty rides on two anchors the
//   contract cannot provide: BPs verify-then-sign (the voter recomputes the
//   declaration digest from the coordinated schedule and refuses a foreign
//   freeze), and the A-Chain light-client check (the declared set must equal
//   the recorded schedule with the version pinned to H, and every member
//   key-anchored to checkpoint state). A false set cannot collect 15 of 21
//   honest signatures.
// - Only K1 schedule keys are supported. init fails closed on any non-K1
//   key. Multisig schedules need a new ceremony, loudly, not a silent tally
//   of the wrong keys.
// - The vote digest is byte-identical to the A-Chain halt-declaration
//   digest: domain || source-chain-id || H-be32 || member-count-be32 || per
//   member (producer-len-be32 || producer-utf8 || key-compressed ||
//   weight-be128, always 1), members in byte-lexicographic name order. One
//   BP signature serves both the on-chain vote and the off-chain
//   declaration.
// - init is permissionless and re-runnable while no vote has landed, or
//   once the freeze expired (see vote_window_us). A wrong-H init cannot
//   forge a quorum (votes bind the stored H; BPs only sign the coordinated
//   digest), so griefing affects liveness only, never safety. An abandoned
//   or wrong-H freeze with votes on it expires instead of bricking the
//   contract: anyone may start over, no admin needed.
// - One cutover: init runs once per live freeze, votes close at finalized,
//   and the contract holds no admin key. There is nothing to upgrade.

#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>

namespace cutover {

// PULSEVM-XPR-HALT-DECLARATION-v1: must match HALT_DECLARATION_DOMAIN in
// pulsevm_chain_types::migration.
static constexpr char declaration_domain[] = "PULSEVM-XPR-HALT-DECLARATION-v1";

// Ceremony liveness bound: votes land within vote_window_us of the freeze
// (init instant below). Afterwards the freeze expires: votes are refused
// and re-init is allowed — even with votes on it, so a wrong-H or
// abandoned freeze can never brick the contract. The window must exceed
// the worst-case ceremony (hours) with wide margin while staying short
// enough that a stale freeze cannot confuse coordination.
static constexpr uint64_t vote_window_us = 7ULL * 24ULL * 60ULL * 60ULL * 1000000ULL;

// publication_time() in plain microseconds since epoch: the init_time ABI
// field and the off-chain microsecond clock speak the same unit.
static uint64_t now_us() {
    return static_cast<uint64_t>(eosio::publication_time().time_since_epoch().count());
}

// One frozen schedule member as supplied to init: producer name plus its
// schedule (block-signing) key. Weight is always 1 and is not transported.
// (CDT reflection serializes this automatically; no serialize macro.)
struct schedule_member {
    eosio::name producer;
    eosio::public_key key;
};

// Frozen ceremony state (singleton). Table typedefs live inside the
// contract class so abigen emits them into the ABI (get_table_rows needs
// the table definitions to decode rows).
struct [[eosio::table]] ceremony {
    uint64_t id = 0; // always 0: one ceremony per contract
    uint32_t h = 0;  // cutover height H
    eosio::checksum256 source_chain_id;
    // The frozen schedule's version (the active schedule version at
    // freeze time). The exporter pins every vote and H to this version;
    // a rotation anywhere in the window fails closed off-chain.
    uint32_t schedule_version = 0;
    // Count quorum over unit members: total is the schedule size, voted
    // is the signer count. Field names stay `*_weight` so existing
    // table readers keep working; every member weighs 1.
    unsigned __int128 total_weight = 0;
    unsigned __int128 voted_weight = 0;
    bool finalized = false;
    eosio::checksum256 declaration_digest;
    // publication_time() microseconds at freeze; votes are accepted only
    // within vote_window_us of it. Appended last to keep the field order
    // of the frozen rows stable for every JSON consumer. (Deployments are
    // fresh accounts with empty tables — there is no same-account upgrade
    // path whose old rows would need migration.)
    uint64_t init_time = 0;
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
// byte-wise over canonical name strings, matching the A-Chain declaration
// builder, so table order never leaks into digests.
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

static std::array<char, 33> compressed_key(const eosio::public_key &key) {
    if (const auto *k1 = std::get_if<0>(&key)) {
        return *k1;
    }
    eosio::check(false, "cutover: only K1 keys are supported");
    return {};
}

// EOSIO name charmap for canonical stringification (matches the A-Chain
// name codec; avoids any toolchain to_string drift).
static std::string name_to_string(uint64_t value) {
    static const char *charmap = ".12345abcdefghijklmnopqrstuvwxyz";
    char str[14];
    uint64_t tmp = value;
    for (int i = 0; i <= 12; ++i) {
        char c;
        if (i == 0) {
            c = charmap[tmp & 0x0f];
            tmp >>= 4;
        } else {
            c = charmap[tmp & 0x1f];
            tmp >>= 5;
        }
        str[12 - i] = c;
    }
    // Strip trailing dots (canonical form).
    int len = 13;
    while (len > 0 && str[len - 1] == '.') {
        --len;
    }
    return std::string(str, len);
}

CONTRACT cutover : public eosio::contract {
  public:
    using eosio::contract::contract;
    using ceremony_singleton = eosio::singleton<"ceremony"_n, ceremony>;
    using member_table = eosio::multi_index<"members"_n, member>;

    // Freeze the coordinated active schedule for cutover height H.
    // Re-runnable while no vote has landed (voted_weight == 0), or once
    // the freeze expired — even with votes on it, so an abandoned freeze
    // can never brick the contract. Expiry is publication_time() based,
    // hence XPR consensus time, not wall clock.
    ACTION init(uint32_t h,
               const eosio::checksum256 &source_chain_id,
               uint32_t schedule_version,
               const std::vector<schedule_member> &schedule) {
        ceremony_singleton state(get_self(), get_self().value);
        if (state.exists()) {
            auto current = state.get();
            bool expired = now_us() > current.init_time + vote_window_us;
            eosio::check(current.voted_weight == 0 || expired,
                         "cutover already collecting votes; freeze is locked");
            state.remove();
            // Fall through and re-freeze. Rows are re-created below; the
            // caller pays RAM for its own freeze.
            member_table members(get_self(), get_self().value);
            for (auto it = members.begin(); it != members.end();) {
                it = members.erase(it);
            }
        }
        eosio::check(!schedule.empty(), "cutover: frozen schedule is empty");
        // Sort byte-wise over canonical name strings so the digest order
        // is independent of parameter order, matching the A-Chain
        // declaration builder.
        struct frozen {
            std::string producer;
            eosio::public_key key;
        };
        std::vector<frozen> set;
        for (const auto &entry : schedule) {
            // The roster key is the schedule key, gated to K1 here (a
            // non-K1 schedule key would mint an entry nobody can sign for,
            // and votes recover K1 only).
            compressed_key(entry.key);
            eosio::check(entry.producer.value != 0, "cutover: schedule member name is empty");
            set.push_back({name_to_string(entry.producer.value), entry.key});
        }
        std::sort(set.begin(), set.end(), [](const frozen &a, const frozen &b) {
            return a.producer < b.producer;
        });
        for (size_t i = 1; i < set.size(); ++i) {
            eosio::check(set[i - 1].producer != set[i].producer,
                         "cutover: schedule names a producer twice");
        }
        member_table members(get_self(), get_self().value);
        std::vector<char> message(declaration_domain,
                                  declaration_domain + sizeof(declaration_domain) - 1);
        const auto chain_bytes = source_chain_id.extract_as_byte_array();
        message.insert(message.end(), chain_bytes.begin(), chain_bytes.end());
        append_be32(message, h);
        append_be32(message, static_cast<uint32_t>(set.size()));
        for (const auto &entry : set) {
            members.emplace(get_self(), [&](auto &row) {
                row.producer = eosio::name(entry.producer);
                row.key = entry.key;
                row.weight = 1;
            });
            append_be32(message, static_cast<uint32_t>(entry.producer.size()));
            message.insert(message.end(), entry.producer.begin(), entry.producer.end());
            const auto key_bytes = compressed_key(entry.key);
            message.insert(message.end(), key_bytes.begin(), key_bytes.end());
            append_be128(message, 1);
        }
        eosio::checksum256 digest =
            eosio::sha256(message.data(), static_cast<uint32_t>(message.size()));
        unsigned __int128 total = static_cast<unsigned __int128>(set.size());
        state.set(
            ceremony{0, h, source_chain_id, schedule_version, total, 0, false, digest, now_us()},
            get_self());
    }

    // Record one producer's vote: signature over the frozen declaration
    // digest by the frozen schedule key. Permissionless: the signature is
    // the authorization, so anyone may relay votes. Votes land inside the
    // freeze window only; afterwards the freeze is expired (re-init for a
    // fresh one) so a stale freeze can never finalize late. One member,
    // one vote: the tally is a count quorum.
    ACTION vote(const eosio::name &producer, const eosio::signature &sig) {
        ceremony_singleton state(get_self(), get_self().value);
        eosio::check(state.exists(), "cutover: no frozen ceremony; init first");
        auto frozen = state.get();
        eosio::check(!frozen.finalized, "cutover: tally already finalized");
        eosio::check(now_us() <= frozen.init_time + vote_window_us,
                     "cutover: ceremony window expired; re-init for a fresh freeze");
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
        frozen.voted_weight += 1;
        if (frozen.voted_weight * 3 > frozen.total_weight * 2) {
            frozen.finalized = true;
        }
        state.set(frozen, get_self());
    }
};

EOSIO_DISPATCH(cutover, (init)(vote))

} // namespace cutover
