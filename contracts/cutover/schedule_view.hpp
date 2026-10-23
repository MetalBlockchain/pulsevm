// Shared `producer_info` row layout for the cutover ceremony contracts.
//
// Included by cutover.cpp (reads the live schedule) and seed.cpp (writes
// fixture rows). One header guarantees the seeder writes exactly the bytes
// the ceremony reads: any layout drift breaks the fixture tests loudly
// instead of silently testing the wrong shape.
//
// The layout mirrors the live XPR mainnet `eosio.producers` table (code
// eosio, scope eosio), verified 2026-10-23 against live mainnet rows: 8
// fields, 90 bytes, NO authority tail — owner, total_votes float64,
// producer_key, is_active, url, unpaid_blocks, last_claim_time,
// location. XPR has no producer authorities on-chain; the schedule key
// is the only consensus-relevant key (votes are K1 recoveries against
// it), so the roster freezes the schedule key after a K1 validity gate.
// A multisig schedule key cannot exist: DPoS schedules hold single keys
// by protocol. (Leap 5 JSON-encodes the float64 total_votes as a decimal
// string; the contract reads binary and is unaffected.)
//
// The row has 8 logical fields, exactly CDT 1.8's PFR reflection limit,
// so it maps directly with no nesting tricks. If a future system
// contract appends fields, multi_index deserialization reads the mapped
// prefix and ignores trailing bytes by construction.

#pragma once

#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>

namespace schedule_view {

// The K1/R1 alternatives of eosio::public_key hold the raw 33-byte
// compressed form. Only K1 (alternative 0) is accepted anywhere here.
static std::array<char, 33> compressed_key(const eosio::public_key &key) {
    if (const auto *k1 = std::get_if<0>(&key)) {
        return *k1;
    }
    eosio::check(false, "schedule view: only K1 keys are supported");
    return {};
}

// The live row: 8 plain fields, exactly the mainnet shape.
struct producer_row {
    eosio::name owner;
    double total_votes;
    eosio::public_key producer_key;
    bool is_active;
    std::string url;
    uint32_t unpaid_blocks;
    int64_t last_claim_time;
    uint16_t location;
    uint64_t primary_key() const { return owner.value; }
};

using system_producers_table =
    eosio::multi_index<"producers"_n, producer_row>;

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

} // namespace schedule_view
