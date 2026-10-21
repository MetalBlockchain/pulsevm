// Shared `producer_info` row layout for the cutover ceremony contracts.
//
// Included by cutover.cpp (reads the live schedule) and seed.cpp (writes
// fixture rows). One header guarantees the seeder writes exactly the bytes
// the ceremony reads: any layout drift breaks the fixture tests loudly
// instead of silently testing the wrong shape.
//
// The layout mirrors the live XPR mainnet `eosio.producers` table
// (code eosio, scope eosio), pinned 2026-10-21 against head 409,789,565:
// owner, total_votes float64, producer_key, is_active, url,
// unpaid_blocks, last_claim_time, location, then the
// `producer_authority$` variant tail flattened as (varuint index,
// threshold, keys). Only variant index 0 with a single 1-of-1 K1 key
// equal to the schedule key is accepted anywhere.

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

// The row has 11 logical fields, past CDT 1.8's PFR reflection limit (8),
// and exotic members (unsigned_int, vectors of variants) miscount fields,
// so the row is nested into PFR-safe pieces and the variable tail is
// carried as raw bytes: head (8 plain fields) + 42-byte authority tail.
// The tail layout is fixed: [varuint version][u32 threshold][varuint
// nkeys][varuint keytype][33 key bytes][u16 weight]. Byte concatenation
// matches the live table exactly; the tail is parsed explicitly below.
struct producer_head {
    eosio::name owner;
    double total_votes;
    eosio::public_key producer_key;
    bool is_active;
    std::string url;
    uint32_t unpaid_blocks;
    int64_t last_claim_time;
    uint16_t location;
};

struct authority_tail {
    std::array<char, 42> bytes;
};

struct producer_row {
    producer_head head;
    authority_tail tail;
    uint64_t primary_key() const { return head.owner.value; }
};

// Build the canonical 1-of-1 tail over a schedule key (fixture seeder).
static authority_tail make_authority_tail(const std::array<char, 33> &key) {
    authority_tail tail;
    size_t pos = 0;
    tail.bytes[pos++] = 0x00; // variant index 0
    tail.bytes[pos++] = 0x01; // threshold u32 LE
    tail.bytes[pos++] = 0x00;
    tail.bytes[pos++] = 0x00;
    tail.bytes[pos++] = 0x00;
    tail.bytes[pos++] = 0x01; // one key
    tail.bytes[pos++] = 0x00; // K1 key type
    for (size_t i = 0; i < 33; ++i) {
        tail.bytes[pos++] = key[i];
    }
    tail.bytes[pos++] = 0x01; // key weight u16 LE
    tail.bytes[pos++] = 0x00;
    return tail;
}

// Parse and enforce the tail: variant 0, threshold 1, one K1 key of weight
// 1. Returns the authority key bytes for the schedule-key equality check.
// Every failure names the producer so a bad row is attributable.
static std::array<char, 33>
parse_authority_tail(const authority_tail &tail, const std::string &producer) {
    const std::string who = "cutover: producer " + producer + " ";
    size_t pos = 0;
    auto need = [&](size_t n, const std::string &what) {
        eosio::check(pos + n <= tail.bytes.size(), who + what);
    };
    // varuint version (values used here encode in one byte).
    need(1, "truncated authority version");
    eosio::check((tail.bytes[pos] & 0x80) == 0, who + "bad authority version encoding");
    uint32_t version = static_cast<uint8_t>(tail.bytes[pos++]);
    eosio::check(version == 0, who + "uses an unknown authority version");
    need(4, "truncated authority threshold");
    uint32_t threshold = static_cast<uint8_t>(tail.bytes[pos]) |
                         (static_cast<uint8_t>(tail.bytes[pos + 1]) << 8) |
                         (static_cast<uint8_t>(tail.bytes[pos + 2]) << 16) |
                         (static_cast<uint8_t>(tail.bytes[pos + 3]) << 24);
    pos += 4;
    eosio::check(threshold == 1, who + "authority is not 1-of-1");
    need(1, "truncated authority key count");
    eosio::check((tail.bytes[pos] & 0x80) == 0, who + "bad key-count encoding");
    eosio::check(static_cast<uint8_t>(tail.bytes[pos++]) == 1,
                 who + "authority does not hold exactly one key");
    need(1, "truncated authority key type");
    eosio::check((tail.bytes[pos] & 0x80) == 0, who + "bad key-type encoding");
    eosio::check(static_cast<uint8_t>(tail.bytes[pos++]) == 0,
                 who + "authority uses a non-K1 key");
    need(33, "truncated authority key");
    std::array<char, 33> key;
    for (size_t i = 0; i < 33; ++i) {
        key[i] = tail.bytes[pos++];
    }
    need(2, "truncated authority key weight");
    uint16_t weight = static_cast<uint8_t>(tail.bytes[pos]) |
                      (static_cast<uint8_t>(tail.bytes[pos + 1]) << 8);
    pos += 2;
    eosio::check(weight == 1, who + "authority key weight is not 1");
    eosio::check(pos == tail.bytes.size(), who + "trailing authority bytes");
    return key;
}

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
