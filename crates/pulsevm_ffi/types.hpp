#pragma once
#include <rust/cxx.h>
#include <pulsevm/chain/authority.hpp>
#include <pulsevm/chain/block_timestamp.hpp>
#include <pulsevm/chain/types.hpp>
#include <pulsevm/chain/genesis_state.hpp>
#include <fc/io/json.hpp>

namespace pulsevm { namespace chain {

    using microseconds = fc::microseconds;

    std::unique_ptr<digest_type> make_empty_digest() {
        return std::make_unique<digest_type>();
    }

    std::unique_ptr<digest_type> make_digest_from_data(rust::Slice<const std::uint8_t> data) {
        return std::make_unique<digest_type>(reinterpret_cast<const char*>(data.data()), data.size());
    }

    std::shared_ptr<time_point> make_time_point_from_now() {
        return std::make_shared<time_point>(time_point::now());
    }

    std::shared_ptr<block_timestamp_type> make_block_timestamp_from_now() {
        return std::make_shared<block_timestamp_type>(time_point::now());
    }

    std::shared_ptr<block_timestamp_type> make_block_timestamp_from_slot( uint32_t slot ) {
        return std::make_shared<block_timestamp_type>(slot);
    }

    std::shared_ptr<time_point> make_time_point_from_i64(int64_t us) {
        return std::make_shared<time_point>(time_point(microseconds(us)));
    }

    std::shared_ptr<time_point> make_time_point_from_microseconds(const microseconds& us) {
        return std::make_shared<time_point>(time_point(us));
    }

    std::unique_ptr<genesis_state> make_empty_genesis_state() {
        return std::make_unique<genesis_state>();
    }

    std::unique_ptr<genesis_state> parse_genesis_state(rust::Str json) {
        std::string s(json.data(), json.size());
        fc::variant v = fc::json::from_string(s);
        genesis_state gstate = v.as<genesis_state>();
        return std::make_unique<genesis_state>(std::move(gstate));
    }

    std::shared_ptr<public_key_type> parse_public_key(rust::Str key_str) {
        std::string s(key_str.data(), key_str.size());
        public_key_type pk = public_key_type(s);
        return std::make_shared<public_key_type>(std::move(pk));
    }

}} // namespace pulsevm::chain