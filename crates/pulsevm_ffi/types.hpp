#pragma once
#include <rust/cxx.h>
#include <pulsevm/chain/block_timestamp.hpp>
#include <pulsevm/chain/types.hpp>

namespace pulsevm { namespace chain {

    using microseconds = fc::microseconds;

    std::unique_ptr<digest_type> make_empty_digest(rust::Slice<const std::uint8_t> data) {
        return std::make_unique<digest_type>();
    }

    std::unique_ptr<digest_type> make_digest_from_data(rust::Slice<const std::uint8_t> data) {
        return std::make_unique<digest_type>(digest_type::hash(data.data(), data.size()));
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

}} // namespace pulsevm::chain