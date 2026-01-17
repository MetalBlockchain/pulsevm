#pragma once
#include "name.hpp"

namespace pulsevm { namespace chain { namespace config {

    const static int percent_100 = 10000;
    const static int percent_1   = 100;

    static const uint32_t account_cpu_usage_average_window_ms  = 24*60*60*1000l;
    static const uint32_t account_net_usage_average_window_ms  = 24*60*60*1000l;
    static const uint32_t block_cpu_usage_average_window_ms    = 60*1000l;
    static const uint32_t block_size_average_window_ms         = 60*1000l;
    static const uint32_t maximum_elastic_resource_multiplier  = 1000;

    const static int      block_interval_ms = 500;
    const static int      block_interval_us = block_interval_ms*1000;
    const static uint64_t block_timestamp_epoch = 946684800000ll; // epoch is year 2000.

    const static uint32_t   default_max_block_cpu_usage                  = 200'000; /// max block cpu usage in microseconds
    const static uint32_t   default_target_block_cpu_usage_pct           = 10 * percent_1;

    const static uint32_t   default_max_block_net_usage                  = 1024 * 1024; /// at 500ms blocks and 200byte trx, this enables ~10,000 TPS burst
    const static uint32_t   default_target_block_net_usage_pct           = 10 * percent_1; /// we target 1000 TPS

    const static uint32_t   fixed_overhead_shared_vector_ram_bytes = 16; ///< overhead accounts for fixed portion of size of shared_vector field
    const static uint32_t   overhead_per_row_per_index_ram_bytes = 32;    ///< overhead accounts for basic tracking structures in a row per index

    const static uint32_t   rate_limiting_precision        = 1000*1000;

    const static uint64_t billable_alignment = 16;

    const static name system_account_name    { "pulse"_n };
    const static name any_name    { "pulse.any"_n };
    const static name null_account_name      { "pulse.null"_n };
    const static name producers_account_name { "pulse.prods"_n };

    template<typename T>
    struct billable_size;

    template<typename T>
    constexpr uint64_t billable_size_v = ((billable_size<T>::value + billable_alignment - 1) / billable_alignment) * billable_alignment;

} } } // pulsevm::chain::config}

constexpr uint64_t EOS_PERCENT(uint64_t value, uint32_t percentage) {
   return (value * percentage) / pulsevm::chain::config::percent_100;
}

template<typename Number>
Number EOS_PERCENT_CEIL(Number value, uint32_t percentage) {
   return ((value * percentage) + pulsevm::chain::config::percent_100 - pulsevm::chain::config::percent_1)  / pulsevm::chain::config::percent_100;
}