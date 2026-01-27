#pragma once
#include "name.hpp"
#include <fc/time.hpp>
#include <fc/utility.hpp>

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

   const static uint32_t genesis_num_supported_key_types = 2;

   const static uint32_t   default_max_block_net_usage                  = 1024 * 1024; /// at 500ms blocks and 200byte trx, this enables ~10,000 TPS burst
   const static uint32_t   default_target_block_net_usage_pct           = 10 * percent_1; /// we target 1000 TPS
   const static uint32_t   default_max_transaction_net_usage            = default_max_block_net_usage / 2;
   const static uint32_t   default_base_per_transaction_net_usage       = 12;  // 12 bytes (11 bytes for worst case of transaction_receipt_header + 1 byte for static_variant tag)
   const static uint32_t   default_net_usage_leeway                     = 500; // TODO: is this reasonable?
   const static uint32_t   default_context_free_discount_net_usage_num  = 20; // TODO: is this reasonable?
   const static uint32_t   default_context_free_discount_net_usage_den  = 100;
   const static uint32_t   transaction_id_net_usage                     = 32; // 32 bytes for the size of a transaction id

   const static uint32_t   default_max_block_cpu_usage                  = 200'000; /// max block cpu usage in microseconds
   const static uint32_t   default_target_block_cpu_usage_pct           = 10 * percent_1;
   const static uint32_t   default_max_transaction_cpu_usage            = 3*default_max_block_cpu_usage/4; /// max trx cpu usage in microseconds
   const static uint32_t   default_min_transaction_cpu_usage            = 100; /// min trx cpu usage in microseconds (10000 TPS equiv)
   const static uint32_t   default_subjective_cpu_leeway_us             = 31000; /// default subjective cpu leeway in microseconds

   const static uint32_t   default_max_trx_lifetime                     = 60*60; // 1 hour
   const static uint32_t   default_deferred_trx_expiration_window       = 10*60; // 10 minutes
   const static uint32_t   default_max_trx_delay                        = 45*24*3600; // 45 days
   const static uint32_t   default_max_inline_action_size               = 512 * 1024;   // 512 KB
   const static uint16_t   default_max_inline_action_depth              = 4;
   const static uint16_t   default_max_auth_depth                       = 6;
   const static uint32_t   default_sig_cpu_bill_pct                     = 50 * percent_1; // billable percentage of signature recovery
   const static uint32_t   default_produce_block_offset_ms              = 450;
   const static uint16_t   default_controller_thread_pool_size          = 2;
   const static uint32_t   default_max_variable_signature_length        = 16384u;
   const static uint32_t   default_max_action_return_value_size         = 256;

    const static uint32_t   fixed_overhead_shared_vector_ram_bytes = 16; ///< overhead accounts for fixed portion of size of shared_vector field
    const static uint32_t   overhead_per_row_per_index_ram_bytes = 32;    ///< overhead accounts for basic tracking structures in a row per index
    const static uint32_t   overhead_per_account_ram_bytes     = 2*1024; ///< overhead accounts for basic account storage and pre-pays features like account recovery
    const static uint32_t   setcode_ram_bytes_multiplier       = 10;     ///< multiplier on contract size to account for multiple copies and cached compilation

    const static uint32_t   rate_limiting_precision        = 1000*1000;

    const static uint64_t billable_alignment = 16;

    const static uint32_t default_max_wasm_mutable_global_bytes = 1024;
    const static uint32_t default_max_wasm_table_elements       = 1024;
    const static uint32_t default_max_wasm_section_elements     = 8192;
    const static uint32_t default_max_wasm_linear_memory_init   = 64*1024;
    const static uint32_t default_max_wasm_func_local_bytes     = 8192;
    const static uint32_t default_max_wasm_nested_structures    = 1024;
    const static uint32_t default_max_wasm_symbol_bytes         = 8192;
    const static uint32_t default_max_wasm_module_bytes         = 20*1024*1024;
    const static uint32_t default_max_wasm_code_bytes           = 20*1024*1024;
    const static uint32_t default_max_wasm_pages                = 528;
    const static uint32_t default_max_wasm_call_depth           = 251;

    const static uint32_t   min_net_usage_delta_between_base_and_max_for_trx  = 10*1024; // 10 KB

    const static name system_account_name    { "pulse"_n };
    const static name any_name    { "pulse.any"_n };
    const static name null_account_name      { "pulse.null"_n };
    const static name producers_account_name { "pulse.prods"_n };
    const static name active_name     { "active"_n };
    const static name owner_name      { "owner"_n };

   const static name majority_producers_permission_name { "prod.major"_n }; // greater than 1/2 of producers needed to authorize
   const static name minority_producers_permission_name { "prod.minor"_n }; // greater than 1/3 of producers needed to authorize0

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