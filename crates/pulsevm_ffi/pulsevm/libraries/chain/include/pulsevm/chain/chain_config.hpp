#pragma once

#include <pulsevm/chain/types.hpp>
#include <pulsevm/chain/config.hpp>

namespace pulsevm { namespace chain {

struct chain_config {
   uint64_t   max_block_net_usage;                 ///< the maxiumum net usage in instructions for a block
   uint32_t   target_block_net_usage_pct;          ///< the target percent (1% == 100, 100%= 10,000) of maximum net usage; exceeding this triggers congestion handling
   uint32_t   max_transaction_net_usage;           ///< the maximum objectively measured net usage that the chain will allow regardless of account limits
   uint32_t   base_per_transaction_net_usage;      ///< the base amount of net usage billed for a transaction to cover incidentals
   uint32_t   net_usage_leeway;
   uint32_t   context_free_discount_net_usage_num; ///< the numerator for the discount on net usage of context-free data
   uint32_t   context_free_discount_net_usage_den; ///< the denominator for the discount on net usage of context-free data

   uint32_t   max_block_cpu_usage;                 ///< the maxiumum billable cpu usage (in microseconds) for a block
   uint32_t   target_block_cpu_usage_pct;          ///< the target percent (1% == 100, 100%= 10,000) of maximum cpu usage; exceeding this triggers congestion handling
   uint32_t   max_transaction_cpu_usage;           ///< the maximum billable cpu usage (in microseconds) that the chain will allow regardless of account limits
   uint32_t   min_transaction_cpu_usage;           ///< the minimum billable cpu usage (in microseconds) that the chain requires

   uint32_t   max_transaction_lifetime;            ///< the maximum number of seconds that an input transaction's expiration can be ahead of the time of the block in which it is first included
   uint32_t   deferred_trx_expiration_window;      ///< the number of seconds after the time a deferred transaction can first execute until it expires
   uint32_t   max_transaction_delay;               ///< the maximum number of seconds that can be imposed as a delay requirement by authorization checks
   uint32_t   max_inline_action_size;              ///< maximum allowed size (in bytes) of an inline action
   uint16_t   max_inline_action_depth;             ///< recursion depth limit on sending inline actions
   uint16_t   max_authority_depth;                 ///< recursion depth limit for checking if an authority is satisfied
   uint32_t   max_action_return_value_size;        ///< size limit for action return value
};

} } // namespace pulsevm::chain

FC_REFLECT(pulsevm::chain::chain_config,
           (max_block_net_usage)(target_block_net_usage_pct)
           (max_transaction_net_usage)(base_per_transaction_net_usage)(net_usage_leeway)
           (context_free_discount_net_usage_num)(context_free_discount_net_usage_den)

           (max_block_cpu_usage)(target_block_cpu_usage_pct)
           (max_transaction_cpu_usage)(min_transaction_cpu_usage)

           (max_transaction_lifetime)(deferred_trx_expiration_window)(max_transaction_delay)
           (max_inline_action_size)(max_inline_action_depth)(max_authority_depth)
           (max_action_return_value_size)
)