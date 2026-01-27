#pragma once

#include "types.hpp"
#include "config.hpp"

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
   uint32_t   max_inline_action_size;              ///< maximum allowed size (in bytes) of an inline action
   uint16_t   max_inline_action_depth;             ///< recursion depth limit on sending inline actions
   uint16_t   max_authority_depth;                 ///< recursion depth limit for checking if an authority is satisfied
   uint32_t   max_action_return_value_size;        ///< size limit for action return value

   void validate()const;
   uint64_t   get_max_block_net_usage() const { return max_block_net_usage; }
   uint32_t   get_target_block_net_usage_pct() const { return target_block_net_usage_pct; }
   uint32_t   get_max_transaction_net_usage() const { return max_transaction_net_usage; }
   uint32_t   get_base_per_transaction_net_usage() const { return base_per_transaction_net_usage; }
   uint32_t   get_net_usage_leeway() const { return net_usage_leeway; }
   uint32_t   get_context_free_discount_net_usage_num() const { return context_free_discount_net_usage_num; }
   uint32_t   get_context_free_discount_net_usage_den() const { return context_free_discount_net_usage_den; }

   uint32_t   get_max_block_cpu_usage() const { return max_block_cpu_usage; }
   uint32_t   get_target_block_cpu_usage_pct() const { return target_block_cpu_usage_pct; }
   uint32_t   get_max_transaction_cpu_usage() const { return max_transaction_cpu_usage; }
   uint32_t   get_min_transaction_cpu_usage() const { return min_transaction_cpu_usage; }

   uint32_t   get_max_transaction_lifetime() const { return max_transaction_lifetime; }
   uint32_t   get_max_inline_action_size() const { return max_inline_action_size; }
   uint16_t   get_max_inline_action_depth() const { return max_inline_action_depth; }
   uint16_t   get_max_authority_depth() const { return max_authority_depth; }
   uint32_t   get_max_action_return_value_size() const { return max_action_return_value_size; }

   template<typename Stream>
   friend Stream& operator << ( Stream& out, const chain_config& c ) {
      return c.log(out) << "\n";
   }

   friend inline bool operator ==( const chain_config& lhs, const chain_config& rhs ) {
      return   std::tie(   lhs.max_block_net_usage,
                           lhs.target_block_net_usage_pct,
                           lhs.max_transaction_net_usage,
                           lhs.base_per_transaction_net_usage,
                           lhs.net_usage_leeway,
                           lhs.context_free_discount_net_usage_num,
                           lhs.context_free_discount_net_usage_den,
                           lhs.max_block_cpu_usage,
                           lhs.target_block_cpu_usage_pct,
                           lhs.max_transaction_cpu_usage,
                           lhs.max_transaction_cpu_usage,
                           lhs.max_transaction_lifetime,
                           lhs.max_inline_action_size,
                           lhs.max_inline_action_depth,
                           lhs.max_authority_depth,
                           lhs.max_action_return_value_size
                        )
               ==
               std::tie(   rhs.max_block_net_usage,
                           rhs.target_block_net_usage_pct,
                           rhs.max_transaction_net_usage,
                           rhs.base_per_transaction_net_usage,
                           rhs.net_usage_leeway,
                           rhs.context_free_discount_net_usage_num,
                           rhs.context_free_discount_net_usage_den,
                           rhs.max_block_cpu_usage,
                           rhs.target_block_cpu_usage_pct,
                           rhs.max_transaction_cpu_usage,
                           rhs.max_transaction_cpu_usage,
                           rhs.max_transaction_lifetime,
                           rhs.max_inline_action_size,
                           rhs.max_inline_action_depth,
                           rhs.max_authority_depth,
                           rhs.max_action_return_value_size
                        );
   };

   friend inline bool operator !=( const chain_config& lhs, const chain_config& rhs ) { return !(lhs == rhs); }

protected:
   template<typename Stream>
   Stream& log(Stream& out) const{
      return out << "Max Block Net Usage: " << max_block_net_usage << ", "
                     << "Target Block Net Usage Percent: " << ((double)target_block_net_usage_pct / (double)config::percent_1) << "%, "
                     << "Max Transaction Net Usage: " << max_transaction_net_usage << ", "
                     << "Base Per-Transaction Net Usage: " << base_per_transaction_net_usage << ", "
                     << "Net Usage Leeway: " << net_usage_leeway << ", "
                     << "Context-Free Data Net Usage Discount: " << (double)context_free_discount_net_usage_num * 100.0 / (double)context_free_discount_net_usage_den << "% , "

                     << "Max Block CPU Usage: " << max_block_cpu_usage << ", "
                     << "Target Block CPU Usage Percent: " << ((double)target_block_cpu_usage_pct / (double)config::percent_1) << "%, "
                     << "Max Transaction CPU Usage: " << max_transaction_cpu_usage << ", "
                     << "Min Transaction CPU Usage: " << min_transaction_cpu_usage << ", "

                     << "Max Transaction Lifetime: " << max_transaction_lifetime << ", "
                     << "Max Inline Action Size: " << max_inline_action_size << ", "
                     << "Max Inline Action Depth: " << max_inline_action_depth << ", "
                     << "Max Authority Depth: " << max_authority_depth << ", "
                     << "Max Action Return Value Size: " << max_action_return_value_size;
   }
};

} } // namespace pulsevm::chain

FC_REFLECT(pulsevm::chain::chain_config,
           (max_block_net_usage)(target_block_net_usage_pct)
           (max_transaction_net_usage)(base_per_transaction_net_usage)(net_usage_leeway)
           (context_free_discount_net_usage_num)(context_free_discount_net_usage_den)

           (max_block_cpu_usage)(target_block_cpu_usage_pct)
           (max_transaction_cpu_usage)(min_transaction_cpu_usage)

           (max_transaction_lifetime)(max_inline_action_size)(max_inline_action_depth)(max_authority_depth)
           (max_action_return_value_size)
)