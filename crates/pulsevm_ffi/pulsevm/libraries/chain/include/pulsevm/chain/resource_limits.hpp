#pragma once
#include "exceptions.hpp"
#include "types.hpp"
#include "config.hpp"
#include "trace.hpp"
#include "block_timestamp.hpp"
#include <chainbase/chainbase.hpp>
#include <set>

namespace pulsevm { namespace chain {
   namespace resource_limits {
   namespace impl {
      template<typename T>
      struct ratio {
         static_assert(std::is_integral<T>::value, "ratios must have integral types");
         T numerator;
         T denominator;

         friend inline bool operator ==( const ratio& lhs, const ratio& rhs ) {
            return std::tie(lhs.numerator, lhs.denominator) == std::tie(rhs.numerator, rhs.denominator);
         }

         friend inline bool operator !=( const ratio& lhs, const ratio& rhs ) {
            return !(lhs == rhs);
         }
      };
   }

   using ratio = impl::ratio<uint64_t>;

   struct elastic_limit_parameters {
      uint64_t target;           // the desired usage
      uint64_t max;              // the maximum usage
      uint32_t periods;          // the number of aggregation periods that contribute to the average usage

      uint32_t max_multiplier;   // the multiplier by which virtual space can oversell usage when uncongested
      ratio    contract_rate;    // the rate at which a congested resource contracts its limit
      ratio    expand_rate;       // the rate at which an uncongested resource expands its limits

      void validate()const; // throws if the parameters do not satisfy basic sanity checks

      friend inline bool operator ==( const elastic_limit_parameters& lhs, const elastic_limit_parameters& rhs ) {
         return std::tie(lhs.target, lhs.max, lhs.periods, lhs.max_multiplier, lhs.contract_rate, lhs.expand_rate)
                  == std::tie(rhs.target, rhs.max, rhs.periods, rhs.max_multiplier, rhs.contract_rate, rhs.expand_rate);
      }

      friend inline bool operator !=( const elastic_limit_parameters& lhs, const elastic_limit_parameters& rhs ) {
         return !(lhs == rhs);
      }
   };

   struct account_resource_limit {
      int64_t used = 0; ///< quantity used in current window
      int64_t available = 0; ///< quantity available in current window (based upon fractional reserve)
      int64_t max = 0; ///< max per window under current congestion
      block_timestamp_type last_usage_update_time; ///< last usage timestamp
      int64_t current_used = 0;  ///< current usage according to the given timestamp
   };
} } } /// pulsevm::chain

FC_REFLECT( pulsevm::chain::resource_limits::account_resource_limit, (used)(available)(max)(last_usage_update_time)(current_used) )
FC_REFLECT( pulsevm::chain::resource_limits::ratio, (numerator)(denominator))
FC_REFLECT( pulsevm::chain::resource_limits::elastic_limit_parameters, (target)(max)(periods)(max_multiplier)(contract_rate)(expand_rate))
