#include <pulsevm/chain/resource_limits_private.hpp>

namespace pulsevm { namespace chain {

    namespace resource_limits {
        static uint64_t update_elastic_limit(uint64_t current_limit, uint64_t average_usage, const elastic_limit_parameters& params) {
            uint64_t result = current_limit;

            if (average_usage > params.target ) {
                result = result * params.contract_rate;
            } else {
                result = result * params.expand_rate;
            }
            
            return std::min(std::max(result, params.max), params.max * params.max_multiplier);
        }

        void resource_limits_state_object::update_virtual_cpu_limit( const resource_limits_config_object& cfg ) {
            virtual_cpu_limit = update_elastic_limit(virtual_cpu_limit, average_block_cpu_usage.average(), cfg.cpu_limit_parameters);
        }

        void resource_limits_state_object::update_virtual_net_limit( const resource_limits_config_object& cfg ) {
            virtual_net_limit = update_elastic_limit(virtual_net_limit, average_block_net_usage.average(), cfg.net_limit_parameters);
        }
    }

} }