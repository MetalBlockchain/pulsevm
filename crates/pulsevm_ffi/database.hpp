// chainbase_bridge.hpp - C++ bridge header for CXX
#pragma once
#include <chainbase/chainbase.hpp>
#include <pulsevm/account_object.hpp>
#include <pulsevm/resource_limits_private.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <memory>
#include <rust/cxx.h>
#include <string>

namespace chainbase {
  using undo_session = database::session;
}

namespace pulsevm { namespace chain {

class database_wrapper : public chainbase::database {
public:
    // Inherit constructors
    using chainbase::database::database;
    
    // Add your non-template wrapper methods
    void add_indices() {
        this->add_index<account_index>();
        this->add_index<resource_limits::resource_limits_index>();
        this->add_index<resource_limits::resource_usage_index>();
        this->add_index<resource_limits::resource_limits_state_index>();
        this->add_index<resource_limits::resource_limits_config_index>();
    }

    void add_account(const account_name& account_name) {
        auto account = this->create<account_object>([&](auto& a) {
            a.name = account_name;
        });
    }

    void initialize_resource_limits() {
        const auto& config = this->create<resource_limits::resource_limits_config_object>([](resource_limits::resource_limits_config_object& config){
            // see default settings in the declaration
        });

        const auto& state = this->create<resource_limits::resource_limits_state_object>([&config](resource_limits::resource_limits_state_object& state){
            // see default settings in the declaration

            // start the chain off in a way that it is "congested" aka slow-start
            state.virtual_cpu_limit = config.cpu_limit_parameters.max;
            state.virtual_net_limit = config.net_limit_parameters.max;
        });
    }

    void initialize_account_resource_limits(const account_name& account_name) {
        const auto& limits = this->create<resource_limits::resource_limits_object>([&]( resource_limits::resource_limits_object& bl ) {
            bl.owner = account_name;
        });

        const auto& usage = this->create<resource_limits::resource_usage_object>([&]( resource_limits::resource_usage_object& bu ) {
            bu.owner = account_name;
        });
    }

    void add_transaction_usage(const rust::Vec<uint64_t>& accounts, uint64_t cpu_usage, uint64_t net_usage, uint32_t time_slot ) {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        const auto& config = this->get<resource_limits::resource_limits_config_object>();

        for( const auto& ac : accounts ) {
            const account_name a(ac);
            const auto& usage = this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( a );
            int64_t unused;
            int64_t net_weight;
            int64_t cpu_weight;
            get_account_limits( a, unused, net_weight, cpu_weight );

            this->modify( usage, [&]( auto& bu ){
                bu.net_usage.add( net_usage, time_slot, config.account_net_usage_average_window );
                bu.cpu_usage.add( cpu_usage, time_slot, config.account_cpu_usage_average_window );
            });

            if( cpu_weight >= 0 && state.total_cpu_weight > 0 ) {
                uint128_t window_size = config.account_cpu_usage_average_window;
                auto virtual_network_capacity_in_window = (uint128_t)state.virtual_cpu_limit * window_size;
                auto cpu_used_in_window                 = ((uint128_t)usage.cpu_usage.value_ex * window_size) / (uint128_t)config::rate_limiting_precision;

                uint128_t user_weight     = (uint128_t)cpu_weight;
                uint128_t all_user_weight = state.total_cpu_weight;

                auto max_user_use_in_window = (virtual_network_capacity_in_window * user_weight) / all_user_weight;

                EOS_ASSERT( cpu_used_in_window <= max_user_use_in_window,
                            tx_cpu_usage_exceeded,
                            "authorizing account '${n}' has insufficient objective cpu resources for this transaction,"
                            " used in window ${cpu_used_in_window}us, allowed in window ${max_user_use_in_window}us",
                            ("n", a)
                            ("cpu_used_in_window",cpu_used_in_window)
                            ("max_user_use_in_window",max_user_use_in_window) );
            }

            if( net_weight >= 0 && state.total_net_weight > 0) {

                uint128_t window_size = config.account_net_usage_average_window;
                auto virtual_network_capacity_in_window = (uint128_t)state.virtual_net_limit * window_size;
                auto net_used_in_window                 = ((uint128_t)usage.net_usage.value_ex * window_size) / (uint128_t)config::rate_limiting_precision;

                uint128_t user_weight     = (uint128_t)net_weight;
                uint128_t all_user_weight = state.total_net_weight;

                auto max_user_use_in_window = (virtual_network_capacity_in_window * user_weight) / all_user_weight;

                EOS_ASSERT( net_used_in_window <= max_user_use_in_window,
                            tx_net_usage_exceeded,
                            "authorizing account '${n}' has insufficient net resources for this transaction,"
                            " used in window ${net_used_in_window}, allowed in window ${max_user_use_in_window}",
                            ("n", a)
                            ("net_used_in_window",net_used_in_window)
                            ("max_user_use_in_window",max_user_use_in_window) );

            }
        }

        // account for this transaction in the block and do not exceed those limits either
        this->modify(state, [&](resource_limits::resource_limits_state_object& rls){
            rls.pending_cpu_usage += cpu_usage;
            rls.pending_net_usage += net_usage;
        });

        EOS_ASSERT( state.pending_cpu_usage <= config.cpu_limit_parameters.max, block_resource_exhausted, "Block has insufficient cpu resources" );
        EOS_ASSERT( state.pending_net_usage <= config.net_limit_parameters.max, block_resource_exhausted, "Block has insufficient net resources" );
    }

    void add_pending_ram_usage( const account_name& account, int64_t ram_delta ) {
        if (ram_delta == 0) {
            return;
        }

        const auto& usage  = this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( account );

        EOS_ASSERT( ram_delta <= 0 || UINT64_MAX - usage.ram_usage >= (uint64_t)ram_delta, transaction_exception,
                    "Ram usage delta would overflow UINT64_MAX");
        EOS_ASSERT(ram_delta >= 0 || usage.ram_usage >= (uint64_t)(-ram_delta), transaction_exception,
                    "Ram usage delta would underflow UINT64_MAX");

        this->modify( usage, [&]( auto& u ) {
            u.ram_usage += ram_delta;
        });
    }

    void verify_account_ram_usage( const account_name& account ) {
        int64_t ram_bytes; int64_t net_weight; int64_t cpu_weight;
        get_account_limits( account, ram_bytes, net_weight, cpu_weight );
        const auto& usage  = this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( account );

        if( ram_bytes >= 0 ) {
            EOS_ASSERT( usage.ram_usage <= static_cast<uint64_t>(ram_bytes), ram_usage_exceeded,
                        "account ${account} has insufficient ram; needs ${needs} bytes has ${available} bytes",
                        ("account", account)("needs",usage.ram_usage)("available",ram_bytes)              );
        }
    }

    int64_t get_account_ram_usage( const account_name& name ) {
        return this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( name ).ram_usage;
    }

    bool set_account_limits( const account_name& account, int64_t ram_bytes, int64_t net_weight, int64_t cpu_weight) {
        auto find_or_create_pending_limits = [&]() -> const resource_limits::resource_limits_object& {
            const auto* pending_limits = this->find<resource_limits::resource_limits_object, resource_limits::by_owner>( boost::make_tuple(true, account) );
            if (pending_limits == nullptr) {
                const auto& limits = this->get<resource_limits::resource_limits_object, resource_limits::by_owner>( boost::make_tuple(false, account));
                return this->create<resource_limits::resource_limits_object>([&](resource_limits::resource_limits_object& pending_limits){
                    pending_limits.owner = limits.owner;
                    pending_limits.ram_bytes = limits.ram_bytes;
                    pending_limits.net_weight = limits.net_weight;
                    pending_limits.cpu_weight = limits.cpu_weight;
                    pending_limits.pending = true;
                });
            } else {
                return *pending_limits;
            }
        };

        // update the users weights directly
        auto& limits = find_or_create_pending_limits();
        bool decreased_limit = false;

        if( ram_bytes >= 0 ) {
            decreased_limit = ( (limits.ram_bytes < 0) || (ram_bytes < limits.ram_bytes) );
        }

        this->modify( limits, [&]( resource_limits::resource_limits_object& pending_limits ){
            pending_limits.ram_bytes = ram_bytes;
            pending_limits.net_weight = net_weight;
            pending_limits.cpu_weight = cpu_weight;
        });

        return decreased_limit;
    }

    void get_account_limits( const account_name& account, int64_t& ram_bytes, int64_t& net_weight, int64_t& cpu_weight ) {
        const auto* pending_buo = this->find<resource_limits::resource_limits_object,resource_limits::by_owner>( boost::make_tuple(true, account) );
        if (pending_buo) {
            ram_bytes  = pending_buo->ram_bytes;
            net_weight = pending_buo->net_weight;
            cpu_weight = pending_buo->cpu_weight;
        } else {
            const auto& buo = this->get<resource_limits::resource_limits_object,resource_limits::by_owner>( boost::make_tuple( false, account ) );
            ram_bytes  = buo.ram_bytes;
            net_weight = buo.net_weight;
            cpu_weight = buo.cpu_weight;
        }
    }

    uint64_t get_total_cpu_weight() {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        return state.total_cpu_weight;
    }

    uint64_t get_total_net_weight() {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        return state.total_net_weight;
    }

    std::unique_ptr<account_object> get_account() {
        return std::make_unique<account_object>(this->get<account_object, by_id>(account_id_type(0)));
    }

    std::unique_ptr<chainbase::database::session> create_undo_session(bool enabled) {
        return std::make_unique<chainbase::database::session>(this->start_undo_session(enabled));
    }
};

// Wrapper methods for database operations
void close(::chainbase::database& db);
void flush(::chainbase::database& db);
void undo(::chainbase::database& db);
void commit(::chainbase::database& db, int64_t revision);
int64_t revision(const ::chainbase::database& db);

} }

// Forward declare the enum from the bridge
enum class DatabaseOpenFlags : uint32_t;

// Bridge function to open database
std::unique_ptr<pulsevm::chain::database_wrapper> open_database(
    rust::Str path,
    DatabaseOpenFlags flags,
    uint64_t size
);