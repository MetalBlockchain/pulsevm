// chainbase_bridge.hpp - C++ bridge header for CXX
#pragma once
#include <chainbase/chainbase.hpp>
#include "authority.hpp"
#include "code_object.hpp"
#include "block.hpp"
#include "block_timestamp.hpp"
#include "multi_index_includes.hpp"
#include "resource_limits.hpp"
#include "resource_limits_private.hpp"
#include "account_object.hpp"
#include "permission_link_object.hpp"
#include "global_property_object.hpp"
#include "protocol_state_object.hpp"
#include "database_header_object.hpp"
#include "genesis_state.hpp"
#include "pulse_abi.hpp"
#include "iterator_cache.hpp"
#include "objects.hpp"
#include "name.hpp"
#include "types.hpp"
#include "type_defs.hpp"
#include <pulsevm_ffi/src/types.rs.h>
#include <memory>
#include <rust/cxx.h>
#include <string>

namespace pulsevm { namespace chain {

using UndoSession = ::chainbase::database::session;

struct cpu_limit_result;
struct net_limit_result;

class database_wrapper : public chainbase::database {
public:
    // Inherit constructors
    using chainbase::database::database;
    
    // Add your non-template wrapper methods
    void add_indices() {
        this->add_index<account_index>();
        this->add_index<account_metadata_index>();
        this->add_index<permission_index>();
        this->add_index<permission_usage_index>();
        this->add_index<permission_link_index>();
        this->add_index<key_value_index>();
        this->add_index<index64_index>();
        this->add_index<index128_index>();
        this->add_index<index256_index>();
        this->add_index<global_property_multi_index>();
        this->add_index<dynamic_global_property_multi_index>();
        this->add_index<table_id_multi_index>();
        this->add_index<resource_limits::resource_limits_index>();
        this->add_index<resource_limits::resource_usage_index>();
        this->add_index<resource_limits::resource_limits_state_index>();
        this->add_index<resource_limits::resource_limits_config_index>();
        this->add_index<protocol_state_multi_index>();
        this->add_index<account_ram_correction_index>();
        this->add_index<code_index>();
        this->add_index<database_header_multi_index>();
    }

    void initialize_database(const genesis_state& genesis) {
        // create the database header sigil
        this->create<database_header_object>([&]( auto& header ){
            // nothing to do for now
        });

        auto chain_id = genesis.compute_chain_id();
        this->create<global_property_object>([&genesis,&chain_id](auto& gpo ){
            gpo.configuration = genesis.initial_configuration;
            gpo.wasm_configuration = genesis_state::default_initial_wasm_configuration;
            gpo.chain_id = chain_id;
        });

        this->create<protocol_state_object>([&](auto& pso ){
            pso.num_supported_key_types = config::genesis_num_supported_key_types;
        });
        this->create<dynamic_global_property_object>([](auto&){});
        this->create<permission_object>([](auto&){});  /// reserve perm 0 (used else where)

        const auto& config = this->create<resource_limits::resource_limits_config_object>([](resource_limits::resource_limits_config_object& config){
            // see default settings in the declaration
        });

        const auto& state = this->create<resource_limits::resource_limits_state_object>([&config](resource_limits::resource_limits_state_object& state){
            // see default settings in the declaration

            // start the chain off in a way that it is "congested" aka slow-start
            state.virtual_cpu_limit = config.cpu_limit_parameters.max;
            state.virtual_net_limit = config.net_limit_parameters.max;
        });

        authority system_auth(genesis.initial_key);
        this->create_native_account( genesis.initial_timestamp, config::system_account_name.to_uint64_t(), system_auth, system_auth, true );

        auto empty_authority = authority(1, {}, {});
        auto active_producers_authority = authority(1, {}, {});
        active_producers_authority.accounts.push_back({{config::system_account_name, config::active_name}, 1});

        this->create_native_account( genesis.initial_timestamp, config::null_account_name.to_uint64_t(), empty_authority, empty_authority );
        this->create_native_account( genesis.initial_timestamp, config::producers_account_name.to_uint64_t(), empty_authority, active_producers_authority );
        const auto& active_permission       = this->get_permission({config::producers_account_name, config::active_name});
        const auto& majority_permission     = this->create_permission(
            config::producers_account_name.to_uint64_t(),
            config::majority_producers_permission_name.to_uint64_t(),
            active_permission.id._id,
            active_producers_authority,
            genesis.initial_timestamp
        );
        this->create_permission(
            config::producers_account_name.to_uint64_t(), 
            config::minority_producers_permission_name.to_uint64_t(),
            majority_permission.id._id,
            active_producers_authority,
            genesis.initial_timestamp
        );
    }

    void create_native_account( const fc::time_point& initial_timestamp, u_int64_t account_name, const authority& owner, const authority& active, bool is_privileged = false ) {
        this->create<account_object>([&](auto& a) {
            a.name = name(account_name);
            a.creation_date = initial_timestamp;

            if( account_name == config::system_account_name.to_uint64_t() ) {
                a.abi.assign(pulsevm_abi_bin, sizeof(pulsevm_abi_bin));
            }
        });
        this->create<account_metadata_object>([&](auto & a) {
            a.name = name(account_name);
            a.set_privileged( is_privileged );
        });

        const auto& owner_permission  = this->create_permission(account_name, config::owner_name.to_uint64_t(), 0,
                                                                        owner, initial_timestamp );
        const auto& active_permission = this->create_permission(account_name, config::active_name.to_uint64_t(), owner_permission.id._id,
                                                                        active, initial_timestamp );

        this->initialize_account_resource_limits(account_name);

        int64_t ram_delta = config::overhead_per_account_ram_bytes;
        ram_delta += 2*config::billable_size_v<permission_object>;
        ram_delta += owner_permission.auth.get_billable_size();
        ram_delta += active_permission.auth.get_billable_size();

        this->add_pending_ram_usage(account_name, ram_delta);
        this->verify_account_ram_usage(account_name);
    }

    const account_object& create_account(uint64_t account_name, uint32_t creation_date) {
        return this->create<account_object>([&](auto& a) {
            a.name = name(account_name);
            a.creation_date = block_timestamp_type(creation_date);
        });
    }

    const account_metadata_object& create_account_metadata(uint64_t account_name, bool is_privileged) {
        return this->create<account_metadata_object>([&](auto& a) {
            a.name = name(account_name);
            a.set_privileged(is_privileged);
        });
    }

    const account_object* find_account(uint64_t account_name) const {
        return this->find<account_object, by_name>(name(account_name));
    }

    const account_object& get_account(uint64_t account_name) const {
        return this->get<account_object, by_name>(name(account_name));
    }

    const account_metadata_object* find_account_metadata(uint64_t account_name) const {
        return this->find<account_metadata_object, by_name>(name(account_name));
    }

    void set_privileged( uint64_t account_name, bool is_priv ) {
        const auto& a = this->get<account_metadata_object, by_name>( name(account_name) );
        this->modify( a, [&]( auto& ma ){
            ma.set_privileged( is_priv );
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

    void initialize_account_resource_limits( uint64_t account_name) {
        const auto& limits = this->create<resource_limits::resource_limits_object>([&]( resource_limits::resource_limits_object& bl ) {
            bl.owner = name(account_name);
        });

        const auto& usage = this->create<resource_limits::resource_usage_object>([&]( resource_limits::resource_usage_object& bu ) {
            bu.owner = name(account_name);
        });
    }

    void add_transaction_usage(const rust::Vec<uint64_t>& accounts, uint64_t cpu_usage, uint64_t net_usage, uint32_t time_slot ) {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        const auto& config = this->get<resource_limits::resource_limits_config_object>();

        for( const auto& ac : accounts ) {
            const auto& usage = this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( name(ac) );
            int64_t unused;
            int64_t net_weight;
            int64_t cpu_weight;
            get_account_limits( ac, unused, net_weight, cpu_weight );

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
                            ("n", name(ac))
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
                            ("n", name(ac))
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

    void add_pending_ram_usage( uint64_t account, int64_t ram_delta ) {
        if (ram_delta == 0) {
            return;
        }

        const auto& usage  = this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( name(account) );

        EOS_ASSERT( ram_delta <= 0 || UINT64_MAX - usage.ram_usage >= (uint64_t)ram_delta, transaction_exception,
                    "Ram usage delta would overflow UINT64_MAX");
        EOS_ASSERT(ram_delta >= 0 || usage.ram_usage >= (uint64_t)(-ram_delta), transaction_exception,
                    "Ram usage delta would underflow UINT64_MAX");

        this->modify( usage, [&]( auto& u ) {
            u.ram_usage += ram_delta;
        });
    }

    void verify_account_ram_usage( uint64_t account ) {
        int64_t ram_bytes; int64_t net_weight; int64_t cpu_weight;
        get_account_limits( account, ram_bytes, net_weight, cpu_weight );
        const auto& usage  = this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( name(account) );

        if( ram_bytes >= 0 ) {
            EOS_ASSERT( usage.ram_usage <= static_cast<uint64_t>(ram_bytes), ram_usage_exceeded,
                        "account ${account} has insufficient ram; needs ${needs} bytes has ${available} bytes",
                        ("account", name(account))("needs",usage.ram_usage)("available",ram_bytes)              );
        }
    }

    int64_t get_account_ram_usage( uint64_t account_name ) const {
        return this->get<resource_limits::resource_usage_object,resource_limits::by_owner>( name(account_name) ).ram_usage;
    }

    bool set_account_limits( uint64_t account, int64_t ram_bytes, int64_t net_weight, int64_t cpu_weight) {
        auto find_or_create_pending_limits = [&]() -> const resource_limits::resource_limits_object& {
            const auto* pending_limits = this->find<resource_limits::resource_limits_object, resource_limits::by_owner>( boost::make_tuple(true, name(account)) );
            if (pending_limits == nullptr) {
                const auto& limits = this->get<resource_limits::resource_limits_object, resource_limits::by_owner>( boost::make_tuple(false, name(account)));
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

    void get_account_limits(  uint64_t account, int64_t& ram_bytes, int64_t& net_weight, int64_t& cpu_weight ) const {
        const auto* pending_buo = this->find<resource_limits::resource_limits_object,resource_limits::by_owner>( boost::make_tuple(true, name(account)) );
        if (pending_buo) {
            ram_bytes  = pending_buo->ram_bytes;
            net_weight = pending_buo->net_weight;
            cpu_weight = pending_buo->cpu_weight;
        } else {
            const auto& buo = this->get<resource_limits::resource_limits_object,resource_limits::by_owner>( boost::make_tuple( false, name(account) ) );
            ram_bytes  = buo.ram_bytes;
            net_weight = buo.net_weight;
            cpu_weight = buo.cpu_weight;
        }
    }

    uint64_t get_total_cpu_weight() const {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        return state.total_cpu_weight;
    }

    uint64_t get_total_net_weight() const {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        return state.total_net_weight;
    }

    cpu_limit_result get_account_cpu_limit(uint64_t name, uint32_t greylist_limit = config::maximum_elastic_resource_multiplier) const;

    std::pair<resource_limits::account_resource_limit, bool> get_account_cpu_limit_ex( uint64_t account_name, uint32_t greylist_limit = config::maximum_elastic_resource_multiplier, const std::optional<block_timestamp_type>& current_time = {}) const {
        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        const auto& usage = this->get<resource_limits::resource_usage_object, resource_limits::by_owner>(name(account_name));
        const auto& config = this->get<resource_limits::resource_limits_config_object>();

        int64_t cpu_weight, x, y;
        get_account_limits( account_name, x, y, cpu_weight );
        if( cpu_weight < 0 || state.total_cpu_weight == 0 ) {
            return {{ -1, -1, -1, block_timestamp_type(usage.cpu_usage.last_ordinal), -1 }, false};
        }

        resource_limits::account_resource_limit arl;

        uint128_t window_size = config.account_cpu_usage_average_window;

        bool greylisted = false;
        uint128_t virtual_cpu_capacity_in_window = window_size;
        if( greylist_limit < config::maximum_elastic_resource_multiplier ) {
            uint64_t greylisted_virtual_cpu_limit = config.cpu_limit_parameters.max * greylist_limit;
            if( greylisted_virtual_cpu_limit < state.virtual_cpu_limit ) {
                virtual_cpu_capacity_in_window *= greylisted_virtual_cpu_limit;
                greylisted = true;
            } else {
                virtual_cpu_capacity_in_window *= state.virtual_cpu_limit;
            }
        } else {
            virtual_cpu_capacity_in_window *= state.virtual_cpu_limit;
        }

        uint128_t user_weight     = (uint128_t)cpu_weight;
        uint128_t all_user_weight = (uint128_t)state.total_cpu_weight;

        auto max_user_use_in_window = (virtual_cpu_capacity_in_window * user_weight) / all_user_weight;
        auto cpu_used_in_window  = resource_limits::impl::integer_divide_ceil((uint128_t)usage.cpu_usage.value_ex * window_size, (uint128_t)config::rate_limiting_precision);

        if( max_user_use_in_window <= cpu_used_in_window )
            arl.available = 0;
        else
            arl.available = resource_limits::impl::downgrade_cast<int64_t>(max_user_use_in_window - cpu_used_in_window);

        arl.used = resource_limits::impl::downgrade_cast<int64_t>(cpu_used_in_window);
        arl.max = resource_limits::impl::downgrade_cast<int64_t>(max_user_use_in_window);
        arl.last_usage_update_time = block_timestamp_type(usage.cpu_usage.last_ordinal);
        arl.current_used = arl.used;
        if ( current_time ) {
            if (current_time->slot > usage.cpu_usage.last_ordinal) {
                auto history_usage = usage.cpu_usage;
                history_usage.add(0, current_time->slot, window_size);
                arl.current_used = resource_limits::impl::downgrade_cast<int64_t>(resource_limits::impl::integer_divide_ceil((uint128_t)history_usage.value_ex * window_size, (uint128_t)config::rate_limiting_precision));
            }
        }
        return {arl, greylisted};
    }

    net_limit_result get_account_net_limit(u_int64_t name, uint32_t greylist_limit = config::maximum_elastic_resource_multiplier) const;

    std::pair<resource_limits::account_resource_limit, bool> get_account_net_limit_ex( u_int64_t account_name, uint32_t greylist_limit = config::maximum_elastic_resource_multiplier, const std::optional<block_timestamp_type>& current_time = {}) const {
        const auto& config = this->get<resource_limits::resource_limits_config_object>();
        const auto& state  = this->get<resource_limits::resource_limits_state_object>();
        const auto& usage  = this->get<resource_limits::resource_usage_object, resource_limits::by_owner>(name(account_name));

        int64_t net_weight, x, y;
        get_account_limits( account_name, x, net_weight, y );

        if( net_weight < 0 || state.total_net_weight == 0) {
            return {{ -1, -1, -1, block_timestamp_type(usage.net_usage.last_ordinal), -1 }, false};
        }

        resource_limits::account_resource_limit arl;

        uint128_t window_size = config.account_net_usage_average_window;

        bool greylisted = false;
        uint128_t virtual_network_capacity_in_window = window_size;
        if( greylist_limit < config::maximum_elastic_resource_multiplier ) {
            uint64_t greylisted_virtual_net_limit = config.net_limit_parameters.max * greylist_limit;
            if( greylisted_virtual_net_limit < state.virtual_net_limit ) {
                virtual_network_capacity_in_window *= greylisted_virtual_net_limit;
                greylisted = true;
            } else {
                virtual_network_capacity_in_window *= state.virtual_net_limit;
            }
        } else {
            virtual_network_capacity_in_window *= state.virtual_net_limit;
        }

        uint128_t user_weight     = (uint128_t)net_weight;
        uint128_t all_user_weight = (uint128_t)state.total_net_weight;

        auto max_user_use_in_window = (virtual_network_capacity_in_window * user_weight) / all_user_weight;
        auto net_used_in_window  = resource_limits::impl::integer_divide_ceil((uint128_t)usage.net_usage.value_ex * window_size, (uint128_t)config::rate_limiting_precision);

        if( max_user_use_in_window <= net_used_in_window )
            arl.available = 0;
        else
            arl.available = resource_limits::impl::downgrade_cast<int64_t>(max_user_use_in_window - net_used_in_window);

        arl.used = resource_limits::impl::downgrade_cast<int64_t>(net_used_in_window);
        arl.max = resource_limits::impl::downgrade_cast<int64_t>(max_user_use_in_window);
        arl.last_usage_update_time = block_timestamp_type(usage.net_usage.last_ordinal);
        arl.current_used = arl.used;
        if ( current_time ) {
            if (current_time->slot > usage.net_usage.last_ordinal) {
                auto history_usage = usage.net_usage;
                history_usage.add(0, current_time->slot, window_size);
                arl.current_used = resource_limits::impl::downgrade_cast<int64_t>(resource_limits::impl::integer_divide_ceil((uint128_t)history_usage.value_ex * window_size, (uint128_t)config::rate_limiting_precision));
            }
        }
        return {arl, greylisted};
    }

    void process_account_limit_updates() {
        auto& multi_index = this->get_mutable_index<resource_limits::resource_limits_index>();
        auto& by_owner_index = multi_index.indices().get<resource_limits::by_owner>();

        // convenience local lambda to reduce clutter
        auto update_state_and_value = [](uint64_t &total, int64_t &value, int64_t pending_value, const char* debug_which) -> void {
            if (value > 0) {
                EOS_ASSERT(total >= static_cast<uint64_t>(value), rate_limiting_state_inconsistent, "underflow when reverting old value to ${which}", ("which", debug_which));
                total -= value;
            }

            if (pending_value > 0) {
                EOS_ASSERT(UINT64_MAX - total >= static_cast<uint64_t>(pending_value), rate_limiting_state_inconsistent, "overflow when applying new value to ${which}", ("which", debug_which));
                total += pending_value;
            }

            value = pending_value;
        };

        const auto& state = this->get<resource_limits::resource_limits_state_object>();
        this->modify(state, [&](resource_limits::resource_limits_state_object& rso){
            while(!by_owner_index.empty()) {
                const auto& itr = by_owner_index.lower_bound(boost::make_tuple(true));
                if (itr == by_owner_index.end() || itr->pending!= true) {
                    break;
                }

                const auto& actual_entry = this->get<resource_limits::resource_limits_object, resource_limits::by_owner>(boost::make_tuple(false, itr->owner));
                this->modify(actual_entry, [&](resource_limits::resource_limits_object& rlo){
                    update_state_and_value(rso.total_ram_bytes,  rlo.ram_bytes,  itr->ram_bytes, "ram_bytes");
                    update_state_and_value(rso.total_cpu_weight, rlo.cpu_weight, itr->cpu_weight, "cpu_weight");
                    update_state_and_value(rso.total_net_weight, rlo.net_weight, itr->net_weight, "net_weight");
                });

                multi_index.remove(*itr);
            }
        });
    }

    const table_id_object* find_table( uint64_t code, uint64_t scope, uint64_t table ) const {
        return this->find<table_id_object, by_code_scope_table>(boost::make_tuple(name(code), name(scope), name(table)));
    }

    const table_id_object& get_table( uint64_t code, uint64_t scope, uint64_t table ) {
        return this->get<table_id_object, by_code_scope_table>(boost::make_tuple(name(code), name(scope), name(table)));
    }

    const table_id_object& create_table( uint64_t code, uint64_t scope, uint64_t table, uint64_t payer ) {
        return this->create<table_id_object>([&](table_id_object &t_id){
            t_id.code = name(code);
            t_id.scope = name(scope);
            t_id.table = name(table);
            t_id.payer = name(payer);
        });
    }

    int db_find_i64( uint64_t code, uint64_t scope, uint64_t table, uint64_t id, CxxKeyValueIteratorCache& keyval_cache ) {
        const auto* tab = find_table( code, scope, table );
        if( !tab ) return -1;

        auto table_end_itr = keyval_cache.cache_table( *tab );

        const key_value_object* obj = this->find<key_value_object, by_scope_primary>( boost::make_tuple( tab->id, id ) );
        if( !obj ) return table_end_itr;

        return keyval_cache.add( *obj );
    }

    const key_value_object& create_key_value_object( const table_id_object& tab, uint64_t payer, uint64_t id, rust::Slice<const std::uint8_t> buffer ) {
        auto tableid = tab.id;
        EOS_ASSERT( payer != 0, invalid_table_payer, "must specify a valid account to pay for new record" );
        const auto& obj = this->create<key_value_object>( [&]( auto& o ) {
            o.t_id        = tableid;
            o.primary_key = id;
            o.value.assign( reinterpret_cast<const char*>(buffer.data()), buffer.size() );
            o.payer       = name(payer);
        });

        this->modify( tab, [&]( auto& t ) {
            ++t.count;
        });

        return obj;
    }

    void update_key_value_object( const key_value_object& obj, uint64_t payer, rust::Slice<const std::uint8_t> buffer ) {
        this->modify( obj, [&]( auto& o ) {
            o.value.assign( buffer.data(), buffer.size() );
            o.payer = name(payer);
        });
    }

    void remove_table( const table_id_object& table_obj ) {
        this->remove( table_obj );
    }

    bool is_account( uint64_t account )const {
        return nullptr != this->find<account_object,by_name>( name(account) );
    }

    const permission_object* find_permission( int64_t id ) const {
        return this->find<permission_object, by_id>( permission_object::id_type( id ) );
    }

    const permission_object* find_permission_by_actor_and_permission( uint64_t actor, uint64_t permission ) const {
        EOS_ASSERT( actor != 0 && permission != 0, invalid_permission, "Invalid permission" );
        return this->find<permission_object, by_owner>( boost::make_tuple(name(actor), name(permission)) );
    }

    void unlink_account_code(
        const code_object& old_code_entry
    ) {
        if( old_code_entry.code_ref_count == 1 ) {
            this->remove(old_code_entry);
        } else {
            this->modify(old_code_entry, [](code_object& o) {
                --o.code_ref_count;
            });
        }
    }

    void update_account_code(
        const account_metadata_object& account,
        rust::Slice<const std::uint8_t> new_code, 
        uint32_t head_block_num, 
        const time_point& pending_block_time,
        const digest_type& code_hash, 
        uint8_t vm_type, 
        uint8_t vm_version
    ) {
        if( new_code.size() > 0 ) {
            const code_object* new_code_entry = this->find<code_object, by_code_hash>( boost::make_tuple(code_hash, vm_type, vm_version) );

            if( new_code_entry ) {
                this->modify(*new_code_entry, [&](code_object& o) {
                    ++o.code_ref_count;
                });
            } else {
                this->create<code_object>([&](code_object& o) {
                    o.code_hash = code_hash;
                    o.code.assign( new_code.data(), new_code.size() );
                    o.code_ref_count = 1;
                    o.first_block_used = head_block_num + 1;
                    o.vm_type = vm_type;
                    o.vm_version = vm_version;
                });
            }
        }

        this->modify( account, [&]( auto& a ) {
            a.code_sequence += 1;
            a.code_hash = code_hash;
            a.vm_type = vm_type;
            a.vm_version = vm_version;
            a.last_code_update = pending_block_time;
        });
    }

    void update_account_abi(
        const account_object& account,
        const account_metadata_object& account_metadata,
        rust::Slice<const std::uint8_t> abi
    ) {
        this->modify( account_metadata, [&]( auto& a ) {
            a.abi_sequence += 1;
        });

        this->modify( account, [&]( auto& a ) {
            a.abi.assign(abi.data(), abi.size());
        });
    }

    const code_object& get_code_object_by_hash(
        const digest_type& code_hash,
        uint8_t vm_type,
        uint8_t vm_version
    ) const {
        return this->get<code_object, by_code_hash>( boost::make_tuple(code_hash, vm_type, vm_version) );
    }

    int64_t delete_auth(uint64_t account, uint64_t permission_name) {
        { // Check for links to this permission
            const auto& index = this->get_index<permission_link_index, by_permission_name>();
            auto range = index.equal_range(boost::make_tuple(name(account), name(permission_name)));
            EOS_ASSERT(range.first == range.second, action_validate_exception,
                        "Cannot delete a linked authority. Unlink the authority first. This authority is linked to ${code}::${type}.",
                        ("code", range.first->code)("type", range.first->message_type));
        }

        const auto& permission = this->get_permission({name(account), name(permission_name)});
        int64_t old_size = config::billable_size_v<permission_object> + permission.auth.get_billable_size();

        this->remove_permission( permission );

        return old_size;
    }

    int64_t link_auth( uint64_t account_name,  uint64_t code_name, uint64_t requirement_name, uint64_t requirement_type ) {
        const auto *account = this->find<account_object, by_name>(name(account_name));
        EOS_ASSERT(account != nullptr, account_query_exception, "Failed to retrieve account: ${account}", ("account", name(account_name)));
        const auto *code = this->find<account_object, by_name>(name(code_name));
        EOS_ASSERT(code != nullptr, account_query_exception, "Failed to retrieve code for account: ${account}", ("account", name(code_name)));

        if( name(requirement_name) != config::any_name ) {
            const permission_object* permission = this->find<permission_object, by_owner>(
                boost::make_tuple( name(account_name), name(requirement_name) )
            );

            EOS_ASSERT(permission != nullptr, permission_query_exception, "Failed to retrieve permission: ${permission}", ("permission", name(requirement_name)));
        }

        auto link_key = boost::make_tuple(name(account_name), name(code_name), name(requirement_type));
        auto link = this->find<permission_link_object, by_action_name>(link_key);

        if( link ) {
            EOS_ASSERT(link->required_permission != name(requirement_name), action_validate_exception, "Attempting to update required authority, but new requirement is same as old");
            this->modify(*link, [requirement = name(requirement_name)](permission_link_object& link) {
                link.required_permission = requirement;
            });
        } else {
            const auto& l =  this->create<permission_link_object>([&requirement_name, &account_name, &code_name, &requirement_type](permission_link_object& link) {
                link.account = name(account_name);
                link.code = name(code_name);
                link.message_type = name(requirement_type);
                link.required_permission = name(requirement_name);
            });

            return (int64_t)(config::billable_size_v<permission_link_object>);
        }

        return 0;
    }

    int64_t unlink_auth( uint64_t account_name,  uint64_t code_name,  uint64_t requirement_type ) {
        auto link_key = boost::make_tuple(name(account_name), name(code_name), name(requirement_type));
        auto link = this->find<permission_link_object, by_action_name>(link_key);

        EOS_ASSERT(link != nullptr, action_validate_exception, "No authority link found for ${account} to ${code}::${type}",
                    ("account", name(account_name))("code", name(code_name))("type", name(requirement_type)));

        this->remove(*link);

        return -(int64_t)(config::billable_size_v<permission_link_object>);
    }

    void remove_permission( const permission_object& permission ) {
        const auto& index = this->get_index<permission_index, by_parent>();
        auto range = index.equal_range(permission.id);
        EOS_ASSERT( range.first == range.second, action_validate_exception,
                    "Cannot remove a permission which has children. Remove the children first.");

        this->get_mutable_index<permission_usage_index>().remove_object( permission.usage_id._id );
        this->remove( permission );
    }

    const permission_object& create_permission(
        uint64_t account,
        uint64_t permission_name,
        uint64_t parent,
        const Authority& a,
        const time_point& creation_time
    ) {
        authority auth;
        auth.threshold = a.threshold;
        auth.keys.reserve(a.keys.size());
        auth.accounts.reserve(a.accounts.size());
        auth.waits.reserve(a.waits.size());
        for (const auto& k : a.keys) {
            auth.keys.emplace_back( key_weight{ *k.key, k.weight } );
        }
        for (const auto& ac : a.accounts) {
            auth.accounts.emplace_back( permission_level_weight{ { name(ac.permission.actor), name(ac.permission.permission) }, ac.weight } );
        }
        for (const auto& w : a.waits) {
            auth.waits.emplace_back( wait_weight{ w.wait_sec, w.weight } );
        }

        for(const key_weight& k: auth.keys)
            EOS_ASSERT(k.key.which() < this->get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
            "Unactivated key type used when creating permission");

        const auto& perm_usage = this->create<permission_usage_object>([&](auto& p) {
            p.last_used = creation_time;
        });

        const auto& perm = this->create<permission_object>([&](auto& p) {
            p.usage_id     = perm_usage.id;
            p.parent       = permission_object::id_type(parent);
            p.owner        = name(account);
            p.perm_name    = name(permission_name);
            p.last_updated = creation_time;
            p.auth         = std::move(auth);
        });

        return perm;
    }

    const permission_object& create_permission(
        uint64_t account,
        uint64_t permission_name,
        uint64_t parent,
        const authority& auth,
        const time_point& creation_time
    ) {
        for(const key_weight& k: auth.keys)
            EOS_ASSERT(k.key.which() < this->get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
            "Unactivated key type used when creating permission");

        const auto& perm_usage = this->create<permission_usage_object>([&](auto& p) {
            p.last_used = creation_time;
        });

        const auto& perm = this->create<permission_object>([&](auto& p) {
            p.usage_id     = perm_usage.id;
            p.parent       = permission_object::id_type(parent);
            p.owner        = name(account);
            p.perm_name    = name(permission_name);
            p.last_updated = creation_time;
            p.auth         = std::move(auth);
        });

        return perm;
    }

    void modify_permission( const permission_object& permission, const Authority& a, const fc::time_point& pending_block_time ) {
        authority auth;
        auth.threshold = a.threshold;
        auth.keys.reserve(a.keys.size());
        auth.accounts.reserve(a.accounts.size());
        auth.waits.reserve(a.waits.size());
        for (const auto& k : a.keys) {
            auth.keys.emplace_back( key_weight{ *k.key, k.weight } );
        }
        for (const auto& ac : a.accounts) {
            auth.accounts.emplace_back( permission_level_weight{ { name(ac.permission.actor), name(ac.permission.permission) }, ac.weight } );
        }
        for (const auto& w : a.waits) {
            auth.waits.emplace_back( wait_weight{ w.wait_sec, w.weight } );
        }

        for(const key_weight& k: auth.keys)
            EOS_ASSERT(k.key.which() < this->get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
            "Unactivated key type used when modifying permission");

        this->modify( permission, [&](permission_object& po) {
            po.auth = auth;
            po.last_updated = pending_block_time;
        });
    }

    const permission_object& get_permission( const permission_level& level ) const { 
        try {
            EOS_ASSERT( !level.actor.empty() && !level.permission.empty(), invalid_permission, "Invalid permission" );
            return this->get<permission_object, by_owner>( boost::make_tuple(level.actor,level.permission) );
        } EOS_RETHROW_EXCEPTIONS( chain::permission_query_exception, "Failed to retrieve permission: ${level}", ("level", level) ) 
    }

    const name* lookup_linked_permission(
        u_int64_t authorizer_account,
        u_int64_t scope,
        u_int64_t act_name
    )const {
      try {
         // First look up a specific link for this message act_name
         auto key = boost::make_tuple(name(authorizer_account), name(scope), name(act_name));
         auto link = this->find<permission_link_object, by_action_name>(key);
         // If no specific link found, check for a contract-wide default
         if (link == nullptr) {
            boost::get<2>(key) = {};
            link = this->find<permission_link_object, by_action_name>(key);
         }

         // If no specific or default link found, use active permission
         if (link != nullptr) {
            return &link->required_permission;
         }
         return nullptr;
      } FC_CAPTURE_AND_RETHROW((authorizer_account)(scope)(act_name))
   }

    const dynamic_global_property_object& get_dynamic_global_properties() const {
        return this->get<dynamic_global_property_object>();
    }

    const global_property_object& get_global_properties() const {
        return this->get<global_property_object>();
    }

    uint64_t next_recv_sequence( const account_metadata_object& receiver_account ) {
        this->modify( receiver_account, [&]( auto& ra ) {
            ++ra.recv_sequence;
        });

        return receiver_account.recv_sequence;
    }

    uint64_t next_auth_sequence( u_int64_t actor ) {
        const auto& amo = this->get<account_metadata_object,by_name>( name(actor) );
        this->modify( amo, [&](auto& am ){
            ++am.auth_sequence;
        });
        return amo.auth_sequence;
    }

    uint64_t next_global_sequence() {
        const auto& p = this->get_dynamic_global_properties();
        
        this->modify( p, [&]( auto& dgp ) {
            ++dgp.global_action_sequence;
        });

        return p.global_action_sequence;
    }

    int64_t db_remove_i64( iterator_cache<key_value_object>& keyval_cache, int iterator, u_int64_t receiver ) {
        const key_value_object& obj = keyval_cache.get( iterator );
        const auto& table_obj = keyval_cache.get_table( obj.t_id );
        EOS_ASSERT( table_obj.code == name(receiver), table_access_violation, "db access violation" );
        auto delta = -(obj.value.size() + config::billable_size_v<key_value_object>);

        this->modify( table_obj, [&]( auto& t ) {
            --t.count;
        });
        this->remove( obj );

        if (table_obj.count == 0) {
            this->remove_table(table_obj);
        }

        keyval_cache.remove( iterator );

        return delta;
    }

    int db_next_i64( iterator_cache<key_value_object>& keyval_cache, int iterator, uint64_t& primary ) {
        if( iterator < -1 ) return -1; // cannot increment past end iterator of table

        const auto& obj = keyval_cache.get( iterator ); // Check for iterator != -1 happens in this call
        const auto& idx = this->get_index<key_value_index, by_scope_primary>();

        auto itr = idx.iterator_to( obj );
        ++itr;

        if( itr == idx.end() || itr->t_id != obj.t_id ) return keyval_cache.get_end_iterator_by_table_id(obj.t_id);

        primary = itr->primary_key;
        return keyval_cache.add( *itr );
    }

    int db_previous_i64( iterator_cache<key_value_object>& keyval_cache, int iterator, uint64_t& primary ) {
        const auto& idx = this->get_index<key_value_index, by_scope_primary>();

        if( iterator < -1 ) // is end iterator
        {
            auto tab = keyval_cache.find_table_by_end_iterator(iterator);
            EOS_ASSERT( tab, invalid_table_iterator, "not a valid end iterator" );

            auto itr = idx.upper_bound(tab->id);
            if( idx.begin() == idx.end() || itr == idx.begin() ) return -1; // Empty table

            --itr;

            if( itr->t_id != tab->id ) return -1; // Empty table

            primary = itr->primary_key;
            return keyval_cache.add(*itr);
        }

        const auto& obj = keyval_cache.get(iterator); // Check for iterator != -1 happens in this call

        auto itr = idx.iterator_to(obj);
        if( itr == idx.begin() ) return -1; // cannot decrement past beginning iterator of table

        --itr;

        if( itr->t_id != obj.t_id ) return -1; // cannot decrement past beginning iterator of table

        primary = itr->primary_key;
        return keyval_cache.add(*itr);
    }

    int db_end_i64( iterator_cache<key_value_object>& keyval_cache,  uint64_t code,  uint64_t scope,  uint64_t table ) {
        const auto* tab = this->find_table( code, scope, table );
        if( !tab ) return -1;

        return keyval_cache.cache_table( *tab );
    }

    int db_lowerbound_i64( iterator_cache<key_value_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, uint64_t id ) {
        const auto* tab = this->find_table( code, scope, table );
        if( !tab ) return -1;

        auto table_end_itr = keyval_cache.cache_table( *tab );

        const auto& idx = this->get_index<key_value_index, by_scope_primary>();
        auto itr = idx.lower_bound( boost::make_tuple( tab->id, id ) );
        if( itr == idx.end() ) return table_end_itr;
        if( itr->t_id != tab->id ) return table_end_itr;

        return keyval_cache.add( *itr );
    }

    int db_upperbound_i64( iterator_cache<key_value_object>& keyval_cache, uint64_t code, uint64_t scope, uint64_t table, uint64_t id ) {
        const auto* tab = this->find_table( code, scope, table );
        if( !tab ) return -1;

        auto table_end_itr = keyval_cache.cache_table( *tab );

        const auto& idx = this->get_index<key_value_index, by_scope_primary>();
        auto itr = idx.upper_bound( boost::make_tuple( tab->id, id ) );
        if( itr == idx.end() ) return table_end_itr;
        if( itr->t_id != tab->id ) return table_end_itr;

        return keyval_cache.add( *itr );
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

// Forward declare the enum from the bridge
enum class DatabaseOpenFlags : uint32_t;

// Bridge function to open database
std::unique_ptr<database_wrapper> open_database(
    rust::Str path,
    DatabaseOpenFlags flags,
    uint64_t size
);

} }