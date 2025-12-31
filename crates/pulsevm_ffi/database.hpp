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

class database_wrapper : public chainbase::database {
public:
    // Inherit constructors
    using chainbase::database::database;
    
    // Add your non-template wrapper methods
    void add_indices() {
        this->add_index<pulsevm::chain::account_index>();
        this->add_index<pulsevm::chain::resource_limits::resource_limits_index>();
        this->add_index<pulsevm::chain::resource_limits::resource_usage_index>();
        this->add_index<pulsevm::chain::resource_limits::resource_limits_state_index>();
        this->add_index<pulsevm::chain::resource_limits::resource_limits_config_index>();
    }

    void add_account(u_int64_t account_name) {
        auto account = this->create<pulsevm::chain::account_object>([&](auto& a) {
            a.name = pulsevm::chain::account_name(account_name);
        });
    }

    void initialize_resource_limits() {
        const auto& config = this->create<pulsevm::chain::resource_limits::resource_limits_config_object>([](pulsevm::chain::resource_limits::resource_limits_config_object& config){
            // see default settings in the declaration
        });

        const auto& state = this->create<pulsevm::chain::resource_limits::resource_limits_state_object>([&config](pulsevm::chain::resource_limits::resource_limits_state_object& state){
            // see default settings in the declaration

            // start the chain off in a way that it is "congested" aka slow-start
            state.virtual_cpu_limit = config.cpu_limit_parameters.max;
            state.virtual_net_limit = config.net_limit_parameters.max;
        });
    }

    void initialize_account_resource_limits(u_int64_t account_name) {
        const auto& limits = this->create<pulsevm::chain::resource_limits::resource_limits_object>([&]( pulsevm::chain::resource_limits::resource_limits_object& bl ) {
            bl.owner = pulsevm::chain::account_name(account_name);
        });

        const auto& usage = this->create<pulsevm::chain::resource_limits::resource_usage_object>([&]( pulsevm::chain::resource_limits::resource_usage_object& bu ) {
            bu.owner = pulsevm::chain::account_name(account_name);
        });
    }

    std::unique_ptr<pulsevm::chain::account_object> get_account() {
        return std::make_unique<pulsevm::chain::account_object>(this->get<pulsevm::chain::account_object, by_id>(pulsevm::chain::account_id_type(0)));
    }

    std::unique_ptr<chainbase::database::session> create_undo_session(bool enabled) {
        return std::make_unique<chainbase::database::session>(this->start_undo_session(enabled));
    }
};

// Forward declare the enum from the bridge
enum class DatabaseOpenFlags : uint32_t;

// Bridge function to open database
std::unique_ptr<database_wrapper> open_database(
    rust::Str path,
    DatabaseOpenFlags flags,
    uint64_t size
);

// Wrapper methods for database operations
void close(::chainbase::database& db);
void flush(::chainbase::database& db);
void undo(::chainbase::database& db);
void commit(::chainbase::database& db, int64_t revision);
int64_t revision(const ::chainbase::database& db);