// chainbase_bridge.hpp - C++ bridge header for CXX
#pragma once
#include <chainbase/chainbase.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <memory>
#include <rust/cxx.h>
#include <string>

#define OBJECT_CTOR1(NAME) \
    public: \
    template<typename Constructor> \
    NAME(Constructor&& c, chainbase::constructor_tag) \
    { c(*this); }
#define OBJECT_CTOR2_MACRO(x, y, field) ,field()
#define OBJECT_CTOR2(NAME, FIELDS) \
    public: \
    template<typename Constructor> \
    NAME(Constructor&& c, chainbase::constructor_tag)            \
    : id(0) BOOST_PP_SEQ_FOR_EACH(OBJECT_CTOR2_MACRO, _, FIELDS) \
    { c(*this); }
#define OBJECT_CTOR(...) BOOST_PP_OVERLOAD(OBJECT_CTOR, __VA_ARGS__)(__VA_ARGS__)

namespace bmi = boost::multi_index;
using bmi::indexed_by;
using bmi::ordered_unique;
using bmi::ordered_non_unique;
using bmi::composite_key;
using bmi::member;
using bmi::const_mem_fun;
using bmi::tag;
using bmi::composite_key_compare;

struct by_id;
enum object_type
{
    null_object_type = 0,
    account_object_type,
    account_metadata_object_type,
    permission_object_type,
    permission_usage_object_type,
    permission_link_object_type,
    UNUSED_action_code_object_type,
    key_value_object_type,
    index64_object_type,
    index128_object_type,
    index256_object_type,
    index_double_object_type,
    index_long_double_object_type,
    global_property_object_type,
    dynamic_global_property_object_type,
    block_summary_object_type,
    transaction_object_type,
    generated_transaction_object_type,
    UNUSED_producer_object_type,
    UNUSED_chain_property_object_type,
    account_control_history_object_type,     ///< Defined by history_plugin
    UNUSED_account_transaction_history_object_type,
    UNUSED_transaction_history_object_type,
    public_key_history_object_type,          ///< Defined by history_plugin
    UNUSED_balance_object_type,
    UNUSED_staked_balance_object_type,
    UNUSED_producer_votes_object_type,
    UNUSED_producer_schedule_object_type,
    UNUSED_proxy_vote_object_type,
    UNUSED_scope_sequence_object_type,
    table_id_object_type,
    resource_limits_object_type,
    resource_usage_object_type,
    resource_limits_state_object_type,
    resource_limits_config_object_type,
    account_history_object_type,              ///< Defined by history_plugin
    action_history_object_type,               ///< Defined by history_plugin
    reversible_block_object_type,
    protocol_state_object_type,
    account_ram_correction_object_type,
    code_object_type,
    database_header_object_type,
    OBJECT_TYPE_COUNT ///< Sentry value which contains the number of different object types
};

class account_object : public chainbase::object<account_object_type, account_object> {
    OBJECT_CTOR(account_object)

    id_type              id;
    u_int64_t            name; //< name should not be changed within a chainbase modifier lambda
};

using account_id_type = account_object::id_type;

struct by_name;
using account_index = chainbase::shared_multi_index_container<
    account_object,
    indexed_by<
        ordered_unique<tag<by_id>, member<account_object, account_object::id_type, &account_object::id>>
    >
>;

CHAINBASE_SET_INDEX_TYPE(account_object, account_index)

class database_wrapper : public chainbase::database {
public:
    // Inherit constructors
    using chainbase::database::database;
    
    // Add your non-template wrapper methods
    void add_indices() {
        this->add_index<account_index>();
    }

    void add_account() {
        auto account = this->create<account_object>([&](auto& a) {
            a.name = 1;
        });
    }

    account_object get_account() {
        return this->get<account_object, by_id>(account_id_type(0));
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
std::unique_ptr<::chainbase::database::session> start_undo_session(chainbase::database& db);