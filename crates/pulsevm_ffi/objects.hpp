#pragma once
#include <fc/io/datastream.hpp>
#include "exceptions.hpp"
#include "types.hpp"
#include "multi_index_includes.hpp"

namespace pulsevm::chain {

    class account_object : public chainbase::object<account_object_type, account_object> {
        OBJECT_CTOR(account_object,(abi))

        id_type              id;
        account_name         name; //< name should not be changed within a chainbase modifier lambda
        block_timestamp_type creation_date;
        shared_blob          abi;

        void set_abi( const pulsevm::chain::abi_def& a ) {
            abi.resize_and_fill( fc::raw::pack_size( a ), [&a](char* data, std::size_t size) {
            fc::datastream<char*> ds( data, size );
            fc::raw::pack( ds, a );
            });
        }

        pulsevm::chain::abi_def get_abi()const {
            pulsevm::chain::abi_def a;
            EOS_ASSERT( abi.size() != 0, abi_not_found_exception, "No ABI set on account ${n}", ("n",name) );

            fc::datastream<const char*> ds( abi.data(), abi.size() );
            fc::raw::unpack( ds, a );
            return a;
        }
    };
    using account_id_type = account_object::id_type;

    struct by_name;
    using account_index = chainbase::shared_multi_index_container<
        account_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<account_object, account_object::id_type, &account_object::id>>,
            ordered_unique<tag<by_name>, member<account_object, account_name, &account_object::name>>
        >
    >;

    class account_metadata_object : public chainbase::object<account_metadata_object_type, account_metadata_object>
    {
        OBJECT_CTOR(account_metadata_object);

        enum class flags_fields : uint32_t {
            privileged = 1
        };

        id_type               id;
        account_name          name; //< name should not be changed within a chainbase modifier lambda
        uint64_t              recv_sequence = 0;
        uint64_t              auth_sequence = 0;
        uint64_t              code_sequence = 0;
        uint64_t              abi_sequence  = 0;
        digest_type           code_hash;
        time_point            last_code_update;
        uint32_t              flags = 0;
        uint8_t               vm_type = 0;
        uint8_t               vm_version = 0;

        bool is_privileged()const { return has_field( flags, flags_fields::privileged ); }

        void set_privileged( bool privileged )  {
            flags = set_field( flags, flags_fields::privileged, privileged );
        }
    };

    struct by_name;
    using account_metadata_index = chainbase::shared_multi_index_container<
        account_metadata_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<account_metadata_object, account_metadata_object::id_type, &account_metadata_object::id>>,
            ordered_unique<tag<by_name>, member<account_metadata_object, account_name, &account_metadata_object::name>>
        >
    >;

    class account_ram_correction_object : public chainbase::object<account_ram_correction_object_type, account_ram_correction_object>
    {
        OBJECT_CTOR(account_ram_correction_object);

        id_type      id;
        account_name name; //< name should not be changed within a chainbase modifier lambda
        uint64_t     ram_correction = 0;
    };

    struct by_name;
    using account_ram_correction_index = chainbase::shared_multi_index_container<
        account_ram_correction_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<account_ram_correction_object, account_ram_correction_object::id_type, &account_ram_correction_object::id>>,
            ordered_unique<tag<by_name>, member<account_ram_correction_object, account_name, &account_ram_correction_object::name>>
        >
    >;

    class permission_usage_object : public chainbase::object<permission_usage_object_type, permission_usage_object> {
        OBJECT_CTOR(permission_usage_object)

        id_type           id;
        time_point        last_used;   ///< when this permission was last used
    };

    struct by_account_permission;
    using permission_usage_index = chainbase::shared_multi_index_container<
        permission_usage_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<permission_usage_object, permission_usage_object::id_type, &permission_usage_object::id>>
        >
    >;

    class permission_object : public chainbase::object<permission_object_type, permission_object> {
        OBJECT_CTOR(permission_object, (auth))

        id_type                           id;
        permission_usage_object::id_type  usage_id;
        id_type                           parent; ///< parent permission
        name                              owner; ///< the account this permission belongs to (should not be changed within a chainbase modifier lambda)
        name                              name; ///< human-readable name for the permission (should not be changed within a chainbase modifier lambda)
        time_point                        last_updated; ///< the last time this authority was updated
        shared_authority                  auth; ///< authority required to execute this permission

        int64_t get_id()const { return id._id; }
        int64_t get_parent_id()const { return parent._id; }
    };
    
    struct by_parent;
    struct by_owner;
    struct by_name;
    using permission_index = chainbase::shared_multi_index_container<
        permission_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<permission_object, permission_object::id_type, &permission_object::id>>,
            ordered_unique<tag<by_parent>,
                composite_key<permission_object,
                member<permission_object, permission_object::id_type, &permission_object::parent>,
                member<permission_object, permission_object::id_type, &permission_object::id>
                >
            >,
            ordered_unique<tag<by_owner>,
                composite_key<permission_object,
                member<permission_object, name, &permission_object::owner>,
                member<permission_object, name, &permission_object::name>
                >
            >,
            ordered_unique<tag<by_name>,
                composite_key<permission_object,
                member<permission_object, name, &permission_object::name>,
                member<permission_object, permission_object::id_type, &permission_object::id>
                >
            >
        >
    >;

    class permission_link_object : public chainbase::object<permission_link_object_type, permission_link_object> {
        OBJECT_CTOR(permission_link_object)

        id_type        id;
        /// The account which is defining its permission requirements
        name       account;
        /// The contract which account requires @ref required_permission to invoke
        name       code; /// TODO: rename to scope
        /// The message type which account requires @ref required_permission to invoke
        /// May be empty; if so, it sets a default @ref required_permission for all messages to @ref code
        name       message_type;
        /// The permission level which @ref account requires for the specified message types
        /// all of the above fields should not be changed within a chainbase modifier lambda
        name       required_permission;
    };

    struct by_action_name;
    struct by_permission_name;
    using permission_link_index = chainbase::shared_multi_index_container<
        permission_link_object,
        indexed_by<
            ordered_unique<tag<by_id>,
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, permission_link_object::id_type, id)
            >,
            ordered_unique<tag<by_action_name>,
                composite_key<permission_link_object,
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, name, account),
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, name, code),
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, name, message_type)
                >
            >,
            ordered_unique<tag<by_permission_name>,
                composite_key<permission_link_object,
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, name, account),
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, name, required_permission),
                BOOST_MULTI_INDEX_MEMBER(permission_link_object, permission_link_object::id_type, id)
                >
            >
        >
    >;

    class code_object : public chainbase::object<code_object_type, code_object> {
        OBJECT_CTOR(code_object, (code))

        id_type      id;
        digest_type  code_hash; //< code_hash should not be changed within a chainbase modifier lambda
        shared_blob  code;
        uint64_t     code_ref_count;
        uint32_t     first_block_used;
        uint8_t      vm_type = 0; //< vm_type should not be changed within a chainbase modifier lambda
        uint8_t      vm_version = 0; //< vm_version should not be changed within a chainbase modifier lambda
    };

    struct by_code_hash;
    using code_index = chainbase::shared_multi_index_container<
        code_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<code_object, code_object::id_type, &code_object::id>>,
            ordered_unique<tag<by_code_hash>,
            composite_key< code_object,
                member<code_object, digest_type, &code_object::code_hash>,
                member<code_object, uint8_t,     &code_object::vm_type>,
                member<code_object, uint8_t,     &code_object::vm_version>
            >
            >
        >
    >;

    class table_id_object : public chainbase::object<table_id_object_type, table_id_object> {
        OBJECT_CTOR(table_id_object)

        id_type        id;
        name     code;  //< code should not be changed within a chainbase modifier lambda
        name     scope; //< scope should not be changed within a chainbase modifier lambda
        name     table; //< table should not be changed within a chainbase modifier lambda
        name     payer;
        uint32_t       count = 0; /// the number of elements in the table
    };

    struct by_code_scope_table;

    using table_id_multi_index = chainbase::shared_multi_index_container<
        table_id_object,
        indexed_by<
            ordered_unique<tag<by_id>,
            member<table_id_object, table_id_object::id_type, &table_id_object::id>
            >,
            ordered_unique<tag<by_code_scope_table>,
            composite_key< table_id_object,
                member<table_id_object, name, &table_id_object::code>,
                member<table_id_object, name,   &table_id_object::scope>,
                member<table_id_object, name,   &table_id_object::table>
            >
            >
        >
    >;

    using table_id = table_id_object::id_type;

    struct by_scope_primary;
    struct by_scope_secondary;
    struct by_scope_tertiary;


    struct key_value_object : public chainbase::object<key_value_object_type, key_value_object> {
        OBJECT_CTOR(key_value_object, (value))

        typedef uint64_t key_type;
        static const int number_of_keys = 1;

        id_type               id;
        table_id              t_id; //< t_id should not be changed within a chainbase modifier lambda
        uint64_t              primary_key; //< primary_key should not be changed within a chainbase modifier lambda
        name          payer;
        shared_blob           value;
    };

    using key_value_index = chainbase::shared_multi_index_container<
        key_value_object,
        indexed_by<
            ordered_unique<tag<by_id>, member<key_value_object, key_value_object::id_type, &key_value_object::id>>,
            ordered_unique<tag<by_scope_primary>,
            composite_key< key_value_object,
                member<key_value_object, table_id, &key_value_object::t_id>,
                member<key_value_object, uint64_t, &key_value_object::primary_key>
            >,
            composite_key_compare< std::less<table_id>, std::less<uint64_t> >
            >
        >
    >;
}

CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::account_object, pulsevm::chain::account_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::account_metadata_object, pulsevm::chain::account_metadata_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::account_ram_correction_object, pulsevm::chain::account_ram_correction_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::permission_object, pulsevm::chain::permission_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::permission_usage_object, pulsevm::chain::permission_usage_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::permission_link_object, pulsevm::chain::permission_link_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::code_object, pulsevm::chain::code_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::table_id_object, pulsevm::chain::table_id_multi_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::key_value_object, pulsevm::chain::key_value_index)

FC_REFLECT(pulsevm::chain::account_object, (name)(creation_date)(abi))
FC_REFLECT(pulsevm::chain::account_metadata_object, (name)(recv_sequence)(auth_sequence)(code_sequence)(abi_sequence)
                                                  (code_hash)(last_code_update)(flags)(vm_type)(vm_version))
FC_REFLECT(pulsevm::chain::account_ram_correction_object, (name)(ram_correction))
FC_REFLECT(pulsevm::chain::permission_object, (usage_id)(parent)(owner)(name)(last_updated)(auth))
FC_REFLECT(pulsevm::chain::permission_usage_object, (last_used))
FC_REFLECT(pulsevm::chain::permission_link_object, (account)(code)(message_type)(required_permission))
FC_REFLECT(pulsevm::chain::code_object, (code_hash)(code)(code_ref_count)(first_block_used)(vm_type)(vm_version))
FC_REFLECT(pulsevm::chain::table_id_object, (code)(scope)(table)(payer)(count) )
FC_REFLECT(pulsevm::chain::key_value_object, (primary_key)(payer)(value) )