#pragma once
#include "authority.hpp"
#include "database_utils.hpp"
#include "multi_index_includes.hpp"

namespace pulsevm { namespace chain {

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
      name                              perm_name; ///< human-readable name for the permission (should not be changed within a chainbase modifier lambda)
      time_point                        last_updated; ///< the last time this authority was updated
      shared_authority                  auth; ///< authority required to execute this permission

      int64_t get_id() const { return id._id; }
      int64_t get_parent_id() const { return parent._id; }
      const name& get_owner() const { return owner; }
      const name& get_name() const { return perm_name; }
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
               member<permission_object, name, &permission_object::perm_name>
            >
         >,
         ordered_unique<tag<by_name>,
            composite_key<permission_object,
               member<permission_object, name, &permission_object::perm_name>,
               member<permission_object, permission_object::id_type, &permission_object::id>
            >
         >
      >
   >;

   namespace config {
      template<>
      struct billable_size<permission_object> { // Also counts memory usage of the associated permission_usage_object
         static const uint64_t  overhead = 5 * overhead_per_row_per_index_ram_bytes; ///< 5 indices 2x internal ID, parent, owner, name
         static const uint64_t  value = (config::billable_size_v<shared_authority> + 64) + overhead;  ///< fixed field size + overhead
      };
   }
} } // pulsevm::chain

CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::permission_object, pulsevm::chain::permission_index)
CHAINBASE_SET_INDEX_TYPE(pulsevm::chain::permission_usage_object, pulsevm::chain::permission_usage_index)

FC_REFLECT(pulsevm::chain::permission_object, (usage_id)(parent)(owner)(perm_name)(last_updated)(auth))
FC_REFLECT(pulsevm::chain::permission_usage_object, (last_used))
