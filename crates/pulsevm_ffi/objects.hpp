#pragma once
#include <pulsevm/chain/account_object.hpp>
#include <pulsevm/chain/code_object.hpp>
#include <pulsevm/chain/permission_object.hpp>
#include <pulsevm/chain/permission_link_object.hpp>
#include <pulsevm/chain/contract_table_objects.hpp>
#include <pulsevm/chain/global_property_object.hpp>

namespace pulsevm { namespace chain {

    using AccountObject = pulsevm::chain::account_object;
    using AccountMetadataObject = pulsevm::chain::account_metadata_object;
    using CodeObject = pulsevm::chain::code_object;
    using PermissionObject = pulsevm::chain::permission_object;
    using PermissionLinkObject = pulsevm::chain::permission_link_object;
    using PermissionUsageObject = pulsevm::chain::permission_usage_object;
    using TableObject = pulsevm::chain::table_id_object;
    using TableId = pulsevm::chain::table_id;
    using KeyValueObject = pulsevm::chain::key_value_object;
    using GlobalPropertyObject = pulsevm::chain::global_property_object;

} } // pulsevm::chain