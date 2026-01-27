#include "database.hpp"
#include <pulsevm_ffi/src/bridge.rs.h>
#include <filesystem>

namespace pulsevm::chain {

std::unique_ptr<pulsevm::chain::database_wrapper> open_database(
    rust::Str path,
    DatabaseOpenFlags flags,
    uint64_t size
) {
    // Convert rust::Str to std::filesystem::path
    std::string path_str(path.data(), path.size());
    std::filesystem::path fs_path(path_str);
    
    // Convert flags enum to chainbase flags
    chainbase::database::open_flags db_flags;
    if (static_cast<uint32_t>(flags) == 0) {
        db_flags = chainbase::database::open_flags::read_only;
    } else {
        db_flags = chainbase::database::open_flags::read_write;
    }
    
    // Create and return database
    return std::make_unique<pulsevm::chain::database_wrapper>(fs_path, db_flags, size);
}

CpuLimitResult database_wrapper::get_account_cpu_limit(uint64_t name, uint32_t greylist_limit) const {
    auto [arl, greylisted] = get_account_cpu_limit_ex(name, greylist_limit);
    return {arl.available, greylisted};
}

NetLimitResult database_wrapper::get_account_net_limit(uint64_t name, uint32_t greylist_limit) const {
    auto [arl, greylisted] = get_account_net_limit_ex(name, greylist_limit);
    return {arl.available, greylisted};
}

const permission_object& database_wrapper::create_permission(
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

void database_wrapper::modify_permission( const permission_object& permission, const Authority& a, const fc::time_point& pending_block_time ) {
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

}