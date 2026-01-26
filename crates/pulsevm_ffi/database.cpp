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

cpu_limit_result database_wrapper::get_account_cpu_limit(uint64_t name, uint32_t greylist_limit) const {
    auto [arl, greylisted] = get_account_cpu_limit_ex(name, greylist_limit);
    return {arl.available, greylisted};
}

net_limit_result database_wrapper::get_account_net_limit(uint64_t name, uint32_t greylist_limit) const {
    auto [arl, greylisted] = get_account_net_limit_ex(name, greylist_limit);
    return {arl.available, greylisted};
}

}