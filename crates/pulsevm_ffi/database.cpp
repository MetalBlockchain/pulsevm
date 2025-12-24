#include "database.hpp"
#include <pulsevm_ffi/src/bridge.rs.h>
#include <filesystem>

std::unique_ptr<database_wrapper> open_database(
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
    return std::make_unique<database_wrapper>(fs_path, db_flags, size);
}

std::unique_ptr<chainbase::database::session> start_undo_session(chainbase::database& db) {
    return std::make_unique<chainbase::database::session>(db.start_undo_session(true));
}