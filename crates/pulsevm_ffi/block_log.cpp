#include "block_log.hpp"
#include <filesystem>

std::unique_ptr<pulsevm::chain::block_log> open_block_log(
    rust::Str path
) {
    std::string path_str(path.data(), path.size());
    std::filesystem::path fs_path(path_str);
    
    return std::make_unique<pulsevm::chain::block_log>(fs_path);
}