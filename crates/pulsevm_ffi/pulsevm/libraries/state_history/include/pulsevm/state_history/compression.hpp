#pragma once

#include <pulsevm/chain/types.hpp>

namespace pulsevm {
namespace state_history {

using chain::bytes;

bytes zlib_compress_bytes(const bytes& in);
bytes zlib_decompress(std::string_view);

} // namespace state_history
} // namespace pulsevm
