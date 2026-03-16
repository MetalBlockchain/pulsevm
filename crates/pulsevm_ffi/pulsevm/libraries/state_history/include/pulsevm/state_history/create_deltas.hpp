#pragma once

#include <pulsevm/state_history/types.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>

namespace pulsevm {
namespace state_history {

template<typename Stream>
void pack_deltas(Stream& ds, const chainbase::database& db, bool full_snapshot);


} // namespace state_history
} // namespace pulsevm
