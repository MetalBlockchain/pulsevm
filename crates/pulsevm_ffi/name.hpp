#include <pulsevm/name.hpp>
#include <rust/cxx.h>

namespace pulsevm::chain {

std::unique_ptr<name> string_to_name(rust::Str str) {
    std::string_view sv{str.data(), str.size()};
    return std::make_unique<name>(sv);
}

uint64_t name_to_uint64(const name& n) {
    return n.to_uint64_t();
}

}