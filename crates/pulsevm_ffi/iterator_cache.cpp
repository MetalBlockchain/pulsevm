#pragma once
#include "iterator_cache.hpp"

namespace pulsevm::chain {

std::unique_ptr<CxxKeyValueIteratorCache> new_key_value_iterator_cache() {
    return std::make_unique<CxxKeyValueIteratorCache>();
}

std::unique_ptr<CxxIndex64IteratorCache> new_index64_iterator_cache() {
    return std::make_unique<CxxIndex64IteratorCache>();
}

}