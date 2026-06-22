#pragma once
#include "iterator_cache.hpp"

namespace pulsevm::chain {

std::unique_ptr<CxxKeyValueIteratorCache> new_key_value_iterator_cache() {
    return std::make_unique<CxxKeyValueIteratorCache>();
}

std::unique_ptr<CxxIndex64IteratorCache> new_index64_iterator_cache() {
    return std::make_unique<CxxIndex64IteratorCache>();
}

std::unique_ptr<CxxIndex128IteratorCache> new_index128_iterator_cache() {
    return std::make_unique<CxxIndex128IteratorCache>();
}

std::unique_ptr<CxxIndex256IteratorCache> new_index256_iterator_cache() {
    return std::make_unique<CxxIndex256IteratorCache>();
}

std::unique_ptr<CxxIndexDoubleIteratorCache> new_index_double_iterator_cache() {
    return std::make_unique<CxxIndexDoubleIteratorCache>();
}

std::unique_ptr<CxxIndexLongDoubleIteratorCache> new_index_long_double_iterator_cache() {
    return std::make_unique<CxxIndexLongDoubleIteratorCache>();
}

}