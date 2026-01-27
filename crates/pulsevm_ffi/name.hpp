#pragma once
#include <pulsevm/chain/name.hpp>
#include <rust/cxx.h>

namespace pulsevm::chain {
   using CxxName = pulsevm::chain::name;

   std::unique_ptr<name> u64_to_name(uint64_t val);
   std::unique_ptr<name> string_to_name(rust::Str str);
   uint64_t name_to_uint64(const name& n);
} // pulsevm::chain