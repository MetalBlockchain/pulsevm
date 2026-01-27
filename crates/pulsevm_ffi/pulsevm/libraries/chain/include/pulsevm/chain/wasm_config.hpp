#pragma once

#include <cstdint>
#include <fc/reflect/reflect.hpp>

namespace pulsevm { namespace chain {

struct wasm_config {
   std::uint32_t max_mutable_global_bytes;
   std::uint32_t max_table_elements;
   std::uint32_t max_section_elements;
   std::uint32_t max_linear_memory_init;
   std::uint32_t max_func_local_bytes;
   std::uint32_t max_nested_structures;
   std::uint32_t max_symbol_bytes;
   std::uint32_t max_module_bytes;
   std::uint32_t max_code_bytes;
   std::uint32_t max_pages;
   std::uint32_t max_call_depth;
};

}}

FC_REFLECT(pulsevm::chain::wasm_config,
   (max_mutable_global_bytes)
   (max_table_elements)
   (max_section_elements)
   (max_linear_memory_init)
   (max_func_local_bytes)
   (max_nested_structures)
   (max_symbol_bytes)
   (max_module_bytes)
   (max_code_bytes)
   (max_pages)
   (max_call_depth)
)
