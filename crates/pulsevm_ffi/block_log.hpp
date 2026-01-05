#pragma once

#include <pulsevm/block_log.hpp>
#include <rust/cxx.h>

std::unique_ptr<pulsevm::chain::block_log> open_block_log(
    rust::Str path
);