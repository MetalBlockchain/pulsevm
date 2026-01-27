#pragma once
#include <pulsevm/chain/exceptions.hpp>
#include <rust/cxx.h>

namespace rust {
namespace behavior {

template <typename Try, typename Fail>
void trycatch(Try &&func, Fail &&fail) noexcept try {
  func();
} catch (const fc::exception& e) {
  fail(e.top_message());
} catch (const std::exception& e) {
  fail(e.what());
} catch (...) {
  fail("unknown exception");
}

} // namespace behavior
} // namespace rust