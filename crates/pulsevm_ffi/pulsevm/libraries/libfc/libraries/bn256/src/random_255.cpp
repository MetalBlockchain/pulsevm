#include "random_255.h"
#include<cstdlib>
namespace bn256 {

std::array<uint64_t, 4>  random_255() {
   // the random number should be a 255 bits integer
   std::array<uint64_t, 4> result{};

   for (auto i = 0U; i < result.size(); ++i) {
      uint64_t r = rand();
      r <<= 32;
      r |= rand();
      result[i] = r;
   }
   result[3] &= 0x7FFFFFFFFFFFFFFFULL;
   return result;
}


} // namespace bn256
