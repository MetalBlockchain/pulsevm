#pragma once
#include "int512.h"
#include "constants.h"

namespace bn256 {

template <std::size_t N>
struct lattice {
   int512_t vectors_[N][N];
   int512_t              inverse_[N];
   const int512_t                     det_;

   // decompose takes a scalar mod order as input and finds a short,
   // positive decomposition of it wrt to the lattice basis.
   constexpr std::array<int512_t, N> decompose(std::span<const uint64_t, 4> scalar) const noexcept{
      int512_t              k = {scalar[0], scalar[1], scalar[2], scalar[3], 0, 0, 0, 0};
      // int512_t              k = to_i512(scalar);
      int512_t c[N] = {};

      // Calculate closest vector in lattice to <k,0,0,...> with Babai's rounding.
      for (std::size_t i = 0; i < N; i++) {
         c[i] = k * inverse_[i];
         round(c[i], det_);
      }

      // Transform vectors according to c and subtract <k,0,0,...>.
      std::array<int512_t, N> out;
      int512_t                temp;
      for (std::size_t i = 0; i < N; i++) {
         out[i] = 0;
         for (std::size_t j = 0; j < N; j++) {
            temp = c[j] * vectors_[j][i];
            out[i] += temp;
         }
         out[i] = -out[i];
         out[i] += vectors_[0][i];
         out[i] += vectors_[0][i];
      }
      out[0] += k;
      return out;
   }

   template <typename Lambda>
   constexpr void foreach_multi_scalar(std::span<const uint64_t, 4> scalar, Lambda&& lambda) const noexcept{

      auto decomp = decompose(scalar);

      int maxlen = 0;
      for (std::size_t i = 0; i < N; ++i) {
         maxlen = std::max(maxlen, bitlen(decomp[i]));
      }

      for (int i = maxlen-1; i >=0; --i) {
         uint8_t out=0;
         for (std::size_t j = 0; j < N; ++j) {
            if (bit_test(decomp[j], i)) {
               out += (1 << j);
            }
         }
         lambda(out);
      }
   }

   // round sets num to num/denom rounded to the nearest integer.
   constexpr void round(int512_t& num, const int512_t& denom) const noexcept {
      if (denom != 0) {
         const int512_t half = int512_t{constants::order[0], constants::order[1], constants::order[2], constants::order[3]}>> 1;
         num /= denom;
         int512_t rem            = num % denom;
         if (rem > half) {
            num = num + int512_t{1};
         }
      }
   }
};

static const lattice<2> curve_lattice = {
      .vectors_ = {
         {
            147946756881789319000765030803803410728_i512,
            147946756881789319010696353538189108491_i512
         },{
            147946756881789319020627676272574806254_i512,
            -147946756881789318990833708069417712965_i512
         }
      },
      .inverse_ = {
         147946756881789318990833708069417712965_i512,
         147946756881789319010696353538189108491_i512,
      },
      .det_ = 43776485743678550444492811490514550177096728800832068687396408373151616991234_i512
   };

static const lattice<4> target_lattice = {
   .vectors_ = { { 9931322734385697761_i512, 9931322734385697761_i512, 9931322734385697763_i512,
                   9931322734385697764_i512 },
                 { 4965661367192848881_i512, 4965661367192848881_i512, 4965661367192848882_i512,
                   -9931322734385697762_i512 },
                 { -9931322734385697762_i512, -4965661367192848881_i512, 4965661367192848881_i512,
                   -4965661367192848882_i512 },
                 { 9931322734385697763_i512, -4965661367192848881_i512, -4965661367192848881_i512,
                   -4965661367192848881_i512 } },
   .inverse_ = { 734653495049373973658254490726798021314063399421879442165_i512,
                 147946756881789319000765030803803410728_i512,
                 -147946756881789319005730692170996259609_i512,
                 1469306990098747947464455738335385361643788813749140841702_i512 },
   .det_     = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001_i512
};

} // namespace bn256
