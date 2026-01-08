#pragma once
#include "array.h"
#include "bitint_arithmetic.h"
#include <cstddef>
namespace bn256 {

namespace constants {
   // p2 is p, represented as little-endian 64-bit words.
   inline constexpr std::array<uint64_t, 4> p2 = { 0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d,
                                                   0x30644e72e131a029 };

   // np is the negative inverse of p, mod 2^256.
   inline constexpr std::array<uint64_t, 4> np = { 0x87d20782e4866389, 0x9ede7d651eca6ac9, 0xd8afcbd01833da80,
                                                   0xf57a22b791888c6b };

} // namespace constants

constexpr std::array<uint64_t, 4> gfp_carry(const std::array<uint64_t, 4>& a, uint64_t head) noexcept {
   std::array<uint64_t, 4> b{};

   bool carry = subborrow_u256(false, a.data(), constants::p2.data(), b.data());
   carry      = subborrow_u64(carry, head, 0, &head);

   return carry ? a : b;
}

constexpr std::array<uint64_t, 4> gfp_neg(const std::array<uint64_t, 4>& a) noexcept {
   std::array<uint64_t, 4> b{};
   subborrow_u256(false, constants::p2.data(), a.data(), b.data());
   return gfp_carry(b, 0);
}

constexpr std::array<uint64_t, 4> gfp_add(const std::array<uint64_t, 4>& a, const std::array<uint64_t, 4>& b) noexcept {
   std::array<uint64_t, 4> c{};
   bool               carry = addcarry_u256(false, a.data(), b.data(), c.data());
   return gfp_carry(c, carry);
}

constexpr std::array<uint64_t, 4> gfp_sub(const std::array<uint64_t, 4>& a, const std::array<uint64_t, 4>& b) noexcept {
   std::array<uint64_t, 4> t{};
   subborrow_u256(false, constants::p2.data(), b.data(), t.data());
   std::array<uint64_t, 4> c{};
   uint64_t           carry = addcarry_u256(false, a.data(), t.data(), c.data());
   return gfp_carry(c, carry);
}

[[gnu::hot]]
constexpr std::array<uint64_t, 4> gfp_mul(const std::array<uint64_t, 4>& a, const std::array<uint64_t, 4>& b) noexcept {
   std::array<uint64_t, 8> T = {};
   full_mul_u256(a.data(), b.data(), T.data());
   std::array<uint64_t, 4> m = {};
   half_mul_u256(T.data(), constants::np.data(), m.data());
   std::array<uint64_t, 8> t = {};
   full_mul_u256(m.data(), constants::p2.data(), t.data());

   bool carry = false;
   carry      = addcarry_u256(carry, T.data(), t.data(), T.data());
   carry      = addcarry_u256(carry, T.data() + 4, t.data() + 4, T.data() + 4);

   return gfp_carry({ T[4], T[5], T[6], T[7] }, carry);
}

} // namespace bn256
