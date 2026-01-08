#pragma once
#include <cstddef>
#include <cstring>
#include <span>
#include <cstdint>
#include <tuple>
#include <array>

namespace bn256 {
template <std::size_t N>
constexpr int bitlen(std::span<const uint64_t, N> a) {
   auto bit_length = N*sizeof(uint64_t)*8;
   const uint64_t all_sign_bits = static_cast<int64_t>(a[N-1]) >> 63;

   int i = N-1;
   while (i >0 && a[i] == all_sign_bits) {
        bit_length -= sizeof(uint64_t)*8;
        --i;
   }
   if (a[i]==0 ) return 0;
   return bit_length - __builtin_clzll(all_sign_bits == 0 ? a[i] : -a[i]);
}

static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0, 0x0FFFFFFFFFFFFFFF}) == 252);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0x0FFFFFFFFFFFFFFF, 0}) == 188);
static_assert(bitlen<4>(std::array<uint64_t,4>{0x0FFFFFFFFFFFFFFF, 0, 0, 0}) == 60);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0, 0x8FFFFFFFFFFFFFFF}) == 255);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0, 0x7FFFFFFFFFFFFFFF}) == 255);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}) == 192);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0x7FFFFFFFFFFFFFFF, 0}) == 191);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0x8FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}) == 191);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0x8FFFFFFFFFFFFFFF, 0}) == 192);
static_assert(bitlen<4>(std::array<uint64_t,4>{0x7FFFFFFFFFFFFFFF, 0, 0, 0}) == 63);
static_assert(bitlen<4>(std::array<uint64_t,4>{0x8FFFFFFFFFFFFFFF, 0, 0, 0}) == 64);
static_assert(bitlen<4>(std::array<uint64_t,4>{0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}) == 64);
static_assert(bitlen<4>(std::array<uint64_t,4>{0x8FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}) == 63);
static_assert(bitlen<4>(std::array<uint64_t,4>{0, 0, 0, 0}) == 0);

constexpr int bitlen(const std::array<uint64_t, 4>& a) {
   return bitlen<4>(std::span<const uint64_t, 4>(a));
}

template <std::size_t N>
constexpr bool bit_test(std::span<const uint64_t, N> value, int i) {
   int limb_index    = i / (sizeof(uint64_t)*8);
   int index_in_limb = i % (sizeof(uint64_t)*8);
   return value[limb_index] & (1ULL << index_in_limb);
}
}
