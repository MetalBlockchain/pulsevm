#pragma once
#include "array.h"
#include "bitint_arithmetic.h"
#include <type_traits>
#include <tuple>
#include <iomanip>
#include <iostream>
namespace bn256 {

constexpr uint64_t signbits(int64_t a) { return a < 0 ? UINT64_MAX : 0; }

struct int512_t {
   std::array<uint64_t, 8> limbs_;

   constexpr int512_t(int64_t a = 0)
       : limbs_{
            (uint64_t)a, signbits(a), signbits(a), signbits(a), signbits(a), signbits(a), signbits(a), signbits(a)
         } {}

   constexpr int512_t(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4 = 0, uint64_t a5 = 0,
                      uint64_t a6 = 0, uint64_t a7 = 0)
       : limbs_{ a0, a1, a2, a3, a4, a5, a6, a7 } {}

   constexpr int512_t(const int512_t& other) : limbs_{ other.limbs_ } {}

   constexpr int512_t& operator=(const int512_t& other) {
      limbs_ = other.limbs_;
      return *this;
   }

   friend constexpr bool is_neg(const int512_t& a) { return static_cast<int64_t>(a.limbs_[7]) < 0; }

   friend constexpr int512_t operator-(const int512_t& a, const int512_t& b) {
      int512_t c{};
      subborrow_u512(false, &a.limbs_[0], &b.limbs_[0], &c.limbs_[0]);
      return c;
   }

   friend constexpr int512_t operator-(const int512_t& a) { return int512_t{} - a; }

   friend constexpr int512_t& operator-=(int512_t& a, const int512_t& b) {
      subborrow_u512(false, &a.limbs_[0], &b.limbs_[0], &a.limbs_[0]);
      return a;
   }

   friend constexpr int512_t operator+(const int512_t& a, const int512_t& b) {
      int512_t c{};
      addcarry_u512(false, &a.limbs_[0], &b.limbs_[0], &c.limbs_[0]);
      return c;
   }

   friend constexpr int512_t& operator+=(int512_t& a, const int512_t& b) {
      addcarry_u512(false, &a.limbs_[0], &b.limbs_[0], &a.limbs_[0]);
      return a;
   }

   friend constexpr int512_t operator*(const int512_t& a, const int512_t& b) {
      uint64_t c[8] = {};
      uint64_t t[4] = {};
      full_mul_u256(&a.limbs_[0], &b.limbs_[0], &c[0]);

      half_mul_u256(&a.limbs_[4], &b.limbs_[0], &t[0]);
      addcarry_u256(false, &c[4], &t[0], &c[4]);
      half_mul_u256(&a.limbs_[0], &b.limbs_[4], &t[0]);
      addcarry_u256(false, &c[4], &t[0], &c[4]);

      return { c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7] };
   }

   friend constexpr int512_t& operator*=(int512_t& a, const int512_t& b) {
      a = a * b;
      return a;
   }

   friend constexpr bool operator==(const int512_t& a, const int512_t& b) {
      if (!std::is_constant_evaluated()) {
         return memcmp(&a, &b, sizeof(a)) == 0;
      }
      for (auto i = 0U; i < a.limbs_.size(); ++i) {
         if (a.limbs_[i] != b.limbs_[i])
            return false;
      }
      return true;
   }

   friend constexpr bool operator!=(const int512_t& a, const int512_t& b) { return !(a == b); }

   friend constexpr bool operator<(const int512_t& a, const int512_t& b) { return is_neg(a - b); }

   friend constexpr bool operator>(const int512_t& a, const int512_t& b) { return is_neg(b - a); }

   friend constexpr bool operator<=(const int512_t& a, const int512_t& b) { return !(a > b); }

   friend constexpr bool operator>=(const int512_t& a, const int512_t& b) { return !(a < b); }

   static constexpr uint64_t shl128(uint64_t low, uint64_t high, int n) {
      __uint128_t v = (__uint128_t(high) << 64) | __uint128_t(low);
      return (v << (n & 63)) >> 64;
   }

   static constexpr uint64_t shr128(uint64_t low, uint64_t high, int n) {
      __uint128_t v = (__uint128_t(high) << 64) | __uint128_t(low);
      return v >> (n & 63);
   }

   friend constexpr int512_t operator<<(const int512_t& a, int n) {
      int512_t r{};
      auto     limb_offset      = n / 64;
      auto     limb_shfit_count = n % 64;

      for (int i = 0, j = limb_offset + 1; j < 8; ++i, ++j)
         r.limbs_[j] = shl128(a.limbs_[i], a.limbs_[i + 1], limb_shfit_count);
      r.limbs_[limb_offset] = (a.limbs_[0] << limb_shfit_count);
      return r;
   }

   friend constexpr int512_t& operator<<=(int512_t& a, int n) {
      a = (a << n);
      return a;
   }

   friend constexpr int512_t operator>>(const int512_t& a, int n) {
      int512_t r{};
      auto     limb_offset      = n / 64;
      auto     limb_shfit_count = n % 64;

      for (int i = limb_offset + 1, j = 0; i < 8; ++i, ++j)
         r.limbs_[j] = shr128(a.limbs_[i - 1], a.limbs_[i], limb_shfit_count);

      r.limbs_[7] = (a.limbs_[7 - limb_offset] >> limb_shfit_count);
      return r;
   }

   friend constexpr int512_t& operator>>=(int512_t& a, int n) {
      a = (a >> n);
      return a;
   }

   friend constexpr int512_t& operator|=(int512_t& a, const int512_t& b) {
      for (int i = 0; i < 8; ++i) { a.limbs_[i] |= b.limbs_[i]; }
      return a;
   }

   friend constexpr int512_t operator|(const int512_t& a, const int512_t& b) {
      int512_t c{};
      for (int i = 0; i < 8; ++i) { c.limbs_[i] = a.limbs_[i] | b.limbs_[i]; }
      return a;
   }

   friend constexpr int512_t& operator&=(int512_t& a, const int512_t& b) {
      for (int i = 0; i < 8; ++i) { a.limbs_[i] &= b.limbs_[i]; }
      return a;
   }

   friend constexpr int512_t operator&(const int512_t& a, const int512_t& b) {
      int512_t c{};
      for (int i = 0; i < 8; ++i) { c.limbs_[i] = a.limbs_[i] & b.limbs_[i]; }
      return a;
   }

   constexpr operator bool() { return *this != int512_t{}; }

   friend constexpr int512_t abs(const int512_t& a) { return is_neg(a) ? -a : a; }

   friend constexpr int leading_zeros(const int512_t& a) {
      int count = 0;
      for (int i = 7; i >= 0; --i) {
         if (a.limbs_[i] == 0)
            count += 64;
         else {
            return count + __builtin_clzll(a.limbs_[i]);
         }
      }
      return count;
   }

   friend constexpr std::tuple<int512_t, int512_t> unsigned_divmod(int512_t a, const int512_t& b) {
      int shift_bits = leading_zeros(b) - leading_zeros(a);
      if (shift_bits < 0) {
         return { 0, a };
      }
      int512_t subtrahend = b << shift_bits;
      int512_t digit      = int512_t{ 1 } << shift_bits;
      int512_t quotient{ 0 };
      while (digit) {
         if (subtrahend <= a) {
            a -= subtrahend;
            quotient |= digit;
         }
         subtrahend >>= 1;
         digit >>= 1;
      }
      return { quotient, a };
   }

   friend constexpr std::tuple<int512_t, int512_t> divmod(int512_t a, const int512_t& b) {
      auto [quotient, remainder] = unsigned_divmod(abs(a), abs(b));
      if (is_neg(a)) {
         remainder = -remainder;
         if (!is_neg(b))
            quotient = -quotient;
      } else { /* positive dividend */
         if (is_neg(b))
            quotient = -quotient;
      }
      return { quotient, remainder };
   }

   friend constexpr int512_t operator/(const int512_t& a, const int512_t& b) { return std::get<0>(divmod(a, b)); }

   friend constexpr int512_t& operator/=(int512_t& a, const int512_t& b) {
      a = a / b;
      return a;
   }

   friend constexpr int512_t operator%(const int512_t& a, const int512_t& b) {
      return std::get<1>(divmod(a, b));
      ;
   }

   friend constexpr int512_t& operator%=(int512_t& a, const int512_t& b) {
      a = a % b;
      return a;
   }

   friend constexpr int bitlen(const int512_t& a) { return bitlen<8>(std::span<const uint64_t, 8>(a.limbs_)); }

   friend constexpr bool bit_test(const int512_t& a, int i) {
      return bit_test<8>(std::span<const uint64_t, 8>(a.limbs_), i);
   }
};

template <char... Chars>
constexpr int512_t operator""_i512() {

   auto parse_heximal = [](const char* str) {
      int512_t r{};
      int      i = 0;

      auto is_hex_digit = [](char digit) {
         auto between = [digit](char b, char e) { return digit >= b && digit <= e; };
         return between('0', '9') || between('A', 'F') || between('a', 'f');
      };
      while (char digit = str[i++]) {
         if (!is_hex_digit(digit))
            throw "invalid digits";
         unsigned char digit_value = 0;
         if (digit >= 'a')
            digit_value = digit - 'a' + 10;
         else if (digit >= 'A')
            digit_value = digit - 'A' + 10;
         else
            digit_value = digit - '0';
         r <<= 4;
         r |= digit_value;
      }
      return r;
   };

   const char str[]{ Chars..., '\0' };
   int512_t   r{};
   int        i = 0;
   if (str[0] == '0' && str[1] == 'x')
      return parse_heximal(str + 2);

   bool is_negtive = (str[0] == '-');
   if (is_negtive)
      ++i;

   while (char digit = str[i++]) {
      if (digit < '0' && digit > '9')
         throw "invalid digits";
      r *= 10;
      r += (digit - '0');
   }
   return is_negtive ? int512_t{} - r : r;
}

inline std::ostream& operator<<(std::ostream& os, const int512_t& a) {
   auto flags = os.flags();
   if (flags & std::ios_base::hex) {
      bool need_fill = false;
      for (int i = a.limbs_.size() - 1; i >= 0; --i) {
         if (!need_fill && a.limbs_[i] == 0)
            continue;
         if (need_fill)
            os << std::setfill('0') << std::setw(16);
         os << a.limbs_[i];
         need_fill = true;
      }
      if (!need_fill)
         os << 0;
   } else if (flags & std::ios_base::dec) {
      char digits[156];
      digits[155] = 0;
      auto tmp    = abs(a);
      int  i      = 154;
      if (!tmp)
         os << 0;
      else {
         while (tmp) {
            auto [quotient, remainder] = divmod(tmp, 10);
            digits[i--]                = '0' + remainder.limbs_[0];
            tmp                        = quotient;
         }
         if (is_neg(a))
            digits[i--] = '-';
         os << digits + i + 1;
      }
   }
   return os;
}

namespace testing {

   static_assert(leading_zeros(int512_t{ 0, 0, 0, 0, 0, 0, 0, 0x0FFFFFFFFFFFFFFF }) == 4);
   static_assert(leading_zeros(int512_t{ 0, 0, 0, 0, 0, 0, 0x0FFFFFFFFFFFFFFF, 0 }) == 68);
   static_assert(leading_zeros(int512_t{ 0x0FFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0 }) == 452);

   static_assert( 21888242871839275222246405745257275088548364400416034343698204186575808495617_i512 == abs(21888242871839275222246405745257275088548364400416034343698204186575808495617_i512));
   static_assert( 21888242871839275222246405745257275088548364400416034343698204186575808495617_i512 == abs(-21888242871839275222246405745257275088548364400416034343698204186575808495617_i512));


   static_assert(
         21888242871839275222246405745257275088548364400416034343698204186575808495617_i512 *
               21888242871839275222246405745257275088696311157297823662689037894645226208583_i512 ==
         479095176016622842441988045216678740796014021984371259138060142739732051292045946981843177216315114219669975956079051917369253052711332371532837883280711_i512);
   static_assert(divmod(1000_i512, 9_i512) == std::make_tuple(111_i512, 1_i512));
} // namespace testing

} // namespace bn256
