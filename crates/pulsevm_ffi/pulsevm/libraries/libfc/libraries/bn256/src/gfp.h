#pragma once
#include "gfp_generic.h"
#include <iosfwd>
#include <string>
#include <system_error>
#include <span>

namespace bn256 {

enum class unmarshal_error { NO_ERROR = 0, COORDINATE_EXCEEDS_MODULUS = 1, COORDINATE_EQUALS_MODULUS, MALFORMED_POINT };

namespace constants {
   // rn1 is R^-1 where R = 2^256 mod p.
   inline constexpr std::array<uint64_t, 4> rn1 = { 0xed84884a014afa37, 0xeb2022850278edf8, 0xcf63e9cfb74492d9,
                                                    0x2e67157159e5c639 };

   // r2 is R^2 where R = 2^256 mod p.
   inline constexpr std::array<uint64_t, 4> r2 = { 0xf32cfc5b538afa89, 0xb5e71911d44501fb, 0x47ab1eff0a417ff6,
                                                   0x06d89f71cab8351f };

   // r3 is R^3 where R = 2^256 mod p.
   inline constexpr std::array<uint64_t, 4> r3 = { 0xb1cd6dafda1530df, 0x62f210e6a7283db6, 0xef7f0b0c0ada0afb,
                                                   0x20fd6e902d592544 };
} // namespace constants

struct gfp : std::array<uint64_t, 4> {

   static constexpr gfp zero() noexcept { return {}; }

   constexpr gfp neg() const noexcept { return { gfp_neg(*this) }; }

   constexpr gfp add(const gfp& other) const noexcept { return { gfp_add(*this, other) }; }

   constexpr gfp sub(const gfp& other) const noexcept { return { gfp_sub(*this, other) }; }

   constexpr gfp mul(const gfp& other) const noexcept { return { gfp_mul(*this, other) }; }

   constexpr gfp invert() const noexcept {
      constexpr std::array<uint64_t, 4> bits = { 0x3c208c16d87cfd45, 0x97816a916871ca8d, 0xb85045b68181585d,
                                                 0x30644e72e131a029 };

      gfp  sum{ constants::rn1 };
      auto power = *this;

      for (auto word : bits) {
         for (auto bit = 0; bit < 64; bit++, word >>=1) {
            if ((word & 1) == 1) {
               sum = sum.mul(power);
            }
            power = power.mul(power);
         }
      }

      return sum.mul({ constants::r3 });
   }

   constexpr void marshal(std::span<uint8_t, 32> out) const noexcept {
      for (auto w = 0; w < 4; w++) {
         for (auto b = 0; b < 8; b++) {
            uint8_t t      = ((*this)[3 - w] >> (56 - 8 * b));
            out[8 * w + b] = t;
         }
      }
   }

   unmarshal_error unmarshal(std::span<const uint8_t, 32> in) noexcept {
      gfp& result = *this;
      // Unmarshal the bytes into little endian form
      for (auto w = 0; w < 4; w++) {
         result[3 - w] = 0;
         for (auto b = 0; b < 8; b++) { result[3 - w] += uint64_t(in[8 * w + b]) << (56 - 8 * b); }
      }

      // Ensure the point respects the curve modulus
      for (auto i = 3; i >= 0; i--) {
         if (result[i] < constants::p2[i]) {
            return unmarshal_error::NO_ERROR;
         }
         if (result[i] > constants::p2[i]) {
            return unmarshal_error::COORDINATE_EXCEEDS_MODULUS;
         }
      }
      return unmarshal_error::MALFORMED_POINT;
   }

#if defined (__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif

   constexpr gfp mont_encode() const noexcept { return mul({ constants::r2 }); }

   constexpr gfp mont_decode() const noexcept { return mul(gfp{ 1 }); }

   std::string string() const {
      std::string result;
      result.resize(64);

      auto buf = result.data();
      for (int i = size() - 1; i >= 0; --i) {
         const char           hex_table[] = "0123456789abcdef";
         const unsigned char* p           = reinterpret_cast<const unsigned char*>(&(*this)[i]) + 8;
         for (std::size_t i = 0; i < sizeof(uint64_t); ++i) {
            unsigned x = *(--p);
            *buf++     = hex_table[(x >> 4)];
            *buf++     = hex_table[x & 0x0F];
         }
      }
      return result;
   }
};

constexpr gfp new_gfp(int64_t x) noexcept {
   gfp out{};
   if (x >= 0) {
      out = { uint64_t(x) };
   } else {
      out = { uint64_t(-x) };
      out = out.neg();
   }
   return out.mont_encode();
}

#if defined (__clang__)
#pragma clang diagnostic pop
#endif

inline std::ostream& operator<<(std::ostream& os, const gfp& v) { return os << v.string(); }
} // namespace bn256
