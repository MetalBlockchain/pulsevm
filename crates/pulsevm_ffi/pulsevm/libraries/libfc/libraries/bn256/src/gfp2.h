#pragma once
#include "gfp.h"
#include "gfp_generic.h"
#include <iostream>

namespace bn256 {

// gfp2 implements a field of size p² as a quadratic extension of the base field
// where i²=-1.
struct gfp2 {
   gfp x_;
   gfp y_;

   static constexpr gfp2 zero() noexcept { return {}; }
   static constexpr gfp2 one() noexcept { return { {}, new_gfp(1) }; }

   constexpr void set_zero() noexcept { *this = zero(); }
   constexpr void set_one() noexcept { *this = one(); }

   constexpr bool is_zero() const noexcept { return *this == zero(); }
   constexpr bool is_one() const noexcept { return *this == one(); }

   static constexpr gfp2 gfp2_decode(const gfp2& in) noexcept { return { in.x_.mont_decode(), in.y_.mont_decode() }; }

   constexpr gfp2 conjugate() const noexcept { return { x_.neg(), y_ }; }

   constexpr gfp2 neg() const noexcept { return { x_.neg(), y_.neg() }; }

   constexpr gfp2 add(const gfp2& b) const noexcept { return { x_.add(b.x_), y_.add(b.y_) }; }

   constexpr gfp2 sub(const gfp2& b) const noexcept { return { x_.sub(b.x_), y_.sub(b.y_) }; }

   // See "Multiplication and Squaring in Pairing-Friendly Fields",
   // http://eprint.iacr.org/2006/471.pdf
   constexpr gfp2 mul(const gfp2& b) const noexcept {
      const gfp2& a = *this;

      gfp tx = a.x_.mul(b.y_);
      gfp t  = b.x_.mul(a.y_);
      tx     = tx.add(t);

      gfp ty = a.y_.mul(b.y_);
      t      = a.x_.mul(b.x_);
      ty     = ty.sub(t);

      return { tx, ty };
   }

   constexpr gfp2 mul_scalar(const gfp& b) const noexcept { return { x_.mul(b), y_.mul(b) }; }

   // MulXi sets e=ξa where ξ=i+9 and then returns e.
   constexpr gfp2 mul_xi() const noexcept {
      const gfp2& a = *this;

      gfp tx = a.x_.add(a.x_);
      tx     = tx.add(tx);
      tx     = tx.add(tx);
      tx     = tx.add(a.x_);

      tx = tx.add(a.y_);

      gfp ty = a.y_.add(a.y_);
      ty     = ty.add(ty);
      ty     = ty.add(ty);
      ty     = ty.add(a.y_);

      ty = ty.sub(a.x_);

      return { tx, ty };
   }

   constexpr gfp2 square() const noexcept {
      const gfp2& a = *this;

      // Complex squaring algorithm:
      // (xi+y)² = (x+y)(y-x) + 2*i*x*y
      gfp tx = a.y_.sub(a.x_);
      gfp ty = a.x_.add(a.y_);
      ty     = tx.mul(ty);

      tx = a.x_.mul(a.y_);
      tx = tx.add(tx);

      return { tx, ty };
   }

   constexpr gfp2 invert() const noexcept {
      const gfp2& a = *this;

      // See "Implementing cryptographic pairings", M. Scott, section 3.2.
      // ftp://136.206.11.249/pub/crypto/pairings.pdf
      gfp t1 = a.x_.mul(a.x_);
      gfp t2 = a.y_.mul(a.y_);
      t1     = t1.add(t2);

      gfp inv = t1.invert();

      t1 = a.x_.neg();

      return { t1.mul(inv), a.y_.mul(inv) };
   }

   std::string string() const { return "(" + x_.string() + ", " + y_.string() + ")"; }

   friend std::ostream& operator<<(std::ostream& os, const gfp2& v) { return os << "(" << v.x_ << ", " << v.y_ << ")"; }

   constexpr bool operator==(const gfp2& rhs) const noexcept {
      static_assert(std::is_standard_layout_v<gfp2>);
      return x_ == rhs.x_ && y_ == rhs.y_;
   }

   constexpr bool operator!=(const gfp2& rhs) const noexcept { return !(*this == rhs); }
};

namespace constants {
#if defined (__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif
   // xi_to_p_minus_1_over_6 is ξ^((p-1)/6) where ξ = i+9.
   inline constexpr gfp2 xi_to_p_minus_1_over_6 = {
      { 0xa222ae234c492d72, 0xd00f02a4565de15b, 0xdc2ff3a253dfc926, 0x10a75716b3899551 },
      { 0xaf9ba69633144907, 0xca6b1d7387afb78a, 0x11bded5ef08a2087, 0x02f34d751a1f3a7c }
   };

   // xi_to_p_minus_1_over_3 is ξ^((p-1)/3) where ξ = i+9.
   inline constexpr gfp2 xi_to_p_minus_1_over_3 = {
      { 0x6e849f1ea0aa4757, 0xaa1c7b6d89f89141, 0xb6e713cdfae0ca3a, 0x26694fbb4e82ebc3 },
      { 0xb5773b104563ab30, 0x347f91c8a9aa6454, 0x7a007127242e0991, 0x1956bcd8118214ec }
   };

   // xi_to_p_minus_1_over_2 is ξ^((p-1)/2) where ξ = i+9.
   inline constexpr gfp2 xi_to_p_minus_1_over_2 = {
      { 0xa1d77ce45ffe77c7, 0x07affd117826d1db, 0x6d16bd27bb7edc6b, 0x2c87200285defecc },
      { 0xe4bbdd0c2936b629, 0xbb30f162e133bacb, 0x31a9d1b6f9645366, 0x253570bea500f8dd }
   };

   // xi_to_p_squared_minus_1_over_3 is ξ^((p²-1)/3) where ξ = i+9.
   inline constexpr gfp xi_to_p_squared_minus_1_over_3 = { 0x3350c88e13e80b9c, 0x7dce557cdb5e56b9, 0x6001b4b8b615564a,
                                                           0x2682e617020217e0 };

   // xi_to_2p_squared_minus_2_over_3 is ξ^((2p²-2)/3) where ξ = i+9 (a cubic root of unity, mod p).
   inline constexpr gfp xi_to_2p_squared_minus_2_over_3 = { 0x71930c11d782e155, 0xa6bb947cffbe3323, 0xaa303344d4741444,
                                                            0x2c3b3f0d26594943 };

   // xi_to_p_squared_minus_1_over_6 is ξ^((1p²-1)/6) where ξ = i+9 (a cubic root of -1, mod p).
   inline constexpr gfp xi_to_p_squared_minus_1_over_6 = { 0xca8d800500fa1bf2, 0xf0c5d61468b39769, 0x0e201271ad0d4418,
                                                           0x04290f65bad856e6 };

   // xi_to_2p_minus_2_over_3 is ξ^((2p-2)/3) where ξ = i+9.
   inline constexpr gfp2 xi_to_2p_minus_2_over_3 = {
      { 0x5dddfd154bd8c949, 0x62cb29a5a4445b60, 0x37bc870a0c7dd2b9, 0x24830a9d3171f0fd },
      { 0x7361d77f843abe92, 0xa5bb2bd3273411fb, 0x9c941f314b3e2399, 0x15df9cddbb9fd3ec }
   };
#if defined (__clang__)
#pragma clang diagnostic pop
#endif
} // namespace constants

} // namespace bn256
