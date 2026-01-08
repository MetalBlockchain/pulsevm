#pragma once

#include "gfp2.h"

namespace bn256 {



// gfp6 implements the field of size p⁶ as a cubic extension of gfp2 where τ³=ξ
// and ξ=i+9.
struct gfp6 {
   // value is xτ² + yτ + z
   gfp2 x_;
   gfp2 y_;
   gfp2 z_;

   static constexpr gfp6 zero() noexcept { return {}; }
   static constexpr gfp6 one() noexcept { return { {}, {}, gfp2::one() }; }

   [[nodiscard]] constexpr bool is_zero() const noexcept { return *this == zero(); }
   [[nodiscard]] constexpr bool is_one() const noexcept { return *this == one(); }

   constexpr gfp6 neg() const noexcept {
      const gfp6& a = *this;
      return { a.x_.neg(), a.y_.neg(), a.z_.neg() };
   }

   constexpr gfp6 frobenius() const noexcept {
      const gfp6& a = *this;
      gfp6        e = { a.x_.conjugate(), a.y_.conjugate(), a.z_.conjugate() };

      e.x_ = e.x_.mul(constants::xi_to_2p_minus_2_over_3);
      e.y_ = e.y_.mul(constants::xi_to_p_minus_1_over_3);
      return e;
   }

   // FrobeniusP2 computes (xτ²+yτ+z)^(p²) = xτ^(2p²) + yτ^(p²) + z
   constexpr gfp6 frobenius_p2() const noexcept {
      const gfp6& a = *this;
      gfp6        e{};
      // τ^(2p²) = τ²τ^(2p²-2) = τ²ξ^((2p²-2)/3)
      e.x_ = a.x_.mul_scalar(constants::xi_to_2p_squared_minus_2_over_3);
      // τ^(p²) = ττ^(p²-1) = τξ^((p²-1)/3)
      e.y_ = a.y_.mul_scalar(constants::xi_to_p_squared_minus_1_over_3);
      e.z_ = a.z_;
      return e;
   }

   constexpr gfp6 frobenius_p4() const noexcept {
      const gfp6& a = *this;
      gfp6        e{};
      e.x_ = a.x_.mul_scalar(constants::xi_to_p_squared_minus_1_over_3);
      e.y_ = a.y_.mul_scalar(constants::xi_to_2p_squared_minus_2_over_3);
      e.z_ = a.z_;
      return e;
   }

   constexpr gfp6 add(const gfp6& b) const noexcept {
      const gfp6& a = *this;
      gfp6        e{};
      e.x_ = a.x_.add(b.x_);
      e.y_ = a.y_.add(b.y_);
      e.z_ = a.z_.add(b.z_);
      return e;
   }

   constexpr gfp6 sub(const gfp6& b) const noexcept {
      const gfp6& a = *this;
      gfp6        e{};
      e.x_ = a.x_.sub(b.x_);
      e.y_ = a.y_.sub(b.y_);
      e.z_ = a.z_.sub(b.z_);
      return e;
   }

   constexpr gfp6 mul(const gfp6& b) const noexcept {
      const gfp6& a = *this;
      // "Multiplication and Squaring on Pairing-Friendly Fields"
      // Section 4, Karatsuba method.
      // http://eprint.iacr.org/2006/471.pdf

      gfp2 v0 = a.z_.mul(b.z_);
      gfp2 v1 = a.y_.mul(b.y_);
      gfp2 v2 = a.x_.mul(b.x_);

      gfp2 t0 = a.x_.add(a.y_);
      gfp2 t1 = b.x_.add(b.y_);
      gfp2 tz = t0.mul(t1);
      tz      = tz.sub(v1).sub(v2).mul_xi().add(v0);

      t0      = a.y_.add(a.z_);
      t1      = b.y_.add(b.z_);
      gfp2 ty = t0.mul(t1);
      t0      = v2.mul_xi();
      ty      = ty.sub(v0).sub(v1).add(t0);

      t0      = a.x_.add(a.z_);
      t1      = b.x_.add(b.z_);
      gfp2 tx = t0.mul(t1);
      tx      = tx.sub(v0).add(v1).sub(v2);

      return { tx, ty, tz };
   }

   constexpr gfp6 mul_scalar(const gfp2& b) const noexcept {
      const gfp6& a = *this;
      gfp6        e{};
      e.x_ = a.x_.mul(b);
      e.y_ = a.y_.mul(b);
      e.z_ = a.z_.mul(b);
      return e;
   }

   constexpr gfp6 mul_gfp(const gfp& b) const noexcept {
      const gfp6& a = *this;
      gfp6        e{};
      e.x_ = a.x_.mul_scalar(b);
      e.y_ = a.y_.mul_scalar(b);
      e.z_ = a.z_.mul_scalar(b);
      return e;
   }

   constexpr gfp6 mul_tau() const noexcept {
      const gfp6& a = *this;

      gfp2 tz = a.x_.mul_xi();
      gfp2 ty = a.y_;

      return { ty, a.z_, tz };
   }

   constexpr gfp6 square() const noexcept {
      const gfp6& a = *this;

      gfp2 v0 = a.z_.square();
      gfp2 v1 = a.y_.square();
      gfp2 v2 = a.x_.square();

      gfp2 c0 = a.x_.add(a.y_);
      c0      = c0.square().sub(v1).sub(v2).mul_xi().add(v0);

      gfp2 c1    = a.y_.add(a.z_);
      c1         = c1.square().sub(v0).sub(v1);
      gfp2 xi_v2 = v2.mul_xi();
      c1         = c1.add(xi_v2);

      gfp2 c2 = a.x_.add(a.z_);
      c2      = c2.square().sub(v0).add(v1).sub(v2);

      return { c2, c1, c0 };
   }

   constexpr gfp6 invert() const noexcept {
      const gfp6& a = *this;
      // See "Implementing cryptographic pairings", M. Scott, section 3.2.
      // ftp://136.206.11.249/pub/crypto/pairings.pdf

      // Here we can give a short explanation of how it works: let j be a cubic root of
      // unity in GF(p²) so that 1+j+j²=0.
      // Then (xτ² + yτ + z)(xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
      // = (xτ² + yτ + z)(Cτ²+Bτ+A)
      // = (x³ξ²+y³ξ+z³-3ξxyz) = F is an element of the base field (the norm).
      //
      // On the other hand (xj²τ² + yjτ + z)(xjτ² + yj²τ + z)
      // = τ²(y²-ξxz) + τ(ξx²-yz) + (z²-ξxy)
      //
      // So that's why A = (z²-ξxy), B = (ξx²-yz), C = (y²-ξxz)

      gfp2 t1 = a.x_.mul(a.y_);
      t1      = t1.mul_xi();

      gfp2 A = a.z_.square();
      A      = A.sub(t1);

      gfp2 B = a.x_.square();
      B      = B.mul_xi();
      t1     = a.y_.mul(a.z_);
      B      = B.sub(t1);

      gfp2 C = a.y_.square();
      t1     = a.x_.mul(a.z_);
      C      = C.sub(t1);

      gfp2 F = C.mul(a.y_);
      F      = F.mul_xi();
      t1     = A.mul(a.z_);
      F      = F.add(t1);
      t1     = B.mul(a.x_);
      t1     = t1.mul_xi();
      F      = F.add(t1);

      F = F.invert();

      return { C.mul(F), B.mul(F), A.mul(F) };
   }

   std::string string() const { return "(" + x_.string() + ", " + y_.string() + ", " + z_.string() + ")"; }

   friend std::ostream& operator<<(std::ostream& os, const gfp6& v) {
      return os << "(" << v.x_ << ", " << v.y_ << ", " << v.z_ << ")";
   }

   constexpr bool operator==(const gfp6& rhs) const noexcept {
      return x_ == rhs.x_ && y_ == rhs.y_ && z_ == rhs.z_;
   }

   constexpr bool operator!=(const gfp6& rhs) const noexcept { return !(*this == rhs); }
};

} // namespace bn256
