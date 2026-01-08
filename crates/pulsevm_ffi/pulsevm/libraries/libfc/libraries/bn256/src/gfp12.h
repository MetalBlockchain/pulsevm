#pragma once

#include "gfp6.h"

namespace bn256 {

// gfp12 implements the field of size p¹² as a quadratic extension of gfp6
// where ω²=τ.
struct gfp12 {
   // value is xω + y
   gfp6 x_;
   gfp6 y_;

   static constexpr gfp12 zero() noexcept { return {}; }
   static constexpr gfp12 one() noexcept { return { {}, gfp6::one() }; }

   constexpr void set_zero() noexcept { *this = zero(); }
   constexpr void set_one() noexcept { *this = one(); }

   constexpr bool is_zero() const noexcept { return *this == zero(); }
   constexpr bool is_one() const noexcept { return *this == one(); }

   constexpr gfp12 conjugate() const noexcept {
      const gfp12& a = *this;
      return { a.x_.neg(), a.y_ };
   }

   constexpr gfp12 neg() const noexcept {
      const gfp12& a = *this;
      return { a.x_.neg(), a.y_.neg() };
   }

   // Frobenius computes (xω+y)^p = x^p ω·ξ^((p-1)/6) + y^p
   constexpr gfp12 frobenius() const noexcept {
      const gfp12& a = *this;
      gfp12        e = {};
      e.x_ = a.x_.frobenius();
      e.y_ = a.y_.frobenius();
      e.x_ = e.x_.mul_scalar(constants::xi_to_p_minus_1_over_6);
      return e;
   }

   // FrobeniusP2 computes (xω+y)^p² = x^p² ω·ξ^((p²-1)/6) + y^p²
   constexpr gfp12 frobenius_p2() const noexcept {
      const gfp12& a = *this;
      gfp12        e = {};
      e.x_ = a.x_.frobenius_p2();
      e.x_ = e.x_.mul_gfp(constants::xi_to_p_squared_minus_1_over_6);
      e.y_ = a.y_.frobenius_p2();
      return e;
   }

   constexpr gfp12 frobenius_p4() const noexcept {
      const gfp12& a = *this;
      gfp12        e = {};
      e.x_ = a.x_.frobenius_p4();
      e.x_ = e.x_.mul_gfp(constants::xi_to_p_squared_minus_1_over_3);
      e.y_ = a.y_.frobenius_p4();
      return e;
   }

   constexpr gfp12 add(const gfp12& b) const noexcept {
      const gfp12& a = *this;
      return { a.x_.add(b.x_), a.y_.add(b.y_) };
   }

   constexpr gfp12 sub(const gfp12& b) const noexcept {
      const gfp12& a = *this;
      return { a.x_.sub(b.x_), a.y_.sub(b.y_) };
   }

   constexpr gfp12 mul(const gfp12& b) const noexcept {
      const gfp12& a = *this;

      gfp6 tx = a.x_.mul(b.y_);
      gfp6 t  = b.x_.mul(a.y_);
      tx      = tx.add(t);

      gfp6 ty = a.y_.mul(b.y_);
      t       = a.x_.mul(b.x_).mul_tau();

      return { tx, ty.add(t) };
   }

   constexpr gfp12 mul_scalar(const gfp6& b) const noexcept {
      const gfp12& a = *this;
      return { a.x_.mul(b), a.y_.mul(b) }; // need review ???
   }

   constexpr gfp12 exp(std::span<const uint64_t, 4> power) const noexcept {
      const gfp12& a   = *this;
      gfp12        sum = one(), t{};

      for (int i = bitlen(power); i >= 0; i--) {
         t = sum.square();
         if (bit_test(power, i) != 0) {
            sum = t.mul(a);
         } else {
            sum = t;
         }
      }

      return sum;
   }

   constexpr gfp12 square() const noexcept {
      const gfp12& a = *this;
      // Complex squaring algorithm

      gfp6 v0 = a.x_.mul(a.y_);

      gfp6 t  = a.x_.mul_tau();
      t       = a.y_.add(t);
      gfp6 ty = a.x_.add(a.y_);
      ty      = ty.mul(t).sub(v0);
      t       = v0.mul_tau();
      ty      = ty.sub(t);

      return { v0.add(v0), ty };
   }

   constexpr gfp12 invert() const noexcept {
      const gfp12& a = *this;
      // See "Implementing cryptographic pairings", M. Scott, section 3.2.
      // ftp://136.206.11.249/pub/crypto/pairings.pdf

      gfp6 t1 = a.x_.square();
      gfp6 t2 = a.y_.square();
      t1      = t1.mul_tau();
      t1      = t2.sub(t1);
      t2      = t1.invert();

      gfp12 e = {};
      e.x_ = a.x_.neg();
      e.y_ = a.y_;
      e    = e.mul_scalar(t2);
      return e;
   }

   std::string string() const { return "(" + x_.string() + "," + y_.string() + ")"; }

   friend std::ostream& operator<<(std::ostream& os, const gfp12& v) { return os << "(" << v.x_ << "," << v.y_ << ")"; }

   constexpr bool operator==(const gfp12& rhs) const noexcept {
      return x_ == rhs.x_ && y_ == rhs.y_;
   }

   constexpr bool operator!=(const gfp12& rhs) const noexcept { return !(*this == rhs); }
};

} // namespace bn256
