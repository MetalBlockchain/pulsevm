#pragma once

#include "gfp2.h"
#include "constants.h"

namespace bn256 {

// twistPoint implements the elliptic curve y²=x³+3/ξ over GF(p²). Points are
// kept in Jacobian form and t=z² when valid. The group G₂ is the set of
// n-torsion points of this curve over GF(p²) (where n = Order)
struct twist_point {
   gfp2 x_;
   gfp2 y_;
   gfp2 z_;
   gfp2 t_;

   static constexpr twist_point infinity() noexcept {
      return { gfp2::zero(), gfp2::one(), gfp2::zero(), gfp2::zero() };
   }

   [[nodiscard]] constexpr bool is_infinity() const noexcept { return z_ == gfp2::zero(); }
#if defined (__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif
   static constexpr gfp2 twist_b = {
      { 0x38e7ecccd1dcff67, 0x65f0b37d93ce0d3e, 0xd749d0dd22ac00aa, 0x0141b9ce4a688d4d },
      { 0x3bf938e377b802a8, 0x020b1b273633535d, 0x26b7edf049755260, 0x2514c6324384a86d },
   };
#if defined (__clang__)
#pragma clang diagnostic pop
#endif

   std::string string() const {
      auto tmp = make_affine();
      auto x   = gfp2::gfp2_decode(tmp.x_);
      auto y   = gfp2::gfp2_decode(tmp.y_);

      std::string ret;
      ret.reserve(265);
      ret.append("(");
      ret.append(x.string());
      ret.append(", ");
      ret.append(y.string());
      ret.append(")");
      return ret;
   }

   constexpr bool is_on_curve() const noexcept {
      auto c = make_affine();
      if (c.is_infinity()) {
         return true;
      }

      gfp2 y2 = c.y_.square();
      gfp2 x3 = c.x_.square().mul(c.x_).add(twist_b);

      if (y2 != x3)
         return false;

      twist_point cneg = c.mul(constants::order);
      return cneg.z_.is_zero();
   }

   constexpr twist_point add(const twist_point& b) const noexcept {
      const twist_point& a = *this;

      if (a.is_infinity()) {
         return b;
      }
      if (b.is_infinity()) {
         return a;
      }

      // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
      gfp2 z12 = a.z_.square();
      gfp2 z22 = b.z_.square();
      gfp2 u1  = a.x_.mul(z22);
      gfp2 u2  = b.x_.mul(z12);

      gfp2 t  = b.z_.mul(z22);
      gfp2 s1 = a.y_.mul(t);

      t       = a.z_.mul(z12);
      gfp2 s2 = b.y_.mul(t);

      gfp2 h       = u2.sub(u1);
      bool x_equal = h.is_zero();

      t      = h.add(h);
      gfp2 i = t.square();
      gfp2 j = h.mul(i);

      t            = s2.sub(s1);
      bool y_equal = t.is_zero();
      if (x_equal && y_equal) {
         return a.double_();
      }

      gfp2 r = t.add(t);

      gfp2 v = u1.mul(i);

      twist_point c = {};

      gfp2 t4 = r.square();
      t       = v.add(v);
      gfp2 t6 = t4.sub(j);
      c.x_    = t6.sub(t);

      t    = v.sub(c.x_); // t7
      t4   = s1.mul(j);   // t8
      t6   = t4.add(t4);  // t9
      t4   = r.mul(t);    // t10
      c.y_ = t4.sub(t6);

      t    = a.z_.add(b.z_); // t11
      t4   = t.square();     // t12
      t    = t4.sub(z12);    // t13
      t4   = t.sub(z22);     // t14
      c.z_ = t4.mul(h);
      c.t_ = {};
      return c;
   }

   constexpr twist_point double_() const noexcept {
      const twist_point& a = *this;

      // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
      gfp2 A = a.x_.square();
      gfp2 B = a.y_.square();
      gfp2 C = B.square();

      gfp2 t  = a.x_.add(B);
      gfp2 t2 = t.square();
      t       = t2.sub(A);
      t2      = t.sub(C);
      gfp2 d  = t2.add(t2);
      t       = A.add(A);
      gfp2 e  = t.add(A);
      gfp2 f  = e.square();

      twist_point c = {};

      t    = d.add(d);
      c.x_ = f.sub(t);

      c.z_ = a.y_.mul(a.z_);
      c.z_ = c.z_.add(c.z_);

      t    = C.add(C);
      t2   = t.add(t);
      t    = t2.add(t2);
      c.y_ = d.sub(c.x_);
      t2   = e.mul(c.y_);
      c.y_ = t2.sub(t);
      return c;
   }

   constexpr twist_point mul(std::span<const uint64_t, 4> scalar) const noexcept {
      const twist_point& a = *this;
      twist_point        sum{}, t{};

      for (int i = bitlen(scalar); i >= 0; i--) {
         t = sum.double_();
         if (bit_test(scalar, i)) {
            sum = t.add(a);
         } else {
            sum = t;
         }
      }

      return sum;
   }

   constexpr twist_point make_affine() const noexcept {
      if (z_.is_one()) {
         return *this;
      } else if (z_.is_zero()) {
         return { gfp2::zero(), gfp2::one(), gfp2::zero() };
      }

      gfp2 z_inv  = z_.invert();
      gfp2 t      = y_.mul(z_inv);
      gfp2 z_inv2 = z_inv.square();

      twist_point c{};
      c.y_ = t.mul(z_inv2);
      t    = x_.mul(z_inv2);
      c.x_ = t;
      c.z_.set_one();
      c.t_.set_one();
      return c;
   }

   constexpr twist_point neg() const noexcept {
      const twist_point& a = *this;
      return { a.x_, a.y_.neg(), a.z_, gfp2::zero() };
   }

   constexpr bool operator==(const twist_point& rhs) const noexcept {
      return x_ == rhs.x_ && y_ == rhs.y_ && z_ == rhs.z_ && t_ == rhs.t_;
   }

   constexpr bool operator!=(const twist_point& rhs) const noexcept { return !(*this == rhs); }
};

#if defined (__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif

inline constexpr twist_point twist_gen = {
   {
         { 0xafb4737da84c6140, 0x6043dd5a5802d8c4, 0x09e950fc52a02f86, 0x14fef0833aea7b6b },
         { 0x8e83b5d102bc2026, 0xdceb1935497b0172, 0xfbb8264797811adf, 0x19573841af96503b },
   },
   {
         { 0x64095b56c71856ee, 0xdc57f922327d3cbb, 0x55f935be33351076, 0x0da4a0e693fd6482 },
         { 0x619dfa9d886be9f6, 0xfe7fd297f59e9b78, 0xff9e1a62231b7dfe, 0x28fd7eebae9e4206 },
   },
   { new_gfp(0), new_gfp(1) },
   { new_gfp(0), new_gfp(1) }
};
#if defined (__clang__)
#pragma clang diagnostic pop
#endif

inline std::ostream& operator<<(std::ostream& os, const twist_point& v) { return os << v.string(); }
} // namespace bn256
