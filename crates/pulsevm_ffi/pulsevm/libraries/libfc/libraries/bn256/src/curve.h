#pragma once

#include "gfp2.h"
#include "lattice.h"

namespace bn256 {

// curvePoint implements the elliptic curve y²=x³+3. Points are kept in Jacobian
// form and t=z² when valid. G₁ is the set of points of this curve on GF(p).
struct curve_point {
   // value is xτ² + yτ + z
   gfp x_;
   gfp y_;
   gfp z_;
   gfp t_;

#if defined (__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif
   static constexpr curve_point infinity() { return { { 0 }, new_gfp(1), { 0 }, { 0 } }; };
   constexpr bool               is_infinity() const noexcept { return z_ == gfp{ 0 }; }

   static constexpr gfp curve_b = new_gfp(3);

#if defined (__clang__)
#pragma clang diagnostic pop
#endif

   std::string string() const {
      auto tmp = make_affine();

      gfp x = tmp.x_.mont_decode();
      gfp y = tmp.y_.mont_decode();

      std::string ret;
      ret.reserve(132);
      ret.append("(");
      ret.append(x.string());
      ret.append(",");
      ret.append(y.string());
      ret.append(")");

      return ret;
   }

   constexpr bool is_on_curve() const noexcept {
      auto c = make_affine();
      if (c.is_infinity()) {
         return true;
      }
      gfp y2 = c.y_.mul(c.y_);
      gfp x3 = c.x_.mul(c.x_);
      x3     = x3.mul(c.x_);
      x3     = x3.add(curve_b);
      return y2 == x3;
   }

   constexpr curve_point add(const curve_point& b) const noexcept {
      const curve_point& a = *this;

      if (a.is_infinity()) {
         return b;
      }
      if (b.is_infinity()) {
         return a;
      }

      // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3

      // Normalize the points by replacing a = [x1:y1:z1] and b = [x2:y2:z2]
      // by [u1:s1:z1·z2] and [u2:s2:z1·z2]
      // where u1 = x1·z2², s1 = y1·z2³ and u1 = x2·z1², s2 = y2·z1³
      gfp z12 = a.z_.mul(a.z_);
      gfp z22 = b.z_.mul(b.z_);

      gfp u1 = a.x_.mul(z22);
      gfp u2 = b.x_.mul(z12);

      gfp t  = b.z_.mul(z22);
      gfp s1 = a.y_.mul(t);

      t      = a.z_.mul(z12);
      gfp s2 = b.y_.mul(t);

      // Compute x_ = (2h)²(s²-u1-u2)
      // where s = (s2-s1)/(u2-u1) is the slope of the line through
      // (u1,s1) and (u2,s2). The extra factor 2h = 2(u2-u1) comes from the value of z_ below.
      // This is also:
      // 4(s2-s1)² - 4h²(u1+u2) = 4(s2-s1)² - 4h³ - 4h²(2u1)
      //                        = r² - j - 2v
      // with the notations below.
      gfp h = u2.sub(u1);

      bool x_equal = h == gfp{};

      t = h.add(h);
      // i = 4h²
      gfp i = t.mul(t);
      // j = 4h³
      gfp j = h.mul(i);

      t            = s2.sub(s1);
      bool y_equal = t == gfp{};
      if (x_equal && y_equal) {
         return a.double_();
      }
      gfp r = t.add(t);

      gfp v = u1.mul(i);

      // t4 = 4(s2-s1)²
      gfp t4 = r.mul(r);
      t      = v.add(v);
      gfp t6 = t4.sub(j);

      curve_point c = {};

      c.x_ = t6.sub(t);

      // Set y_ = -(2h)³(s1 + s*(x_/4h²-u1))
      // This is also
      // y_ = - 2·s1·j - (s2-s1)(2x - 2i·u1) = r(v-x_) - 2·s1·j
      t    = v.sub(c.x_); // t7
      t4   = s1.mul(j);   // t8
      t6   = t4.add(t4);  // t9
      t4   = r.mul(t);    // t10
      c.y_ = t4.sub(t6);

      // Set z_ = 2(u2-u1)·z1·z2 = 2h·z1·z2
      t    = a.z_.add(b.z_); // t11
      t4   = t.mul(t);       // t12
      t    = t4.sub(z12);    // t13
      t4   = t.sub(z22);     // t14
      c.z_ = t4.mul(h);
      c.t_ = {};
      return c;
   }

   constexpr curve_point double_() const noexcept {
      const curve_point& a = *this;

      // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3

      gfp A = a.x_.mul(a.x_);
      gfp B = a.y_.mul(a.y_);
      gfp C = B.mul(B);

      gfp t  = a.x_.add(B);
      gfp t2 = t.mul(t);
      t      = t2.sub(A);
      t2     = t.sub(C);

      gfp d = t2.add(t2);
      t     = A.add(A);
      gfp e = t.add(A);
      gfp f = e.mul(e);

      t = d.add(d);
      curve_point c{};
      c.x_ = f.sub(t);

      c.z_ = a.y_.mul(a.z_);
      c.z_ = c.z_.add(c.z_);

      t    = C.add(C);
      t2   = t.add(t);
      t    = t2.add(t2);
      c.y_ = d.sub(c.x_);
      t2   = e.mul(c.y_);
      c.y_ = t2.sub(t);
      c.t_ = {};
      return c;
   }

   curve_point mul(std::span<const uint64_t, 4> scalar) const noexcept {
      const curve_point& a = *this;

      std::array<curve_point, 4> precomp{};

      precomp[1]    = a;
      precomp[2]    = a;
      precomp[2].x_ = precomp[2].x_.mul(constants::xi_to_2p_squared_minus_2_over_3);
      precomp[3]    = precomp[1].add(precomp[2]);

      auto        sum = infinity();
      curve_point t{};

      curve_lattice.foreach_multi_scalar(scalar, [&sum, &t, &precomp] (uint8_t v){
         t = sum.double_();
         if (v == 0) {
            sum = t;
         } else {
            sum = t.add(precomp[v]);
         }
      });

      return sum;
   }

   constexpr curve_point make_affine() const noexcept {
      if (z_ == new_gfp(1)) {
         return *this;
      } else if (z_ == new_gfp(0)) {
         return { {}, new_gfp(1), new_gfp(0), {} };
      }

      curve_point c{ x_, y_, new_gfp(1), new_gfp(1) };

      gfp z_inv = z_.invert();

      gfp t      = c.y_.mul(z_inv);
      gfp z_inv2 = z_inv.mul(z_inv);
      c.x_       = c.x_.mul(z_inv2);
      c.y_       = t.mul(z_inv2);

      return c;
   }

   constexpr curve_point neg() const noexcept {
      const curve_point& a = *this;
      return { a.x_, a.y_.neg(), a.z_, gfp{} };
   }

   constexpr bool operator==(const curve_point& rhs) const noexcept {
      return x_ == rhs.x_ && y_ == rhs.y_ && z_ == rhs.z_ && t_ == rhs.t_;
   }

   constexpr bool operator!=(const curve_point& rhs) const noexcept { return !(*this == rhs); }
};

inline constexpr curve_point curve_gen = { new_gfp(1), new_gfp(2), new_gfp(1), new_gfp(1) };

inline std::ostream& operator<<(std::ostream& os, const curve_point& v) { return os << v.string(); }
} // namespace bn256
