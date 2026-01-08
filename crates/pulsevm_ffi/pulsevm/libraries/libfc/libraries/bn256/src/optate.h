#include "constants.h"
#include <tuple>
#include "twist.h"
#include "gfp6.h"
#include "gfp12.h"

namespace bn256 {

constexpr auto line_function_add(const twist_point& r, const twist_point& p, const curve_point& q, const gfp2& r2) noexcept {
   // See the mixed addition algorithm from "Faster Computation of the
   // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf
   gfp2 B = p.x_.mul(r.t_);

   gfp2 D = p.y_.add(r.z_);
   D      = D.square();
   D      = D.sub(r2);
   D      = D.sub(r.t_);
   D      = D.mul(r.t_);

   gfp2 H = B.sub(r.x_);
   gfp2 I = H.square();

   gfp2 E = I.add(I);
   E      = E.add(E);

   gfp2 J = H.mul(E);

   gfp2 L1 = D.sub(r.y_);
   L1      = L1.sub(r.y_);

   gfp2 V = r.x_.mul(E);

   twist_point rOut{};
   rOut.x_ = L1.square().sub(J).sub(V).sub(V);

   rOut.z_ = r.z_.add(H).square().sub(r.t_).sub(I);

   gfp2 t  = V.sub(rOut.x_);
   t       = t.mul(L1);
   gfp2 t2 = r.y_.mul(J);
   t2      = t2.add(t2);
   rOut.y_ = t.sub(t2);

   rOut.t_ = rOut.z_.square();

   t = p.y_.add(rOut.z_).square().sub(r2).sub(rOut.t_);

   t2     = L1.mul(p.x_);
   t2     = t2.add(t2);
   gfp2 a = t2.sub(t);

   gfp2 c = rOut.z_.mul_scalar(q.y_);
   c      = c.add(c);

   gfp2 b{};
   b = b.sub(L1);
   b = b.mul_scalar(q.x_);
   b = b.add(b);

   return std::make_tuple(a, b, c, rOut);
}

constexpr auto line_function_double(const twist_point& r, const curve_point& q) noexcept {

   // See the doubling algorithm for a=0 from "Faster Computation of the
   // Tate Pairing", http://arxiv.org/pdf/0904.0854v3.pdf

   gfp2 A = r.x_.square();
   gfp2 B = r.y_.square();
   gfp2 C = B.square();

   gfp2 D = r.x_.add(B);
   D      = D.square();
   D      = D.sub(A);
   D      = D.sub(C);
   D      = D.add(D);

   gfp2 E = A.add(A);
   E      = E.add(A);

   gfp2 G = E.square();

   twist_point rOut{};
   rOut.x_ = G.sub(D);
   rOut.x_ = rOut.x_.sub(D);

   rOut.z_ = r.y_.add(r.z_);
   rOut.z_ = rOut.z_.square();
   rOut.z_ = rOut.z_.sub(B);
   rOut.z_ = rOut.z_.sub(r.t_);

   rOut.y_ = D.sub(rOut.x_);
   rOut.y_ = rOut.y_.mul(E);
   gfp2 t  = C.add(C);
   t       = t.add(t);
   t       = t.add(t);
   rOut.y_ = rOut.y_.sub(t);

   rOut.t_ = rOut.z_.square();

   t      = E.mul(r.t_);
   t      = t.add(t);
   gfp2 b = {};
   b      = b.sub(t);
   b      = b.mul_scalar(q.x_);

   gfp2 a = r.x_.add(E);
   a      = a.square();
   a      = a.sub(A);
   a      = a.sub(G);
   t      = B.add(B);
   t      = t.add(t);
   a      = a.sub(t);

   gfp2 c = rOut.z_.mul(r.t_);
   c      = c.add(c);
   c      = c.mul_scalar(q.y_);

   return std::make_tuple(a, b, c, rOut);
}

constexpr void mul_line(gfp12& ret, const gfp2& a, const gfp2& b, const gfp2& c) {

   gfp6 a2{ gfp2::zero(), a, b };
   a2      = a2.mul(ret.x_);
   gfp6 t3 = ret.y_.mul_scalar(c);

   gfp2 t = b.add(c);
   gfp6 t2{ gfp2::zero(), a, t };
   ret.x_ = ret.x_.add(ret.y_);

   ret.y_ = t3;

   ret.x_ = ret.x_.mul(t2);
   ret.x_ = ret.x_.sub(a2);
   ret.x_ = ret.x_.sub(ret.y_);
   a2     = a2.mul_tau();
   ret.y_ = ret.y_.add(a2);
}

// sixuPlus2NAF is 6u+2 in non-adjacent form.
constexpr std::array<int8_t, 65> six_u_plus_2_naf = {
   0,  0, 0, 1,  0, 1, 0, -1, 0, 0, 1, -1, 0, 0,  1,  0, 0, 1, 1, 0, -1, 0,
   0,  1, 0, -1, 0, 0, 0, 0,  1, 1, 1, 0,  0, -1, 0,  0, 1, 0, 0, 0, 0,  0,
   -1, 0, 0, 1,  1, 0, 0, -1, 0, 0, 0, 1,  1, 0,  -1, 0, 0, 1, 0, 1, 1 };

// miller implements the Miller loop for calculating the Optimal Ate pairing.
// See algorithm 1 from http://cryptojedi.org/papers/dclxvi-20100714.pdf
inline gfp12 miller(const twist_point& q, const curve_point& p) noexcept {
   gfp12 ret = gfp12::one();

   twist_point a_affine = q.make_affine();
   curve_point b_affine = p.make_affine();

   twist_point minus_a = a_affine.neg();

   twist_point r = a_affine;

   gfp2 r2 = a_affine.y_.square();

   for (auto i = six_u_plus_2_naf.size() - 1; i > 0; i--) {
      auto [a, b, c, newR] = line_function_double(r, b_affine);
      if (i != six_u_plus_2_naf.size() - 1) {
         ret = ret.square();
      }

      mul_line(ret, a, b, c);
      r = newR;

      switch (six_u_plus_2_naf[i - 1]) {
         case 1: std::tie(a, b, c, newR) = line_function_add(r, a_affine, b_affine, r2); break;
         case -1: std::tie(a, b, c, newR) = line_function_add(r, minus_a, b_affine, r2); break;
         default: continue;
      }

      mul_line(ret, a, b, c);
      r = newR;
   }

   // In order to calculate Q1 we have to convert q from the sextic twist
   // to the full GF(p^12) group, apply the Frobenius there, and convert
   // back.
   //
   // The twist isomorphism is (x', y') -> (xω², yω³). If we consider just
   // x for a moment, then after applying the Frobenius, we have x̄ω^(2p)
   // where x̄ is the conjugate of x. If we are going to apply the inverse
   // isomorphism we need a value with a single coefficient of ω² so we
   // rewrite this as x̄ω^(2p-2)ω². ξ⁶ = ω and, due to the construction of
   // p, 2p-2 is a multiple of six. Therefore we can rewrite as
   // x̄ξ^((p-1)/3)ω² and applying the inverse isomorphism eliminates the
   // ω².
   //
   // A similar argument can be made for the y value.

   twist_point q1{};
   q1.x_ = a_affine.x_.conjugate();
   q1.x_ = q1.x_.mul(constants::xi_to_p_minus_1_over_3);

   q1.y_ = a_affine.y_.conjugate();
   q1.y_ = q1.y_.mul(constants::xi_to_p_minus_1_over_2);
   q1.z_.set_one();
   q1.t_.set_one();

   // For Q2 we are applying the p² Frobenius. The two conjugations cancel
   // out and we are left only with the factors from the isomorphism. In
   // the case of x, we end up with a pure number which is why
   // xiToPSquaredMinus1Over3 is ∈ GF(p). With y we get a factor of -1. We
   // ignore this to end up with -Q2.

   twist_point minus_q2{};
   minus_q2.x_ = a_affine.x_.mul_scalar(constants::xi_to_p_squared_minus_1_over_3);
   minus_q2.y_ = a_affine.y_;
   minus_q2.z_.set_one();
   minus_q2.t_.set_one();

   r2                   = q1.y_.square();
   auto [a, b, c, newR] = line_function_add(r, q1, b_affine, r2);
   mul_line(ret, a, b, c);
   r = newR;

   r2                      = minus_q2.y_.square();
   std::tie(a, b, c, newR) = line_function_add(r, minus_q2, b_affine, r2);
   mul_line(ret, a, b, c);
   r = newR;

   return ret;
}

// finalExponentiation computes the (p¹²-1)/Order-th power of an element of
// GF(p¹²) to obtain an element of GT (steps 13-15 of algorithm 1 from
// http://cryptojedi.org/papers/dclxvi-20100714.pdf)
inline gfp12 final_exponentiation(const gfp12& in) noexcept {
   gfp12 t1{};

   // This is the p^6-Frobenius
   t1.x_ = in.x_.neg();
   t1.y_ = in.y_;

   gfp12 inv = in.invert();
   t1        = t1.mul(inv);

   gfp12 t2 = t1.frobenius_p2();
   t1       = t1.mul(t2);

   gfp12 fp  = t1.frobenius();
   gfp12 fp2 = t1.frobenius_p2();
   gfp12 fp3 = fp2.frobenius();

   gfp12 fu  = t1.exp(constants::u);
   gfp12 fu2 = fu.exp(constants::u);
   gfp12 fu3 = fu2.exp(constants::u);

   gfp12 y3   = fu.frobenius();
   gfp12 fu2p = fu2.frobenius();
   gfp12 fu3p = fu3.frobenius();
   gfp12 y2   = fu2.frobenius_p2();

   gfp12 y0 = fp.mul(fp2);
   y0       = y0.mul(fp3);

   gfp12 y1 = t1.conjugate();
   gfp12 y5 = fu2.conjugate();
   y3       = y3.conjugate();
   gfp12 y4 = fu.mul(fu2p);
   y4       = y4.conjugate();

   gfp12 y6 = fu3.mul(fu3p);
   y6       = y6.conjugate();

   gfp12 t0 = y6.square();
   t0       = t0.mul(y4);
   t0       = t0.mul(y5);
   t1       = y3.mul(y5);
   t1       = t1.mul(t0);
   t0       = t0.mul(y2);
   t1       = t1.square();
   t1       = t1.mul(t0);
   t1       = t1.square();
   t0       = t1.mul(y1);
   t1       = t1.mul(y0);
   t0       = t0.square();
   t0       = t0.mul(t1);

   return t0;
}

inline gfp12 optimal_ate(const twist_point& a, const curve_point& b) noexcept {
   auto e   = miller(a, b);
   auto ret = final_exponentiation(e);

   if (a.is_infinity() || b.is_infinity()) {
      ret.set_one();
   }
   return ret;
}
} // namespace bn256
