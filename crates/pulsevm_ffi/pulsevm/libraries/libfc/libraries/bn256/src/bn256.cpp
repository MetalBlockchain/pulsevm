#include "curve.h"
#include "optate.h"
#include "random_255.h"
#include <bn256/bn256.h>
#include <vector>

namespace bn256 {

namespace {
   struct unmarshal_error_category : std::error_category {
      const char* name() const noexcept override { return "unmarshall"; }
      std::string message(int ev) const override {
         switch (static_cast<unmarshal_error>(ev)) {
            case unmarshal_error::COORDINATE_EXCEEDS_MODULUS: return "coordinate exceeds modulus";
            case unmarshal_error::COORDINATE_EQUALS_MODULUS: return "coordinate equal modulus";
            case unmarshal_error::MALFORMED_POINT: return "malformed point";
            default: return "(unrecognized error)";
         }
      }
   };
} // namespace

inline std::error_code make_error_code(unmarshal_error e) noexcept {
   static const unmarshal_error_category category;
   return { static_cast<int>(e), category };
}
} // namespace bn256

namespace std {
template <>
struct is_error_code_enum<bn256::unmarshal_error> : true_type {};
} // namespace std

namespace bn256 {

std::tuple<uint255_t, g1> ramdom_g1() {
   auto k = random_255();
   return std::tuple(k, g1::scalar_base_mult(k));
}

g1::g1(const curve_point& p) {
   static_assert(sizeof(*this) == sizeof(curve_point));
   memcpy(this, &p, sizeof(*this));
}

g1 g1::curve_gen{ bn256::curve_gen };

curve_point& g1::p() {
   static_assert(sizeof(*this) == sizeof(curve_point));
   return *reinterpret_cast<curve_point*>(p_);
}

const curve_point& g1::p() const {
   static_assert(sizeof(*this) == sizeof(curve_point));
   return *reinterpret_cast<const curve_point*>(p_);
}

std::string g1::string() const { return p().string(); }

// scalar_base_mult returns g*k where g is the generator of the group
g1 g1::scalar_base_mult(const uint255_t& k) noexcept { return g1{ bn256::curve_gen.mul(k) }; }

// scalar_mult returns a*k
g1 g1::scalar_mult(const uint255_t& k) const noexcept { return g1{ p().mul(k) }; }

// add sets g1 to a+b and then returns g1.
g1 g1::add(const g1& b) const noexcept { return g1{ p().add(b.p()) }; }

// neg sets g1 to -a and then returns g1.
g1 g1::neg() { return g1{ p().neg() }; }

// marshal converts g1 to a byte slice.
void g1::marshal(std::span<uint8_t, 64> m) const noexcept {
   constexpr auto num_bytes = 256 / 8;
   auto           affined   = p().make_affine();
   if (affined.is_infinity()) {
      memset(m.data(), 0, m.size());
      return;
   }

   affined.x_.mont_decode().marshal(m.subspan<0, num_bytes>());
   affined.y_.mont_decode().marshal(m.subspan<num_bytes, num_bytes>());
   return;
}

// unmarshal sets g1 to the result of converting the output of marshal back into
// a group element and then returns unmarshal_status.
std::error_code g1::unmarshal(std::span<const uint8_t, 64> m) noexcept {
   constexpr auto num_bytes = 256 / 8;
   g1&            e         = *this;
   if (auto ec = e.p().x_.unmarshal(m.subspan<0, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = e.p().y_.unmarshal(m.subspan<num_bytes, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;
   e.p().x_ = e.p().x_.mont_encode();
   e.p().y_ = e.p().y_.mont_encode();

   if (e.p().x_ == gfp::zero() && e.p().y_ == gfp::zero()) {
      // This is the point at infinity.
      e.p().y_ = new_gfp(1);
      e.p().z_ = gfp::zero();
      e.p().t_ = gfp::zero();
   } else {
      e.p().z_ = new_gfp(1);
      e.p().t_ = new_gfp(1);
      if (!e.p().is_on_curve()) {
         return unmarshal_error::MALFORMED_POINT;
      }
   }
   return {};
}

std::tuple<uint255_t, g2> ramdom_g2() {
   auto k = random_255();
   return std::make_tuple(k, g2::scalar_base_mult(k));
}

g2::g2(const twist_point& p) {
   static_assert(sizeof(*this) == sizeof(twist_point));
   memcpy(this, &p, sizeof(*this));
}

g2 g2::twist_gen{ bn256::twist_gen };

twist_point& g2::p() {
   static_assert(sizeof(*this) == sizeof(twist_point));
   return *reinterpret_cast<twist_point*>(p_);
}

const twist_point& g2::p() const {
   static_assert(sizeof(*this) == sizeof(twist_point));
   return *reinterpret_cast<const twist_point*>(p_);
}

std::string g2::string() const { return p().string(); }

// scalar_base_mult sets g2 to g*k where g is the generator of the group and then
// returns out.
g2 g2::scalar_base_mult(const uint255_t& k) noexcept { return g2{ bn256::twist_gen.mul(k) }; }

// scalar_mult sets g2 to a*k and then returns g2.
g2 g2::scalar_mult(const uint255_t& k) const noexcept { return g2{ p().mul(k) }; }

// add sets g2 to a+b and then returns g2.
g2 g2::add(const g2& b) const noexcept { return g2{ p().add(b.p()) }; }

// neg sets g2 to -a and then returns g2.
g2 g2::neg() const noexcept { return g2{ p().neg() }; }

// marshal converts g2 to a byte slice.
void g2::marshal(std::span<uint8_t, 128> view) const noexcept {
   constexpr auto num_bytes = 256 / 8;
   auto           affined   = p().make_affine();
   if (affined.is_infinity()) {
      memset(view.data(), 0, view.size());
      return;
   }

   affined.x_.x_.mont_decode().marshal(view.subspan<0, num_bytes>());
   affined.x_.y_.mont_decode().marshal(view.subspan<num_bytes, num_bytes>());
   affined.y_.x_.mont_decode().marshal(view.subspan<num_bytes * 2, num_bytes>());
   affined.y_.y_.mont_decode().marshal(view.subspan<num_bytes * 3, num_bytes>());
}

// unmarshal sets g2 to the result of converting the output of marshal back into
// a group element and then returns unmarshal_status.
std::error_code g2::unmarshal(std::span<const uint8_t, 128> m) noexcept {
   constexpr auto num_bytes = 256 / 8;

   if (auto ec = p().x_.x_.unmarshal(m.subspan<0, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().x_.y_.unmarshal(m.subspan<num_bytes, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.x_.unmarshal(m.subspan<num_bytes * 2, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.y_.unmarshal(m.subspan<num_bytes * 3, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   p().x_.x_ = p().x_.x_.mont_encode();
   p().x_.y_ = p().x_.y_.mont_encode();
   p().y_.x_ = p().y_.x_.mont_encode();
   p().y_.y_ = p().y_.y_.mont_encode();

   if (p().x_.is_zero() && p().y_.is_zero()) {
      // This is the point at infinity.
      p().y_.set_one();
      p().z_.set_zero();
      p().t_.set_zero();
   } else {
      p().z_.set_one();
      p().t_.set_one();
      if (!p().is_on_curve()) {
         return unmarshal_error::MALFORMED_POINT;
      }
   }

   return {};
}

std::string gt::string() const { return p().string(); }

gt::gt(const gfp12& p) {
   static_assert(sizeof(*this) == sizeof(gfp12));
   memcpy(this, &p, sizeof(*this));
}

gfp12& gt::p() {
   static_assert(sizeof(*this) == sizeof(gfp12));
   return *reinterpret_cast<gfp12*>(p_);
}

const gfp12& gt::p() const {
   static_assert(sizeof(*this) == sizeof(gfp12));
   return *reinterpret_cast<const gfp12*>(p_);
}

// scalar_mult return a*k
gt gt::scalar_mult(const uint255_t& k) const noexcept { return gt{ p().exp(k) }; }

// add sets gt to a*b and then returns gt.
gt gt::add(const gt& b) const noexcept { return gt{ p().mul(b.p()) }; }

// neg sets g2 to -a and then returns g2.
gt gt::neg() const noexcept { return gt{ p().conjugate() }; }

// finalize is a linear function from F_p^12 to gt.
gt gt::finalize() const noexcept { return gt{ final_exponentiation(p()) }; }

void gt::marshal(std::span<uint8_t, 384> m) const noexcept {
   constexpr auto num_bytes = 256 / 8;

   p().x_.x_.x_.mont_decode().marshal(m.subspan<0, num_bytes>());
   p().x_.x_.y_.mont_decode().marshal(m.subspan<num_bytes, num_bytes>());
   p().x_.y_.x_.mont_decode().marshal(m.subspan<num_bytes * 2, num_bytes>());
   p().x_.y_.y_.mont_decode().marshal(m.subspan<num_bytes * 3, num_bytes>());
   p().x_.z_.x_.mont_decode().marshal(m.subspan<num_bytes * 4, num_bytes>());
   p().x_.z_.y_.mont_decode().marshal(m.subspan<num_bytes * 5, num_bytes>());
   p().y_.x_.x_.mont_decode().marshal(m.subspan<num_bytes * 6, num_bytes>());
   p().y_.x_.y_.mont_decode().marshal(m.subspan<num_bytes * 7, num_bytes>());
   p().y_.y_.x_.mont_decode().marshal(m.subspan<num_bytes * 8, num_bytes>());
   p().y_.y_.y_.mont_decode().marshal(m.subspan<num_bytes * 9, num_bytes>());
   p().y_.z_.x_.mont_decode().marshal(m.subspan<num_bytes * 10, num_bytes>());
   p().y_.z_.y_.mont_decode().marshal(m.subspan<num_bytes * 11, num_bytes>());
}

std::error_code gt::unmarshal(std::span<const uint8_t, 384> m) noexcept {
   constexpr auto num_bytes = 256 / 8;
   if (auto ec = p().x_.x_.x_.unmarshal(m.subspan<0, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().x_.x_.y_.unmarshal(m.subspan<num_bytes, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().x_.y_.x_.unmarshal(m.subspan<num_bytes * 2, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().x_.y_.y_.unmarshal(m.subspan<num_bytes * 3, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().x_.z_.x_.unmarshal(m.subspan<num_bytes * 4, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().x_.z_.y_.unmarshal(m.subspan<num_bytes * 5, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.x_.x_.unmarshal(m.subspan<num_bytes * 6, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.x_.y_.unmarshal(m.subspan<num_bytes * 7, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.y_.x_.unmarshal(m.subspan<num_bytes * 8, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.y_.y_.unmarshal(m.subspan<num_bytes * 9, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.z_.x_.unmarshal(m.subspan<num_bytes * 10, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   if (auto ec = p().y_.z_.y_.unmarshal(m.subspan<num_bytes * 11, num_bytes>()); ec != unmarshal_error::NO_ERROR)
      return ec;

   p().x_.x_.x_ = p().x_.x_.x_.mont_encode();
   p().x_.x_.y_ = p().x_.x_.y_.mont_encode();
   p().x_.y_.x_ = p().x_.y_.x_.mont_encode();
   p().x_.y_.y_ = p().x_.y_.y_.mont_encode();
   p().x_.z_.x_ = p().x_.z_.x_.mont_encode();
   p().x_.z_.y_ = p().x_.z_.y_.mont_encode();
   p().y_.x_.x_ = p().y_.x_.x_.mont_encode();
   p().y_.x_.y_ = p().y_.x_.y_.mont_encode();
   p().y_.y_.x_ = p().y_.y_.x_.mont_encode();
   p().y_.y_.y_ = p().y_.y_.y_.mont_encode();
   p().y_.z_.x_ = p().y_.z_.x_.mont_encode();
   p().y_.z_.y_ = p().y_.z_.y_.mont_encode();

   return {};
}

// pair calculates an Optimal Ate pairing.
gt pair(const g1& g1, const g2& g2) noexcept { return gt{ optimal_ate(g2.p(), g1.p()) }; }

// pairing_check calculates the Optimal Ate pairing for a set of points.
bool pairing_check(std::span<const g1> a, std::span<const g2> b) noexcept {
   gfp12 acc{};
   acc.set_one();
   for (auto i = 0U; i < a.size(); ++i) {
      if (a[i].p().is_infinity() || b[i].p().is_infinity()) {
         continue;
      }
      acc = acc.mul(miller(b[i].p(), a[i].p()));
   }
   return final_exponentiation(acc).is_one();
}

int32_t pairing_check(std::span<const uint8_t> marshaled_g1g2_pair, std::function<void()> yield) {
   const int marshaled_g1g2_pair_size = 64 + 128;
   if (marshaled_g1g2_pair.size() % marshaled_g1g2_pair_size != 0)
      return -1;

   const uint8_t* data     = marshaled_g1g2_pair.data();
   const uint8_t* data_end = marshaled_g1g2_pair.data() + marshaled_g1g2_pair.size();

   gfp12 acc{};
   acc.set_one();
   while (data < data_end) {
      g1 a;
      if (auto err = a.unmarshal(std::span<const uint8_t, 64>{ data, 64 }); err)
         return -1;
      data += 64;
      g2 b;
      if (auto err = b.unmarshal(std::span<const uint8_t, 128>{ data, 128 }); err)
         return -1;
      data += 128;
      if (a.p().is_infinity() || b.p().is_infinity()) {
         continue;
      }
      acc = acc.mul(miller(b.p(), a.p()));
      yield();
   }

   return final_exponentiation(acc).is_one();
}

int32_t g1_add(std::span<const uint8_t, 64> marshaled_lhs, std::span<const uint8_t, 64> marshaled_rhs,
               std::span<uint8_t, 64> result) {
   g1 a;
   if (auto err = a.unmarshal(marshaled_lhs); err)
      return -1;
   g1 b;
   if (auto err = b.unmarshal(marshaled_rhs); err)
      return -1;

   a.add(b).marshal(result);
   return 0;
}

int32_t g1_scalar_mul(std::span<const uint8_t, 64> marshaled_g1, std::span<const uint8_t, 32> scalar,
                      std::span<uint8_t, 64> result) {

   g1 a;
   if (auto err = a.unmarshal(marshaled_g1); err)
      return -1;
   uint255_t k;
   std::copy(scalar.rbegin(), scalar.rend(), (uint8_t*)&k);
   a.scalar_mult(k).marshal(result);
   return 0;
}

// miller applies Miller's algorithm, which is a bilinear function from
// the source groups to F_p^12. miller(g1, g2).finalize() is equivalent
// to pair(g1,g2).
gt miller(const g1& g1, const g2& g2) noexcept { return gt{ miller(g2.p(), g1.p()) }; }

std::ostream& operator<<(std::ostream& os, const gt& v) { return os << v.p(); }
} // namespace bn256
