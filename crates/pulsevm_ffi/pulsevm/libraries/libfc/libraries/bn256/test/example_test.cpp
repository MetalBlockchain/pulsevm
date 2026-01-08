#include <bn256/bn256.h>
#include <catch2/catch_test_macros.hpp>
#include <random_255.h>

TEST_CASE("test example pair", "[example]") {

   auto a = bn256::random_255();
   auto b = bn256::random_255();
   auto c = bn256::random_255();

   auto pa = bn256::g1::scalar_base_mult(a);
   auto qa = bn256::g2::scalar_base_mult(a);

   auto pb = bn256::g1::scalar_base_mult(b);
   auto qb = bn256::g2::scalar_base_mult(b);

   auto pc = bn256::g1::scalar_base_mult(c);
   auto qc = bn256::g2::scalar_base_mult(c);

   auto k1 = bn256::pair(pb, qc).scalar_mult(a);
   auto k2 = bn256::pair(pc, qa).scalar_mult(b);
   auto k3 = bn256::pair(pa, qb).scalar_mult(c);

   CHECK(k1 == k2);
   CHECK(k1 == k3);
}
