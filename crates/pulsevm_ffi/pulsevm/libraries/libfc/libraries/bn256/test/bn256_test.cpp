#include "curve.h"
#include "twist.h"
#include <bn256/bn256.h>
#include <catch2/catch_test_macros.hpp>
#include <memory>

#if defined(__clang__)
#   pragma clang diagnostic ignored "-Wmissing-braces"
#endif

TEST_CASE("test g1 marshall", "[bn256]") {
   auto [_, ga] = bn256::ramdom_g1();
   std::array<uint8_t, 64> ma, mb;
   ga.marshal(ma);

   bn256::g1 gb{};

   REQUIRE(gb.unmarshal(ma) == std::error_code{});

   gb.marshal(mb);
   CHECK(ma == mb); // "fail if bytes are different"
}

TEST_CASE("test g2 marshall", "[bn256]") {
   auto [_, ga] = bn256::ramdom_g2();
   std::array<uint8_t, 128> ma, mb;
   ga.marshal(ma);

   bn256::g2 gb{};
   REQUIRE(gb.unmarshal(ma) == std::error_code{});
   gb.marshal(mb);
   CHECK(ma == mb); // "fail if bytes are different"
}

TEST_CASE("test bilinearity", "[bn256]") {
   bn256::g1 c1{ bn256::curve_gen };
   bn256::g2 c2{ bn256::twist_gen };

   for (auto i = 0U; i < 2; ++i) {
      auto [a, p1] = bn256::ramdom_g1();
      auto [b, p2] = bn256::ramdom_g2();
      bn256::gt e1 = bn256::pair(p1, p2);

      bn256::gt e2 = bn256::pair(c1, c2);
      e2           = e2.scalar_mult(a);
      e2           = e2.scalar_mult(b);
      CHECK(e1 == e2); // "fail if keys didn't agree"
   }
}

TEST_CASE("test tripartite_diffie_hellman", "[bn256]") {

   std::array<uint64_t, 4> a = { (uint64_t)rand(), 0, 0, 0 };
   std::array<uint64_t, 4> b = { (uint64_t)rand(), 0, 0, 0 };
   std::array<uint64_t, 4> c = { (uint64_t)rand(), 0, 0, 0 };

   bn256::g1 pa, pb, pc;
   bn256::g2 qa, qb, qc;

   REQUIRE(pa.unmarshal(bn256::g1::scalar_base_mult(a).marshal()) == std::error_code{});
   REQUIRE(qa.unmarshal(bn256::g2::scalar_base_mult(a).marshal()) == std::error_code{});
   REQUIRE(pb.unmarshal(bn256::g1::scalar_base_mult(b).marshal()) == std::error_code{});
   REQUIRE(qb.unmarshal(bn256::g2::scalar_base_mult(b).marshal()) == std::error_code{});
   REQUIRE(pc.unmarshal(bn256::g1::scalar_base_mult(c).marshal()) == std::error_code{});
   REQUIRE(qc.unmarshal(bn256::g2::scalar_base_mult(c).marshal()) == std::error_code{});

   auto k1_bytes = bn256::pair(pb, qc).scalar_mult(a).marshal();
   auto k2_bytes = bn256::pair(pc, qa).scalar_mult(b).marshal();
   auto k3_bytes = bn256::pair(pa, qb).scalar_mult(c).marshal();

   CHECK(k1_bytes == k2_bytes); // "fail if keys didn't agree"
   CHECK(k2_bytes == k3_bytes);
}

TEST_CASE("test g2_self_addition", "[bn256]") {
   std::array<uint64_t, 4> s = { (uint64_t)rand(), 0, 0, 0 };
   bn256::g2               p = bn256::g2::scalar_base_mult(s);
   REQUIRE(p.p().is_on_curve()); // "fail if p isn't on curve"

   p      = p.add(p);
   auto m = p.marshal();
   CHECK(p.unmarshal(m) == std::error_code{}); // "fail if unmarshalling p.Add(p, p) ∉ G₂"
}

TEST_CASE("test twist point mul", "[bn256]") {
   const bn256::uint255_t k = { 0x1ee155ddfb789c17, 0x2fe306f28ed08574, 0x8f80f739c3f3b7a3, 0xa2422041c5891a94 };
   bn256::g2              p = bn256::g2::scalar_base_mult(k);

   const bn256::twist_point expected = {
      {
            { 0x05ec0a32b82b74d0, 0x79226658a77fa893, 0x127032ff3328c543, 0x1e7d6db7d450f4be },
            { 0x8e35b004a08c0b11, 0x791ad513fcc41a41, 0x8842fab42e7eba4b, 0x03da6b5fc89c90ab },
      },
      {
            { 0xd2f8eadf4e38ca86, 0x4b9fed22bbe0dc94, 0x1e29c03a8cf24db7, 0x26ec1edd6d3dac31 },
            { 0x7c151529d654d2d2, 0x273c7512c431ee15, 0xcc3179ec7d8d6148, 0x15a47d30dd1e78e4 },
      },
      {
            { 0xb80ceea187dac34b, 0xc6fe051c511b1d67, 0x1b3efe1172f2c0d2, 0x0b34a4dba3c1edd4 },
            { 0xfbfc4c2759d29b67, 0x01e318b3356b84c8, 0xf4c1b7f4bd86512a, 0x26f9c677782ad979 },
      },
      { bn256::new_gfp(0), bn256::new_gfp(0) }
   };

   CHECK(p.p() == expected);
}

std::vector<uint8_t> unhex(const char* str, std::size_t len) {
   std::vector<uint8_t> result;
   result.resize((len + 1) / 2);

   auto to_nibble = [](char c) -> uint8_t {
      if (c >= 'a' && c <= 'f')
         return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
         return c - 'A' + 10;
      if (c >= '0' && c <= '9')
         return c - '0';
      else
         return 0;
   };

   int i = 0;
   int j = 0;
   if (len % 2) {
      result[0] = to_nibble(str[0]);
      ++i;
      ++j;
   }
   while (str[i] != 0) {
      result[j++] = to_nibble(str[i]) << 4 | to_nibble(str[i + 1]);
      i += 2;
   }
   return result;
}

std::vector<uint8_t> operator""_unhex(const char* str, std::size_t len) { return unhex(str, len); }

std::vector<uint8_t> unhex(const char* str) { return unhex(str, strlen(str)); }

static int32_t g1_add(std::vector<uint8_t>&& marshaled_lhs,
                      std::vector<uint8_t>&& marshaled_rhs,
                      std::vector<uint8_t>& result)
{
   return bn256::g1_add(std::span<const uint8_t, 64>(marshaled_lhs),
                        std::span<const uint8_t, 64>(marshaled_rhs),
                        std::span<uint8_t, 64>(result));
}

static int32_t g1_scalar_mul(std::vector<uint8_t>&& marshaled_g1,
                             std::vector<uint8_t>&&  scalar,
                             std::vector<uint8_t>& result) {
   return bn256::g1_scalar_mul(std::span<const uint8_t, 64>(marshaled_g1),
                               std::span<const uint8_t, 32>(scalar),
                               std::span<uint8_t, 64>(result));
}

TEST_CASE("test g1_add", "[bn256]") {

   std::vector<uint8_t> result;
   result.resize(64);

   // test (2 valid points, both on curve)
   CHECK(g1_add(
            "222480c9f95409bfa4ac6ae890b9c150bc88542b87b352e92950c340458b0c092976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2"_unhex,
            "1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f53322a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844"_unhex,
            result) == 0);
   CHECK(result ==
         "16c7c4042e3a725ddbacf197c519c3dcad2bc87dfd9ac7e1e1631154ee0b7d9c19cd640dd28c9811ebaaa095a16b16190d08d6906c4f926fce581985fe35be0e"_unhex);

   // test (2 valid points, P1 not on curve)
   CHECK(g1_add(
            "222480c9f95409bfa4ac6ae890b9c150bc88542b87b352e92950c340458b0c092976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2"_unhex,
            "2a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce46498441bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f5332"_unhex,
               result) == -1);

   //|Fp| = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
   // test (P1.x=|Fp|)
   CHECK(g1_add(
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd472976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2"_unhex,
            "1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f53322a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844"_unhex,
            result) == -1);

   // test (P1=(0,0))
   CHECK(g1_add(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"_unhex,
            "1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f53322a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844"_unhex,
            result) == 0);
   CHECK(result ==
         "1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f53322a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844"_unhex);
}

TEST_CASE("test g1_scalar_mul", "[bn256]") {
   std::vector<uint8_t> result;
   result.resize(64);

   CHECK(g1_scalar_mul(
            "007c43fcd125b2b13e2521e395a81727710a46b34fe279adbf1b94c72f7f91360db2f980370fb8962751c6ff064f4516a6a93d563388518bb77ab9a6b30755be"_unhex,
            "0312ed43559cf8ecbab5221256a56e567aac5035308e3f1d54954d8b97cd1c9b"_unhex, result) == 0);
   CHECK(result ==
         "2d66cdeca5e1715896a5a924c50a149be87ddd2347b862150fbb0fd7d0b1833c11c76319ebefc5379f7aa6d85d40169a612597637242a4bbb39e5cd3b844becd"_unhex);

   // test (P1 not on curve)
   CHECK(g1_scalar_mul(
            "0db2f980370fb8962751c6ff064f4516a6a93d563388518bb77ab9a6b30755be007c43fcd125b2b13e2521e395a81727710a46b34fe279adbf1b94c72f7f9136"_unhex,
            "0312ed43559cf8ecbab5221256a56e567aac5035308e3f1d54954d8b97cd1c9b"_unhex, result) == -1);

   //|Fp| = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
   // test (P1.y=|Fp|)

   CHECK(g1_scalar_mul(
            "2976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"_unhex,
            "0100010001000100010001000100010001000100010001000100010001000100"_unhex, result) == -1);

   // test (P1=(0,0))
   CHECK(g1_scalar_mul(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"_unhex,
            "0312ed43559cf8ecbab5221256a56e567aac5035308e3f1d54954d8b97cd1c9b"_unhex, result) == 0);
   CHECK(result ==
         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"_unhex);
}

void append(std::vector<uint8_t>& a, const std::vector<uint8_t>& b) { a.insert(a.end(), b.begin(), b.end()); }

struct g1g2_pair {
   const char* g1_x;
   const char* g1_y;
   const char* g2_xx;
   const char* g2_xy;
   const char* g2_yx;
   const char* g2_yy;

   std::vector<uint8_t> to_bytes() const {
      std::vector<uint8_t> r(unhex(g1_x));
      append(r, unhex(g1_y));
      append(r, unhex(g2_xx));
      append(r, unhex(g2_xy));
      append(r, unhex(g2_yx));
      append(r, unhex(g2_yy));
      return r;
   }
};

template <std::size_t N>
std::vector<uint8_t> to_bytes(const std::array<g1g2_pair, N>& pairs) {
   auto result = pairs[0].to_bytes();
   for (auto i = 1U; i < N; ++i) append(result, pairs[i].to_bytes());
   return result;
}

TEST_CASE("test pair", "[bn256]") {

   auto yield = []() {};

   { // test1: 2 pairs => (G1_a,G2_a),(G1_b,G2_b) ; true

      g1g2_pair a{ "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2", // G1_a.x
                   "16da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba", // G1_a.y
                   "2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729cf0d51eb", // G2_a.x
                   "01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb3",
                   "14a9a87b789a58af499b314e13c3d65bede56c07ea2d418d6874857b70763713", // G2_a.y
                   "178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9abd10c3baee24590" };
      g1g2_pair b{ "1b9e027bd5cfc2cb5db82d4dc9677ac795ec500ecd47deee3b5da006d6d049b8", // G1_b.x
                   "11d7511c78158de484232fc68daf8a45cf217d1c2fae693ff5871e8752d73b21", // G1_b.y
                   "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", // G2_b.x
                   "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                   "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", // G2_b.y
                   "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa" };

      std::array<g1g2_pair, 2> case1{ a, b };

      CHECK(bn256::pairing_check(to_bytes(case1), yield) == 1);
   }
   { // test2: 1 pair => (G1_a,G2_a) ; alt_bn128_error::none; false
      g1g2_pair a{ "0000000000000000000000000000000000000000000000000000000000000001", // G1_a.x
                   "0000000000000000000000000000000000000000000000000000000000000002", // G1_a.y
                   "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", // G2_b.x
                   "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                   "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", // G2_b.y
                   "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa" };
      CHECK(bn256::pairing_check(a.to_bytes(), yield) == 0);
   }
   { // test3: 1 pair => (G1_a,G2_a) ; error
      g1g2_pair a{ "00000000000000000000000000000000000000000000000000000000000001",   // G1_a.x
                   "0000000000000000000000000000000000000000000000000000000000000002", // G1_a.y
                   "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", // G2_b.x
                   "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                   "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", // G2_b.y
                   "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa" };
      CHECK(bn256::pairing_check(a.to_bytes(), yield) == -1);
   }
   { // test5: 1 pair => (G1_a,G2_a) ; error
      g1g2_pair a{ "0000000000000000000000000000000000000000000000000000000000000000", // G1_a.x
                   "0000000000000000000000000000000100000000000000000000000000000000", // G1_a.y
                   "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", // G2_b.x
                   "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                   "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", // G2_b.y
                   "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa" };
      CHECK(bn256::pairing_check(a.to_bytes(), yield) == -1);
   }
   { // test6: 1 pair => (G1_a,G2_a) ; error
      g1g2_pair a{ "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", // G1_a.x == |Fp|
                   "0000000000000000000000000000000100000000000000000000000000000000", // G1_a.y
                   "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", // G2_b.x
                   "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
                   "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", // G2_b.y
                   "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa" };
      CHECK(bn256::pairing_check(a.to_bytes(), yield) == -1);
   }
}
