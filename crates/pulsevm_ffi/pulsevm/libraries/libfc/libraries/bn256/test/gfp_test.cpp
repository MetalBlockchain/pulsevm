#include <constants.h>
#include <gfp.h>
#include <gfp_generic.h>
#include <iostream>
#include <iosfwd>
#include <catch2/catch_test_macros.hpp>
#if defined (__clang__)
#pragma clang diagnostic ignored "-Wmissing-braces"
#endif

// Tests that negation works the same way on both assembly-optimized and C++
// implementation.
TEST_CASE("test_gfp_neg", "[gfp]"){

   constexpr bn256::gfp n = {0x0123456789abcdef, 0xfedcba9876543210, 0xdeadbeefdeadbeef, 0xfeebdaedfeebdaed};
   constexpr bn256::gfp w = {0xfedcba9876543211, 0x0123456789abcdef, 0x2152411021524110, 0x0114251201142512};
   static_assert( bn256::gfp_neg(n) == w ); // negation mismatch
   CHECK(bn256::gfp_neg(n) == w);
}

// Tests that addition works the same way on both assembly-optimized and C++
// implementation.
TEST_CASE("test_gfp_add", "[gfp]"){

   constexpr bn256::gfp a = {0x0123456789abcdef, 0xfedcba9876543210, 0xdeadbeefdeadbeef, 0xfeebdaedfeebdaed};
   constexpr bn256::gfp b = {0xfedcba9876543210, 0x0123456789abcdef, 0xfeebdaedfeebdaed, 0xdeadbeefdeadbeef};
   constexpr bn256::gfp w = {0xc3df73e9278302b8, 0x687e956e978e3572, 0x254954275c18417f, 0xad354b6afc67f9b4};
   static_assert( bn256::gfp_add(a, b) == w ); // addition mismatch
   CHECK(bn256::gfp_add(a, b) == w);
}

// Tests that subtraction works the same way on both assembly-optimized and C++
// implementation.
TEST_CASE("test_gfp_sub", "[gfp]"){
   constexpr bn256::gfp a = {0x0123456789abcdef, 0xfedcba9876543210, 0xdeadbeefdeadbeef, 0xfeebdaedfeebdaed};
   constexpr bn256::gfp b = {0xfedcba9876543210, 0x0123456789abcdef, 0xfeebdaedfeebdaed, 0xdeadbeefdeadbeef};
   constexpr bn256::gfp w = {0x02468acf13579bdf, 0xfdb97530eca86420, 0xdfc1e401dfc1e402, 0x203e1bfe203e1bfd};
   static_assert( bn256::gfp_sub(a, b) == w ); // subtraction mismatch
   CHECK( bn256::gfp_sub(a, b) == w);
}

// Tests that multiplication works the same way on both assembly-optimized and C++
// implementation.
TEST_CASE("test_gfp_mul", "[gfp]"){
   constexpr bn256::gfp a = {0x0123456789abcdef, 0xfedcba9876543210, 0xdeadbeefdeadbeef, 0xfeebdaedfeebdaed};
   constexpr bn256::gfp b = {0xfedcba9876543210, 0x0123456789abcdef, 0xfeebdaedfeebdaed, 0xdeadbeefdeadbeef};
   constexpr bn256::gfp w = {0xcbcbd377f7ad22d3, 0x3b89ba5d849379bf, 0x87b61627bd38b6d2, 0xc44052a2a0e654b2};
   static_assert( bn256::gfp_mul(a, b) == w ); // multiplication mismatch
   CHECK(bn256::gfp_mul(a, b) == w);
}