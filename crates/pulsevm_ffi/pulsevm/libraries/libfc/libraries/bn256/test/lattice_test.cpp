#include <lattice.h>
#include <iostream>
#include <iosfwd>
#include <random_255.h>
#include <catch2/catch_test_macros.hpp>


TEST_CASE("test lattice reduce curve", "[lattice]"){
    constexpr int max_bitlen = 130;
    auto k = bn256::random_255();
    auto ks = bn256::curve_lattice.decompose(k);

    for (std::size_t i = 0; i < 2; i++) {
        CHECK(bitlen(ks[i]) <= max_bitlen ); // fails if reduction too large
        CHECK(!is_neg(ks[i])); // reduction must be positive
    }
}

TEST_CASE("test lattice reduce target", "[lattice]"){

    constexpr int max_bitlen = 66;
    auto k = bn256::random_255();
    auto ks = bn256::target_lattice.decompose(k);

    for (std::size_t i = 0; i < 4; i++) {
        CHECK(bitlen(ks[i]) <= max_bitlen ); // fails if reduction too large
        CHECK(!is_neg(ks[i])); // reduction must be positive
    }
}
