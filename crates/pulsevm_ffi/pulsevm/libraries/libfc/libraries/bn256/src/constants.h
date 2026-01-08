#pragma once
#include "array.h"

namespace bn256::constants {


// u is the BN parameter.
// inline constexpr boost::multiprecision::int512_t u = 0x44E992B44A6909F1_cppi512;
inline constexpr std::array<uint64_t,4> u = {  0x44E992B44A6909F1, 0, 0, 0};

// Order is the number of elements in both G₁ and G₂: 36u⁴+36u³+18u²+6u+1.
// Needs to be highly 2-adic for efficient SNARK key and proof generation.
// Order - 1 = 2^28 * 3^2 * 13 * 29 * 983 * 11003 * 237073 * 405928799 * 1670836401704629 *
// 13818364434197438864469338081. Refer to https://eprint.iacr.org/2013/879.pdf and https://eprint.iacr.org/2013/507.pdf
// for more information on these parameters. order is
// 21888242871839275222246405745257275088548364400416034343698204186575808495617 dec 254 bits
// inline constexpr int512_t order =              0x30644E72E131A029    B85045B68181585D    2833E84879B97091    43E1F593F0000001_cppi512;
inline constexpr std::array<uint64_t,4> order = { 0x43E1F593F0000001, 0x2833E84879B97091, 0xB85045B68181585D, 0x30644E72E131A029 };



// p is a prime over which we form a basic field: 36u⁴+36u³+24u²+6u+1.
// p is 21888242871839275222246405745257275088696311157297823662689037894645226208583 dec 254 bits
//inline constexpr int512_t p =                 0x30644E72E131A029    B85045B68181585D    97816A916871CA8D    3C208C16D87CFD47_cppi512;
inline constexpr std::array<uint64_t,4> p = { 0x3C208C16D87CFD47, 0x97816A916871CA8D, 0xB85045B68181585D, 0x30644E72E131A029 };


} // namespace bn256::constants
