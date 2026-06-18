#pragma once

#include <cstdint>

namespace pulsevm::chain {

struct U128;
struct I128;
struct Float128;

// ---- 128-bit carrier helpers ----
unsigned __int128 to_u128(const U128& v);
U128 from_u128(unsigned __int128 x);

// ---- arithmetic (long double / f128) ----
Float128 addtf3(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
Float128 subtf3(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
Float128 multf3(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
Float128 divtf3(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
Float128 negtf2(uint64_t la, uint64_t ha);

// ---- conversions: widening / narrowing ----
Float128 extendsftf2(float f);
Float128 extenddftf2(double d);
double   trunctfdf2(uint64_t l, uint64_t h);
float    trunctfsf2(uint64_t l, uint64_t h);

// ---- f128 -> integer ----
int32_t  fixtfsi(uint64_t l, uint64_t h);
int64_t  fixtfdi(uint64_t l, uint64_t h);
I128     fixtfti(uint64_t l, uint64_t h);
uint32_t fixunstfsi(uint64_t l, uint64_t h);
uint64_t fixunstfdi(uint64_t l, uint64_t h);
U128     fixunstfti(uint64_t l, uint64_t h);

// ---- float -> i128/u128 ----
I128 fixsfti(float a);
I128 fixdfti(double a);
U128 fixunssfti(float a);
U128 fixunsdfti(double a);

// ---- integer -> float / f128 ----
double   floatsidf(int32_t i);
Float128 floatsitf(int32_t i);
Float128 floatditf(uint64_t a);
Float128 floatunsitf(uint32_t i);
Float128 floatunditf(uint64_t a);

// ---- 128-bit integer -> double ----
double floattidf(uint64_t l, uint64_t h);
double floatuntidf(uint64_t l, uint64_t h);

// ---- comparisons ----
int unordtf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int eqtf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int netf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int getf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int gttf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int letf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int lttf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);
int cmptf2(uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb);

}