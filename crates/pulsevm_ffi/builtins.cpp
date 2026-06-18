#include <cstring>

#include <compiler_builtins.hpp>
#include <softfloat.hpp>

#include <fc/uint128.hpp>

#include <pulsevm_ffi/src/bridge.rs.h>

namespace pulsevm::chain {

inline unsigned __int128 to_u128(const U128& v) {
    return (static_cast<unsigned __int128>(v.hi) << 64)
         |  static_cast<unsigned __int128>(v.lo);
}

inline U128 from_u128(unsigned __int128 x) {
    return U128{
        static_cast<uint64_t>(x),          // lo
        static_cast<uint64_t>(x >> 64),    // hi
    };
}

inline __int128 to_i128(const I128& v) {
    return (static_cast<__int128>(static_cast<unsigned __int128>(v.hi) << 64)
          | static_cast<__int128>(static_cast<unsigned __int128>(v.lo)));
}

inline I128 from_i128(__int128 x) {
    return I128{
        static_cast<uint64_t>(x),                              // lo
        static_cast<uint64_t>(static_cast<unsigned __int128>(x) >> 64), // hi
    };
}

// arithmetic long double
Float128 addtf3( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    float128_t a = {{ la, ha }};
    float128_t b = {{ lb, hb }};
    float128_t result = f128_add( a, b );
    return Float128{ result.v[0], result.v[1] };
}
Float128 subtf3( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    float128_t a = {{ la, ha }};
    float128_t b = {{ lb, hb }};
    float128_t result = f128_sub( a, b );
    return Float128{ result.v[0], result.v[1] };
}
Float128 multf3( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    float128_t a = {{ la, ha }};
    float128_t b = {{ lb, hb }};
    float128_t result = f128_mul( a, b );
    return Float128{ result.v[0], result.v[1] };
}
Float128 divtf3( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    float128_t a = {{ la, ha }};
    float128_t b = {{ lb, hb }};
    float128_t result = f128_div( a, b );
    return Float128{ result.v[0], result.v[1] };
}
Float128 negtf2( uint64_t la, uint64_t ha ) {
    float128_t result = {{ la, (ha ^ (uint64_t)1 << 63) }};
    return Float128{ result.v[0], result.v[1] };
}

// conversion long double
Float128 extendsftf2( float f ) {
    float128_t result = f32_to_f128( to_softfloat32(f) );
    return Float128{ result.v[0], result.v[1] };
}
Float128 extenddftf2( double d ) {
    float128_t result = f64_to_f128( to_softfloat64(d) );
    return Float128{ result.v[0], result.v[1] };
}
double trunctfdf2( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    return from_softfloat64(f128_to_f64( f ));
}
float trunctfsf2( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    return from_softfloat32(f128_to_f32( f ));
}
int32_t fixtfsi( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    return f128_to_i32( f, 0, false );
}
int64_t fixtfdi( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    return f128_to_i64( f, 0, false );
}
I128 fixtfti( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    __int128_t result = ___fixtfti( f );
    return from_i128(result);
}
uint32_t fixunstfsi( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    return f128_to_ui32( f, 0, false );
}
uint64_t fixunstfdi( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    return f128_to_ui64( f, 0, false );
}
U128 fixunstfti( uint64_t l, uint64_t h ) {
    float128_t f = {{ l, h }};
    auto result = ___fixunstfti( f );
    return from_u128(result);
}
I128 fixsfti( float a ) {
    __int128_t result = ___fixsfti( to_softfloat32(a).v );
    return from_i128(result);
}
I128 fixdfti( double a ) {
    __int128_t result = ___fixdfti( to_softfloat64(a).v );
    return from_i128(result);
}
U128 fixunssfti( float a ) {
    auto result = ___fixunssfti( to_softfloat32(a).v );
    return from_u128(result);
}
U128 fixunsdfti( double a ) {
    auto result = ___fixunsdfti( to_softfloat64(a).v );
    return from_u128(result);
}
double floatsidf( int32_t i ) {
    return from_softfloat64(i32_to_f64(i));
}
Float128 floatsitf( int32_t i ) {
    float128_t result = i32_to_f128(i);
    return Float128{ result.v[0], result.v[1] };
}
Float128 floatditf( uint64_t a ) {
    float128_t result = i64_to_f128( a );
    return Float128{ result.v[0], result.v[1] };
}
Float128 floatunsitf( uint32_t i ) {
    float128_t result = ui32_to_f128(i);
    return Float128{ result.v[0], result.v[1] };
}
Float128 floatunditf( uint64_t a ) {
    float128_t result = ui64_to_f128( a );
    return Float128{ result.v[0], result.v[1] };
}
double floattidf( uint64_t l, uint64_t h ) {
    fc::uint128 v(h, l);
    unsigned __int128 val = (unsigned __int128)v;
    return ___floattidf( *(__int128*)&val );
}
double floatuntidf( uint64_t l, uint64_t h ) {
    fc::uint128 v(h, l);
    return ___floatuntidf( (unsigned __int128)v );
}

int unordtf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    float128_t a = {{ la, ha }};
    float128_t b = {{ lb, hb }};
    if ( f128_is_nan(a) || f128_is_nan(b) )
        return 1;
    return 0;
}

inline static int cmptf2_impl( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb, int return_value_if_nan ) {
    float128_t a = {{ la, ha }};
    float128_t b = {{ lb, hb }};
    if ( unordtf2(la, ha, lb, hb) )
        return return_value_if_nan;
    if ( f128_lt( a, b ) )
        return -1;
    if ( f128_eq( a, b ) )
        return 0;
    return 1;
}
int eqtf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, 1);
}
int netf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, 1);
}
int getf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, -1);
}
int gttf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, 0);
}
int letf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, 1);
}
int lttf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, 0);
}
int cmptf2( uint64_t la, uint64_t ha, uint64_t lb, uint64_t hb ) {
    return cmptf2_impl(la, ha, lb, hb, 1);
}

}