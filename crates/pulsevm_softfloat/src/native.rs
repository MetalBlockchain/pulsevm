//! Direct, line-for-line ports of the vendored C routines whose returned bit
//! patterns are implementation-defined (NaN payloads, integer saturation,
//! round-to-nearest-even integer conversions, exact int->float packing).
//!
//! Sources (all under crates/pulsevm_database/pulsevm/libraries):
//!   * softfloat/source/{f128_to_i32,f128_to_i64,f128_to_ui32,f128_to_ui64}.c
//!   * softfloat/source/{s_roundToI32,s_roundToI64,s_roundToUI32,s_roundToUI64}.c
//!   * softfloat/source/{i32_to_f128,i64_to_f128,ui32_to_f128,ui64_to_f128,i32_to_f64}.c
//!   * softfloat/source/8086-SSE/specialize.h  (default/canonical NaN bit patterns)
//!   * softfloat/source/8086-SSE/s_*CommonNaN*.c
//!   * softfloat/source/{f128_lt,f128_eq}.c
//!   * builtins/{fixtfti,fixunstfti,fixsfti,fixdfti,fixunssfti,fixunsdfti,floattidf,floatuntidf}.c
//!
//! The 8086-SSE specialization is what the build selects
//! (softfloat/CMakeLists.txt references source/8086-SSE/*).

// ----- f128 field accessors (float128_t = {{ v0 = lo, v1 = hi }}) -----------

#[inline]
pub fn compose(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}

#[inline]
pub fn split(v: u128) -> (u64, u64) {
    (v as u64, (v >> 64) as u64)
}

#[inline]
fn sign_f128(hi: u64) -> bool {
    hi >> 63 != 0
}
#[inline]
fn exp_f128(hi: u64) -> i32 {
    ((hi >> 48) & 0x7FFF) as i32
}
#[inline]
fn frac_f128_hi(hi: u64) -> u64 {
    hi & 0x0000_FFFF_FFFF_FFFF
}

/// `isNaNF128UI` from internals.h.
#[inline]
pub fn is_nan_f128(hi: u64, lo: u64) -> bool {
    (!hi & 0x7FFF_0000_0000_0000) == 0 && (lo != 0 || (hi & 0x0000_FFFF_FFFF_FFFF) != 0)
}

#[inline]
pub fn is_nan_f32(bits: u32) -> bool {
    (bits & 0x7FFF_FFFF) > 0x7F80_0000
}
#[inline]
pub fn is_nan_f64(bits: u64) -> bool {
    (bits & 0x7FFF_FFFF_FFFF_FFFF) > 0x7FF0_0000_0000_0000
}

// Canonical / default NaN bit patterns for the 8086-SSE specialization.
pub const DEFAULT_NAN_F128_HI: u64 = 0xFFFF_8000_0000_0000; // defaultNaNF128UI64
pub const DEFAULT_NAN_F128_LO: u64 = 0x0000_0000_0000_0000; // defaultNaNF128UI0

/// `softfloat_propagateNaNF128UI`: combine two f128 bit patterns, at least one
/// of which is a NaN, into the propagated (quieted) NaN result. The returned
/// bits are independent of add vs sub vs mul vs div.
#[inline]
pub fn propagate_nan_f128(a_lo: u64, a_hi: u64, b_lo: u64, b_hi: u64) -> u128 {
    let (mut z_hi, z_lo) = if is_nan_f128(a_hi, a_lo) {
        (a_hi, a_lo)
    } else {
        (b_hi, b_lo)
    };
    z_hi |= 0x0000_8000_0000_0000;
    compose(z_lo, z_hi)
}

// ---------------------------------------------------------------------------
// NaN format conversions (8086-SSE s_*CommonNaN*.c), expressed with the same
// truncating u64 shifts the C performs.
// ---------------------------------------------------------------------------

/// f32 NaN bits -> f128 NaN bits (used by `extendsftf2`).
pub fn f32_nan_to_f128(ui_a: u32) -> u128 {
    let sign = (ui_a >> 31) as u64;
    let v64 = (ui_a as u64).wrapping_shl(41); // (uint_fast64_t)uiA<<41
    let v0: u64 = 0;
    // softfloat_commonNaNToF128UI: shortShiftRight128(v64, v0, 16), then set exp/sign.
    let mut z_hi = v64 >> 16;
    let z_lo = (v64 << 48) | (v0 >> 16);
    z_hi |= (sign << 63) | 0x7FFF_8000_0000_0000;
    compose(z_lo, z_hi)
}

/// f64 NaN bits -> f128 NaN bits (used by `extenddftf2`).
pub fn f64_nan_to_f128(ui_a: u64) -> u128 {
    let sign = ui_a >> 63;
    let v64 = ui_a.wrapping_shl(12); // uiA<<12
    let v0: u64 = 0;
    let mut z_hi = v64 >> 16;
    let z_lo = (v64 << 48) | (v0 >> 16);
    z_hi |= (sign << 63) | 0x7FFF_8000_0000_0000;
    compose(z_lo, z_hi)
}

/// f128 NaN bits -> f64 NaN bits (used by `trunctfdf2`).
pub fn f128_nan_to_f64(lo: u64, hi: u64) -> u64 {
    let sign = hi >> 63;
    // softfloat_f128UIToCommonNaN: shortShiftLeft128(hi, lo, 16).v64
    let v64 = (hi << 16) | (lo >> 48);
    // softfloat_commonNaNToF64UI
    (sign << 63) | 0x7FF8_0000_0000_0000 | (v64 >> 12)
}

/// f128 NaN bits -> f32 NaN bits (used by `trunctfsf2`).
pub fn f128_nan_to_f32(lo: u64, hi: u64) -> u32 {
    let sign = hi >> 63;
    let v64 = (hi << 16) | (lo >> 48);
    // softfloat_commonNaNToF32UI
    ((sign << 31) as u32) | 0x7FC0_0000 | ((v64 >> 41) as u32)
}

// ---------------------------------------------------------------------------
// Rounding-mode-0 (round-to-nearest-even) f128 -> integer conversions.
// These back fixtfsi / fixtfdi / fixunstfsi / fixunstfdi.
// ---------------------------------------------------------------------------

const I32_MIN: i32 = -0x7FFF_FFFF - 1;
const I64_MIN: i64 = -0x7FFF_FFFF_FFFF_FFFF - 1;
const UI32_MAX: u32 = 0xFFFF_FFFF;
const UI64_MAX: u64 = 0xFFFF_FFFF_FFFF_FFFF;

fn shift_right_jam64(a: u64, dist: u32) -> u64 {
    if dist < 63 {
        (a >> dist) | ((a.wrapping_shl(dist.wrapping_neg() & 63) != 0) as u64)
    } else {
        (a != 0) as u64
    }
}

/// (v, extra) = softfloat_shiftRightJam64Extra(a, extra, dist)
fn shift_right_jam64_extra(a: u64, extra: u64, dist: u32) -> (u64, u64) {
    let (v, mut e) = if dist < 64 {
        (a >> dist, a.wrapping_shl(dist.wrapping_neg() & 63))
    } else if dist == 64 {
        (0, a)
    } else {
        (0, (a != 0) as u64)
    };
    e |= (extra != 0) as u64;
    (v, e)
}

/// softfloat_shortShiftLeft128 (0 < dist < 64).
fn short_shift_left128(a64: u64, a0: u64, dist: u32) -> (u64, u64) {
    let v64 = (a64 << dist) | (a0 >> (64 - dist));
    let v0 = a0 << dist;
    (v64, v0)
}

fn round_to_i32(sign: bool, sig_in: u64) -> i32 {
    // roundingMode == near_even  =>  roundIncrement = 0x800
    let round_bits = sig_in & 0xFFF;
    let sig = sig_in.wrapping_add(0x800);
    // i32_fromNaN == i32_fromPosOverflow == i32_fromNegOverflow == INT32_MIN.
    if sig & 0xFFFFF_00000000000 != 0 {
        return I32_MIN;
    }
    let mut sig32 = (sig >> 12) as u32;
    if round_bits == 0x800 {
        sig32 &= !1;
    }
    let z = if sign {
        (sig32 as i32).wrapping_neg()
    } else {
        sig32 as i32
    };
    if z != 0 && ((z < 0) != sign) {
        return I32_MIN;
    }
    z
}

fn round_to_ui32(sign: bool, sig_in: u64) -> u32 {
    let round_bits = sig_in & 0xFFF;
    let sig = sig_in.wrapping_add(0x800);
    if sig & 0xFFFFF_00000000000 != 0 {
        return UI32_MAX;
    }
    let mut z = (sig >> 12) as u32;
    if round_bits == 0x800 {
        z &= !1;
    }
    if sign && z != 0 {
        return UI32_MAX;
    }
    z
}

fn round_to_i64(sign: bool, mut sig: u64, sig_extra: u64) -> i64 {
    if sig_extra >= 0x8000_0000_0000_0000 {
        sig = sig.wrapping_add(1);
        if sig == 0 {
            return I64_MIN;
        }
        if sig_extra == 0x8000_0000_0000_0000 {
            sig &= !1;
        }
    }
    let z = if sign {
        (sig as i64).wrapping_neg()
    } else {
        sig as i64
    };
    if z != 0 && ((z < 0) != sign) {
        return I64_MIN;
    }
    z
}

fn round_to_ui64(sign: bool, mut sig: u64, sig_extra: u64) -> u64 {
    if sig_extra >= 0x8000_0000_0000_0000 {
        sig = sig.wrapping_add(1);
        if sig == 0 {
            return UI64_MAX;
        }
        if sig_extra == 0x8000_0000_0000_0000 {
            sig &= !1;
        }
    }
    if sign && sig != 0 {
        return UI64_MAX;
    }
    sig
}

pub fn f128_to_i32(lo: u64, hi: u64) -> i32 {
    let sign = sign_f128(hi);
    let exp = exp_f128(hi);
    let mut sig64 = frac_f128_hi(hi);
    let sig0 = lo;
    if exp != 0 {
        sig64 |= 0x0001_0000_0000_0000;
    }
    sig64 |= (sig0 != 0) as u64;
    let shift_dist = 0x4023 - exp;
    if shift_dist > 0 {
        sig64 = shift_right_jam64(sig64, shift_dist as u32);
    }
    round_to_i32(sign, sig64)
}

pub fn f128_to_ui32(lo: u64, hi: u64) -> u32 {
    let sign = sign_f128(hi);
    let exp = exp_f128(hi);
    let mut sig64 = frac_f128_hi(hi) | ((lo != 0) as u64);
    if exp != 0 {
        sig64 |= 0x0001_0000_0000_0000;
    }
    let shift_dist = 0x4023 - exp;
    if shift_dist > 0 {
        sig64 = shift_right_jam64(sig64, shift_dist as u32);
    }
    round_to_ui32(sign, sig64)
}

pub fn f128_to_i64(lo: u64, hi: u64) -> i64 {
    let sign = sign_f128(hi);
    let exp = exp_f128(hi);
    let mut sig64 = frac_f128_hi(hi);
    let mut sig0 = lo;
    let shift_dist = 0x402F - exp;
    if shift_dist <= 0 {
        if shift_dist < -15 {
            // i64_fromNaN == i64_fromNegOverflow == i64_fromPosOverflow == INT64_MIN.
            return I64_MIN;
        }
        sig64 |= 0x0001_0000_0000_0000;
        if shift_dist != 0 {
            let (v64, v0) = short_shift_left128(sig64, sig0, (-shift_dist) as u32);
            sig64 = v64;
            sig0 = v0;
        }
    } else {
        if exp != 0 {
            sig64 |= 0x0001_0000_0000_0000;
        }
        let (v, e) = shift_right_jam64_extra(sig64, sig0, shift_dist as u32);
        sig64 = v;
        sig0 = e;
    }
    round_to_i64(sign, sig64, sig0)
}

pub fn f128_to_ui64(lo: u64, hi: u64) -> u64 {
    let sign = sign_f128(hi);
    let exp = exp_f128(hi);
    let mut sig64 = frac_f128_hi(hi);
    let mut sig0 = lo;
    let shift_dist = 0x402F - exp;
    if shift_dist <= 0 {
        if shift_dist < -15 {
            // ui64_fromNaN == ui64_fromNegOverflow == ui64_fromPosOverflow == UINT64_MAX.
            return UI64_MAX;
        }
        sig64 |= 0x0001_0000_0000_0000;
        if shift_dist != 0 {
            let (v64, v0) = short_shift_left128(sig64, sig0, (-shift_dist) as u32);
            sig64 = v64;
            sig0 = v0;
        }
    } else {
        if exp != 0 {
            sig64 |= 0x0001_0000_0000_0000;
        }
        let (v, e) = shift_right_jam64_extra(sig64, sig0, shift_dist as u32);
        sig64 = v;
        sig0 = e;
    }
    round_to_ui64(sign, sig64, sig0)
}

// ---------------------------------------------------------------------------
// Exact integer -> float packing (softfloat i*_to_f*).
// packToF128UI64 uses `+` (fields don't overlap except the implicit leading 1,
// which is meant to carry into the exponent), so we mirror it with wrapping add.
// ---------------------------------------------------------------------------

#[inline]
fn pack_f128_hi(sign: bool, exp: i32, sig64: u64) -> u64 {
    ((sign as u64) << 63)
        .wrapping_add((exp as u64) << 48)
        .wrapping_add(sig64)
}

pub fn i32_to_f128(a: i32) -> u128 {
    if a == 0 {
        return 0;
    }
    let sign = a < 0;
    let abs_a = (a as i64).unsigned_abs() as u32;
    let shift_dist = abs_a.leading_zeros() as i32 + 17;
    let hi = pack_f128_hi(sign, 0x402E - shift_dist, (abs_a as u64) << shift_dist);
    compose(0, hi)
}

pub fn ui32_to_f128(a: u32) -> u128 {
    if a == 0 {
        return 0;
    }
    let shift_dist = a.leading_zeros() as i32 + 17;
    let hi = pack_f128_hi(false, 0x402E - shift_dist, (a as u64) << shift_dist);
    compose(0, hi)
}

pub fn i64_to_f128(a: i64) -> u128 {
    if a == 0 {
        return 0;
    }
    let sign = a < 0;
    let abs_a = (a as i128).unsigned_abs() as u64;
    let shift_dist = abs_a.leading_zeros() as i32 + 49;
    let (z64, z0) = if shift_dist >= 64 {
        (abs_a << (shift_dist - 64), 0u64)
    } else {
        short_shift_left128(0, abs_a, shift_dist as u32)
    };
    let hi = pack_f128_hi(sign, 0x406E - shift_dist, z64);
    compose(z0, hi)
}

pub fn ui64_to_f128(a: u64) -> u128 {
    if a == 0 {
        return 0;
    }
    let shift_dist = a.leading_zeros() as i32 + 49;
    let (z64, z0) = if shift_dist >= 64 {
        (a << (shift_dist - 64), 0u64)
    } else {
        short_shift_left128(0, a, shift_dist as u32)
    };
    let hi = pack_f128_hi(false, 0x406E - shift_dist, z64);
    compose(z0, hi)
}

pub fn i32_to_f64(a: i32) -> u64 {
    if a == 0 {
        return 0;
    }
    let sign = a < 0;
    let abs_a = (a as i64).unsigned_abs() as u32;
    let shift_dist = abs_a.leading_zeros() as i32 + 21;
    // packToF64UI(sign, 0x432 - shiftDist, absA<<shiftDist)
    ((sign as u64) << 63)
        .wrapping_add(((0x432 - shift_dist) as u64) << 52)
        .wrapping_add((abs_a as u64) << shift_dist)
}

// ---------------------------------------------------------------------------
// compiler-rt style truncating float -> 128-bit integer (builtins/fix*ti.c).
// ---------------------------------------------------------------------------

/// __int128 ___fixtfti(float128_t)
pub fn fixtfti(lo: u64, hi: u64) -> i128 {
    const SIGNIFICAND_BITS: u32 = 112;
    let fixint_max: i128 = i128::MAX;
    let fixint_min: i128 = i128::MIN;
    let a_rep = compose(lo, hi) as i128;
    let a_abs = a_rep & (i128::MAX); // absMask = signBit - 1
    let sign: i128 = if (a_rep as u128) & (1u128 << 127) != 0 {
        -1
    } else {
        1
    };
    let exponent = ((a_abs >> SIGNIFICAND_BITS) as i64 - 16383) as i32; // exponentBias = 16383
    let significand = (a_abs & ((1i128 << SIGNIFICAND_BITS) - 1)) | (1i128 << SIGNIFICAND_BITS);
    if exponent < 0 {
        return 0;
    }
    if (exponent as u32) >= 128 {
        return if sign == 1 { fixint_max } else { fixint_min };
    }
    if exponent < SIGNIFICAND_BITS as i32 {
        sign.wrapping_mul(significand >> (SIGNIFICAND_BITS as i32 - exponent))
    } else {
        sign.wrapping_mul(significand << (exponent - SIGNIFICAND_BITS as i32))
    }
}

/// unsigned __int128 ___fixunstfti(float128_t)
pub fn fixunstfti(lo: u64, hi: u64) -> u128 {
    const SIGNIFICAND_BITS: u32 = 112;
    let a_rep = compose(lo, hi) as i128;
    let a_abs = a_rep & i128::MAX;
    let sign: i32 = if (a_rep as u128) & (1u128 << 127) != 0 {
        -1
    } else {
        1
    };
    let exponent = ((a_abs >> SIGNIFICAND_BITS) as i64 - 16383) as i32;
    let significand =
        ((a_abs & ((1i128 << SIGNIFICAND_BITS) - 1)) | (1i128 << SIGNIFICAND_BITS)) as u128;
    if sign == -1 || exponent < 0 {
        return 0;
    }
    if (exponent as u32) >= 128 {
        return u128::MAX;
    }
    if exponent < SIGNIFICAND_BITS as i32 {
        significand >> (SIGNIFICAND_BITS as i32 - exponent)
    } else {
        significand << (exponent - SIGNIFICAND_BITS as i32)
    }
}

/// Shared body for the compiler-rt f32/f64 -> i128 signed truncations.
fn fix_signed_ti(a_rep: u128, significand_bits: u32, exponent_bias: i32) -> i128 {
    let type_width = if significand_bits == 23 { 32 } else { 64 };
    let sign_bit = 1u128 << (type_width - 1);
    let abs_mask = sign_bit - 1;
    let a_abs = a_rep & abs_mask;
    let sign: i128 = if a_rep & sign_bit != 0 { -1 } else { 1 };
    let exponent = ((a_abs >> significand_bits) as i64 - exponent_bias as i64) as i32;
    let significand =
        ((a_abs & ((1u128 << significand_bits) - 1)) | (1u128 << significand_bits)) as i128;
    if exponent < 0 {
        return 0;
    }
    if (exponent as u32) >= 128 {
        return if sign == 1 { i128::MAX } else { i128::MIN };
    }
    if exponent < significand_bits as i32 {
        sign.wrapping_mul(significand >> (significand_bits as i32 - exponent))
    } else {
        sign.wrapping_mul(significand << (exponent - significand_bits as i32))
    }
}

fn fix_unsigned_ti(a_rep: u128, significand_bits: u32, exponent_bias: i32) -> u128 {
    let type_width = if significand_bits == 23 { 32 } else { 64 };
    let sign_bit = 1u128 << (type_width - 1);
    let abs_mask = sign_bit - 1;
    let a_abs = a_rep & abs_mask;
    let sign: i32 = if a_rep & sign_bit != 0 { -1 } else { 1 };
    let exponent = ((a_abs >> significand_bits) as i64 - exponent_bias as i64) as i32;
    let significand = (a_abs & ((1u128 << significand_bits) - 1)) | (1u128 << significand_bits);
    if sign == -1 || exponent < 0 {
        return 0;
    }
    if (exponent as u32) >= 128 {
        return u128::MAX;
    }
    if exponent < significand_bits as i32 {
        significand >> (significand_bits as i32 - exponent)
    } else {
        significand << (exponent - significand_bits as i32)
    }
}

pub fn fixsfti(bits: u32) -> i128 {
    fix_signed_ti(bits as u128, 23, 127)
}
pub fn fixdfti(bits: u64) -> i128 {
    fix_signed_ti(bits as u128, 52, 1023)
}
pub fn fixunssfti(bits: u32) -> u128 {
    fix_unsigned_ti(bits as u128, 23, 127)
}
pub fn fixunsdfti(bits: u64) -> u128 {
    fix_unsigned_ti(bits as u128, 52, 1023)
}

// ---------------------------------------------------------------------------
// compiler-rt 128-bit integer -> double (round to nearest even).
// builtins/floattidf.c and floatuntidf.c.
// ---------------------------------------------------------------------------

const DBL_MANT_DIG: i32 = 53;

pub fn floattidf(a_in: i128) -> f64 {
    if a_in == 0 {
        return 0.0;
    }
    let n: i32 = 128;
    let s = a_in >> (n - 1); // 0 or -1
    let mut a = ((a_in ^ s).wrapping_sub(s)) as u128; // abs
    let sd = n - a.leading_zeros() as i32; // significant digits
    let mut e = sd - 1; // exponent
    if sd > DBL_MANT_DIG {
        match sd {
            x if x == DBL_MANT_DIG + 1 => {
                a <<= 1;
            }
            x if x == DBL_MANT_DIG + 2 => {}
            _ => {
                a = (a >> (sd - (DBL_MANT_DIG + 2)))
                    | (((a & (u128::MAX >> ((n + DBL_MANT_DIG + 2) - sd))) != 0) as u128);
            }
        }
        a |= ((a & 4) != 0) as u128;
        a = a.wrapping_add(1);
        a >>= 2;
        if a & (1u128 << DBL_MANT_DIG) != 0 {
            a >>= 1;
            e += 1;
        }
    } else {
        a <<= DBL_MANT_DIG - sd;
    }
    let high =
        ((s as u32) & 0x8000_0000) | (((e + 1023) as u32) << 20) | ((a >> 32) as u32 & 0x000F_FFFF);
    let low = a as u32;
    f64::from_bits(((high as u64) << 32) | low as u64)
}

pub fn floatuntidf(a_in: u128) -> f64 {
    if a_in == 0 {
        return 0.0;
    }
    let n: i32 = 128;
    let mut a = a_in;
    let sd = n - a.leading_zeros() as i32;
    let mut e = sd - 1;
    if sd > DBL_MANT_DIG {
        match sd {
            x if x == DBL_MANT_DIG + 1 => {
                a <<= 1;
            }
            x if x == DBL_MANT_DIG + 2 => {}
            _ => {
                a = (a >> (sd - (DBL_MANT_DIG + 2)))
                    | (((a & (u128::MAX >> ((n + DBL_MANT_DIG + 2) - sd))) != 0) as u128);
            }
        }
        a |= ((a & 4) != 0) as u128;
        a = a.wrapping_add(1);
        a >>= 2;
        if a & (1u128 << DBL_MANT_DIG) != 0 {
            a >>= 1;
            e += 1;
        }
    } else {
        a <<= DBL_MANT_DIG - sd;
    }
    let high = (((e + 1023) as u32) << 20) | ((a >> 32) as u32 & 0x000F_FFFF);
    let low = a as u32;
    f64::from_bits(((high as u64) << 32) | low as u64)
}

// ---------------------------------------------------------------------------
// Ordered comparison primitives (f128_lt / f128_eq), NaN already excluded by
// the callers. Direct ports so signed-zero and total-order edge cases match.
// ---------------------------------------------------------------------------

#[inline]
fn lt128(a64: u64, a0: u64, b64: u64, b0: u64) -> bool {
    a64 < b64 || (a64 == b64 && a0 < b0)
}

pub fn f128_lt(a_lo: u64, a_hi: u64, b_lo: u64, b_hi: u64) -> bool {
    let sign_a = sign_f128(a_hi);
    let sign_b = sign_f128(b_hi);
    if sign_a != sign_b {
        sign_a && (((a_hi | b_hi) & 0x7FFF_FFFF_FFFF_FFFF) | a_lo | b_lo) != 0
    } else {
        ((a_hi != b_hi) || (a_lo != b_lo)) && (sign_a ^ lt128(a_hi, a_lo, b_hi, b_lo))
    }
}

pub fn f128_eq(a_lo: u64, a_hi: u64, b_lo: u64, b_hi: u64) -> bool {
    (a_lo == b_lo)
        && ((a_hi == b_hi) || (a_lo == 0 && ((a_hi | b_hi) & 0x7FFF_FFFF_FFFF_FFFF) == 0))
}
