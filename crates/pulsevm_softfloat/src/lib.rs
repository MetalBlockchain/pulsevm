//! Pure-Rust port of the EOSIO/Antelope 128-bit softfloat compiler-rt routines
//! that back the WASM floating-point builtins.
//!
//! The vendored C reaches Berkeley SoftFloat (8086-SSE specialization) through
//! `pulsevm_database`; these functions reproduce it bit-for-bit. The public API
//! mirrors the `pulsevm_database` bridge signatures:
//!
//!   * A 128-bit float is passed as `(lo, hi)` u64 halves and returned as a `u128` holding the full
//!     little-endian bit pattern (`(hi << 64) | lo`). Use [`f128_parts`] to split it back into
//!     `(lo, hi)`.
//!   * f32/f64 in/out use `f32`/`f64` directly (callers compare raw bits).
//!   * 128-bit integer results use `i128`/`u128`.
//!   * Comparisons return the same `i32` codes the C `cmptf2_impl` yields.
//!
//! This is consensus-critical: it is validated bit-for-bit against the C++
//! oracle in `crates/pulsevm_database/tests/softfloat_cross_validation.rs`.

use rustc_apfloat::{
    Float,
    FloatConvert,
    ieee::{
        Double,
        Quad,
        Single,
    },
};

mod native;

pub use native::{
    compose as f128_compose,
    split as f128_parts,
};

// Rounding is always round-to-nearest-ties-to-even (softfloat_round_near_even),
// which is what the vendored builtins select and what APFloat defaults to.

#[inline]
fn quad_bits(lo: u64, hi: u64) -> Quad {
    Quad::from_bits(native::compose(lo, hi))
}

// ===========================================================================
// Arithmetic (addtf3 / subtf3 / multf3 / divtf3 / negtf2)
//
// NaN handling is done by hand: when an input is NaN we return the exact
// softfloat_propagateNaNF128UI result; when the inputs are finite/inf but the
// operation is invalid (inf-inf, 0*inf, 0/0, inf/inf) softfloat returns the
// canonical default NaN, so we substitute it for whatever NaN APFloat produced.
// Every other (finite/inf) result is the unique correctly-rounded IEEE value,
// identical between APFloat and Berkeley SoftFloat.
// ===========================================================================

#[inline]
fn finish_arith(result: Quad) -> u128 {
    let bits = result.to_bits();
    let (lo, hi) = native::split(bits);
    if native::is_nan_f128(hi, lo) {
        // Inputs were guaranteed non-NaN here, so any NaN is an invalid-op
        // default NaN; force the softfloat canonical pattern.
        native::compose(native::DEFAULT_NAN_F128_LO, native::DEFAULT_NAN_F128_HI)
    } else {
        bits
    }
}

pub fn addtf3(la: u64, ha: u64, lb: u64, hb: u64) -> u128 {
    if native::is_nan_f128(ha, la) || native::is_nan_f128(hb, lb) {
        return native::propagate_nan_f128(la, ha, lb, hb);
    }
    finish_arith((quad_bits(la, ha) + quad_bits(lb, hb)).value)
}

pub fn subtf3(la: u64, ha: u64, lb: u64, hb: u64) -> u128 {
    if native::is_nan_f128(ha, la) || native::is_nan_f128(hb, lb) {
        return native::propagate_nan_f128(la, ha, lb, hb);
    }
    finish_arith((quad_bits(la, ha) - quad_bits(lb, hb)).value)
}

pub fn multf3(la: u64, ha: u64, lb: u64, hb: u64) -> u128 {
    if native::is_nan_f128(ha, la) || native::is_nan_f128(hb, lb) {
        return native::propagate_nan_f128(la, ha, lb, hb);
    }
    finish_arith((quad_bits(la, ha) * quad_bits(lb, hb)).value)
}

pub fn divtf3(la: u64, ha: u64, lb: u64, hb: u64) -> u128 {
    if native::is_nan_f128(ha, la) || native::is_nan_f128(hb, lb) {
        return native::propagate_nan_f128(la, ha, lb, hb);
    }
    finish_arith((quad_bits(la, ha) / quad_bits(lb, hb)).value)
}

/// negtf2 is a pure sign-bit flip on the high word (matches the C, even for NaN).
pub fn negtf2(la: u64, ha: u64) -> u128 {
    native::compose(la, ha ^ 0x8000_0000_0000_0000)
}

// ===========================================================================
// Widening f32/f64 -> f128 (extendsftf2 / extenddftf2)
// Exact conversions; only NaN inputs need the softfloat commonNaN payload path.
// ===========================================================================

pub fn extendsftf2(f: f32) -> u128 {
    let bits = f.to_bits();
    if native::is_nan_f32(bits) {
        return native::f32_nan_to_f128(bits);
    }
    let mut loses = false;
    let q: Quad = Single::from_bits(bits as u128).convert(&mut loses).value;
    q.to_bits()
}

pub fn extenddftf2(d: f64) -> u128 {
    let bits = d.to_bits();
    if native::is_nan_f64(bits) {
        return native::f64_nan_to_f128(bits);
    }
    let mut loses = false;
    let q: Quad = Double::from_bits(bits as u128).convert(&mut loses).value;
    q.to_bits()
}

// ===========================================================================
// Narrowing f128 -> f64/f32 (trunctfdf2 / trunctfsf2)
// Correctly-rounded; NaN inputs use the softfloat commonNaN payload path.
// ===========================================================================

pub fn trunctfdf2(l: u64, h: u64) -> f64 {
    if native::is_nan_f128(h, l) {
        return f64::from_bits(native::f128_nan_to_f64(l, h));
    }
    let mut loses = false;
    let d: Double = quad_bits(l, h).convert(&mut loses).value;
    f64::from_bits(d.to_bits() as u64)
}

pub fn trunctfsf2(l: u64, h: u64) -> f32 {
    if native::is_nan_f128(h, l) {
        return f32::from_bits(native::f128_nan_to_f32(l, h));
    }
    let mut loses = false;
    let s: Single = quad_bits(l, h).convert(&mut loses).value;
    f32::from_bits(s.to_bits() as u32)
}

// ===========================================================================
// f128 -> integer (round-to-nearest-even; softfloat f128_to_* with mode 0)
// ===========================================================================

pub fn fixtfsi(l: u64, h: u64) -> i32 {
    native::f128_to_i32(l, h)
}
pub fn fixtfdi(l: u64, h: u64) -> i64 {
    native::f128_to_i64(l, h)
}
pub fn fixunstfsi(l: u64, h: u64) -> u32 {
    native::f128_to_ui32(l, h)
}
pub fn fixunstfdi(l: u64, h: u64) -> u64 {
    native::f128_to_ui64(l, h)
}

// ===========================================================================
// float -> 128-bit integer (compiler-rt truncating; builtins/fix*ti.c)
// ===========================================================================

pub fn fixtfti(l: u64, h: u64) -> i128 {
    native::fixtfti(l, h)
}
pub fn fixunstfti(l: u64, h: u64) -> u128 {
    native::fixunstfti(l, h)
}
pub fn fixsfti(a: f32) -> i128 {
    native::fixsfti(a.to_bits())
}
pub fn fixdfti(a: f64) -> i128 {
    native::fixdfti(a.to_bits())
}
pub fn fixunssfti(a: f32) -> u128 {
    native::fixunssfti(a.to_bits())
}
pub fn fixunsdfti(a: f64) -> u128 {
    native::fixunsdfti(a.to_bits())
}

// ===========================================================================
// integer -> float/f128 (exact softfloat packing, plus compiler-rt ti->double)
// ===========================================================================

pub fn floatsidf(i: i32) -> f64 {
    f64::from_bits(native::i32_to_f64(i))
}
pub fn floatsitf(i: i32) -> u128 {
    native::i32_to_f128(i)
}
/// floatditf takes a u64 across the bridge but reinterprets it as i64.
pub fn floatditf(a: u64) -> u128 {
    native::i64_to_f128(a as i64)
}
pub fn floatunsitf(i: u32) -> u128 {
    native::ui32_to_f128(i)
}
pub fn floatunditf(a: u64) -> u128 {
    native::ui64_to_f128(a)
}

pub fn floattidf(l: u64, h: u64) -> f64 {
    native::floattidf(native::compose(l, h) as i128)
}
pub fn floatuntidf(l: u64, h: u64) -> f64 {
    native::floatuntidf(native::compose(l, h))
}

// ===========================================================================
// Comparisons (builtins.cpp cmptf2_impl / unordtf2)
//
// cmptf2_impl(a, b, ret_if_nan):
//     if either is NaN            -> ret_if_nan
//     else if f128_lt(a, b)       -> -1
//     else if f128_eq(a, b)       ->  0
//     else                        ->  1
//
// eqtf2/netf2/letf2/cmptf2 pass ret_if_nan = 1; getf2 passes -1;
// gttf2/lttf2 pass 0. unordtf2 returns 1 when either operand is NaN.
// ===========================================================================

#[inline]
fn cmptf2_impl(la: u64, ha: u64, lb: u64, hb: u64, ret_if_nan: i32) -> i32 {
    if native::is_nan_f128(ha, la) || native::is_nan_f128(hb, lb) {
        return ret_if_nan;
    }
    if native::f128_lt(la, ha, lb, hb) {
        -1
    } else if native::f128_eq(la, ha, lb, hb) {
        0
    } else {
        1
    }
}

pub fn unordtf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    (native::is_nan_f128(ha, la) || native::is_nan_f128(hb, lb)) as i32
}
pub fn eqtf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, 1)
}
pub fn netf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, 1)
}
pub fn getf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, -1)
}
pub fn gttf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, 0)
}
pub fn letf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, 1)
}
pub fn lttf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, 0)
}
pub fn cmptf2(la: u64, ha: u64, lb: u64, hb: u64) -> i32 {
    cmptf2_impl(la, ha, lb, hb, 1)
}
