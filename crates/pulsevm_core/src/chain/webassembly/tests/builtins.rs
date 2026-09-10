use super::*;

type Binary =
    fn(FunctionEnvMut<WasmContext>, WasmPtr<u8>, u64, u64, u64, u64) -> Result<(), RuntimeError>;
type Shift =
    fn(FunctionEnvMut<WasmContext>, WasmPtr<u8>, u64, u64, u32) -> Result<(), RuntimeError>;
type Compare = fn(FunctionEnvMut<WasmContext>, u64, u64, u64, u64) -> Result<i32, RuntimeError>;

#[test]
fn integer_shifts_cover_limb_and_width_boundaries() {
    let mut h = Host::new(false);
    for (op, arithmetic, left) in [
        (__ashlti3 as Shift, false, true),
        (__lshlti3, false, true),
        (__lshrti3, false, false),
        (__ashrti3, true, false),
    ] {
        for value in [0, 1, (1u128 << 127) | 0x123456789abcdef, u128::MAX] {
            for shift in [0, 1, 63, 64, 65, 127, 128, 129, u32::MAX] {
                op(h.env(), ptr(OUT), value as u64, (value >> 64) as u64, shift).unwrap();
                let expected = if arithmetic {
                    ((value as i128) >> (shift % 128)) as u128
                } else if shift >= 128 {
                    0
                } else if left {
                    value << shift
                } else {
                    value >> shift
                };
                assert_eq!(h.read128(), expected, "value={value:x}, shift={shift}");
            }
        }
        assert!(op(h.env(), ptr(END - 15), 1, 0, 0).is_err());
        h.budget(cost::BUILTIN - 1);
        assert!(op(h.env(), ptr(OUT), 1, 0, 0).is_err());
        assert_eq!(h.remaining(), 0);
        h.budget(u64::MAX);
    }
}

#[test]
fn integer_arithmetic_handles_signs_overflow_and_zero_divisors() {
    let mut h = Host::new(false);
    for (op, lhs, rhs, expected, price) in [
        (
            __divti3 as Binary,
            (-17i128) as u128,
            5,
            (-3i128) as u128,
            cost::BUILTIN_DIV,
        ),
        (
            __modti3,
            (-17i128) as u128,
            5,
            (-2i128) as u128,
            cost::BUILTIN_DIV,
        ),
        (
            __divti3,
            i128::MIN as u128,
            u128::MAX,
            i128::MIN as u128,
            cost::BUILTIN_DIV,
        ),
        (__modti3, i128::MIN as u128, u128::MAX, 0, cost::BUILTIN_DIV),
        (__udivti3, u128::MAX, 2, u128::MAX / 2, cost::BUILTIN_DIV),
        (__umodti3, u128::MAX, 2, 1, cost::BUILTIN_DIV),
        (__multi3, u128::MAX, 2, u128::MAX - 1, cost::BUILTIN),
    ] {
        h.budget(price);
        op(
            h.env(),
            ptr(OUT),
            lhs as u64,
            (lhs >> 64) as u64,
            rhs as u64,
            (rhs >> 64) as u64,
        )
        .unwrap();
        assert_eq!(h.read128(), expected);
        assert_eq!(h.remaining(), 0);
        h.budget(u64::MAX);
        assert!(op(h.env(), ptr(END - 15), 9, 0, 2, 0).is_err());
    }
    for op in [__divti3 as Binary, __udivti3, __modti3, __umodti3] {
        h.write(OUT, &[0xa5; 16]);
        assert_error(op(h.env(), ptr(OUT), 1, 0, 0, 0), "zero");
        assert_eq!(h.read(OUT, 16), vec![0xa5; 16]);
    }
}

// Explicit IEEE binary128 encodings, independent of the conversion helpers under test.
const ONE: u128 = 0x3fff0000000000000000000000000000;
const TWO: u128 = 0x40000000000000000000000000000000;
const THREE: u128 = 0x40008000000000000000000000000000;
const HALF: u128 = 0x3ffe0000000000000000000000000000;
const SIGN: u128 = 1 << 127;

#[test]
fn binary128_arithmetic_writes_exact_unaligned_results() {
    let mut h = Host::new(false);
    for (op, a, b, expected, price) in [
        (__addtf3 as Binary, ONE, TWO, THREE, cost::BUILTIN),
        (__subtf3, THREE, TWO, ONE, cost::BUILTIN),
        (__multf3, HALF, TWO, ONE, cost::BUILTIN),
        (__divtf3, ONE, TWO, HALF, cost::BUILTIN_DIV),
    ] {
        h.budget(price);
        op(
            h.env(),
            ptr(OUT),
            a as u64,
            (a >> 64) as u64,
            b as u64,
            (b >> 64) as u64,
        )
        .unwrap();
        assert_eq!(h.read128(), expected);
        assert_eq!(h.remaining(), 0);
        h.budget(u64::MAX);
        assert!(op(h.env(), ptr(END - 15), 0, 0, 0, 0).is_err());
    }
    __negtf2(h.env(), ptr(OUT), 0, (ONE >> 64) as u64).unwrap();
    assert_eq!(h.read128(), ONE | SIGN);
    __negtf2(h.env(), ptr(OUT), 0, 0).unwrap();
    assert_eq!(h.read128(), SIGN);
}

#[test]
fn binary128_conversions_preserve_sign_and_truncate_toward_zero() {
    let mut h = Host::new(false);
    __extendsftf2(h.env(), ptr(OUT), -1.0).unwrap();
    assert_eq!(h.read128(), ONE | SIGN);
    __extenddftf2(h.env(), ptr(OUT), 0.5).unwrap();
    assert_eq!(h.read128(), HALF);
    let hi = ((THREE | SIGN) >> 64) as u64;
    assert_eq!(__trunctfdf2(h.env(), 0, hi).unwrap(), -3.0);
    assert_eq!(__trunctfsf2(h.env(), 0, hi).unwrap(), -3.0);
    assert_eq!(__fixtfsi(h.env(), 0, hi).unwrap(), -3);
    assert_eq!(__fixtfdi(h.env(), 0, hi).unwrap(), -3);
    __fixtfti(h.env(), ptr(OUT), 0, hi).unwrap();
    assert_eq!(h.read128() as i128, -3);
    let hi = (THREE >> 64) as u64;
    assert_eq!(__fixunstfsi(h.env(), 0, hi).unwrap(), 3);
    assert_eq!(__fixunstfdi(h.env(), 0, hi).unwrap(), 3);
    __fixunstfti(h.env(), ptr(OUT), 0, hi).unwrap();
    assert_eq!(h.read128(), 3);
    __fixsfti(h.env(), ptr(OUT), -3.75).unwrap();
    assert_eq!(h.read128() as i128, -3);
    __fixdfti(h.env(), ptr(OUT), -3.75).unwrap();
    assert_eq!(h.read128() as i128, -3);
    __fixunssfti(h.env(), ptr(OUT), 3.75).unwrap();
    assert_eq!(h.read128(), 3);
    __fixunsdfti(h.env(), ptr(OUT), 3.75).unwrap();
    assert_eq!(h.read128(), 3);
    assert_eq!(__floatsidf(h.env(), -3).unwrap(), -3.0);
    __floatsitf(h.env(), ptr(OUT), -3).unwrap();
    assert_eq!(h.read128(), THREE | SIGN);
    __floatditf(h.env(), ptr(OUT), (-3i64) as u64).unwrap();
    assert_eq!(h.read128(), THREE | SIGN);
    __floatunsitf(h.env(), ptr(OUT), 3).unwrap();
    assert_eq!(h.read128(), THREE);
    __floatunditf(h.env(), ptr(OUT), 3).unwrap();
    assert_eq!(h.read128(), THREE);
    assert_eq!(
        __floattidf(h.env(), (-3i64) as u64, u64::MAX).unwrap(),
        -3.0
    );
    assert_eq!(__floatuntidf(h.env(), 3, 0).unwrap(), 3.0);
}

#[test]
fn binary128_comparisons_distinguish_order_equality_and_nan() {
    let mut h = Host::new(false);
    for (op, unordered) in [
        (__eqtf2 as Compare, 1),
        (__netf2, 1),
        (__getf2, -1),
        (__gttf2, 0),
        (__letf2, 1),
        (__lttf2, 0),
        (__cmptf2, 1),
    ] {
        for (a, b, expected) in [
            (ONE, TWO, -1),
            (TWO, ONE, 1),
            (ONE, ONE, 0),
            (0, SIGN, 0),
            (0x7fff8000000000000000000000000000, ONE, unordered),
        ] {
            assert_eq!(
                op(
                    h.env(),
                    a as u64,
                    (a >> 64) as u64,
                    b as u64,
                    (b >> 64) as u64
                )
                .unwrap(),
                expected
            );
        }
    }
    assert_eq!(
        __unordtf2(h.env(), 0, 0x7fff800000000000, 0, (ONE >> 64) as u64).unwrap(),
        1
    );
    assert_eq!(__unordtf2(h.env(), 0, 0, 0, 0).unwrap(), 0);
}
