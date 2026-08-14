//! Bit-exact cross-validation of the pure-Rust `pulsevm_softfloat` port against
//! the vendored C++ Berkeley SoftFloat / compiler-rt routines reached through
//! this crate's cxx bridge.
//!
//! Placement: this lives in `pulsevm_ffi/tests` because it is the only crate
//! that can see BOTH sides at once -- the C++ oracle (the bridge functions,
//! e.g. `pulsevm_ffi::addtf3`) and the pure-Rust port (`pulsevm_softfloat`,
//! wired in as a dev-dependency). The build requires the C++ toolchain, so run
//! it with the softfloat/boost env and `--features arena-shadow` (which is what
//! makes the ffi crate compile in this tree):
//!
//! ```text
//! LLVM_SYS_221_PREFIX=... BOOST_HEADERS=... BOOST_LIB=... ZLIB_ROOT=... \
//!   cargo test -p pulsevm_ffi --features arena-shadow \
//!   --test softfloat_cross_validation -- --nocapture
//! ```
//!
//! Every float output is compared by raw bits (so -0.0 and every NaN payload
//! are checked exactly), integer outputs by value, comparisons by the i32 code.

use pulsevm_ffi as cxx_oracle;
use pulsevm_softfloat as rs;

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) -- reproducible without an external rand dep.
// ---------------------------------------------------------------------------

struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
}

// ---------------------------------------------------------------------------
// Input generators. Each mixes fully-random bit patterns with "structured"
// values (bounded exponents, subnormals, specials) so both the exotic paths
// (NaN/inf) and the ordinary finite-arithmetic rounding paths are exercised.
// ---------------------------------------------------------------------------

/// Returns f128 bits as (lo, hi).
fn gen_f128(rng: &mut SplitMix64) -> (u64, u64) {
    match rng.next_u64() % 8 {
        0 | 1 => (rng.next_u64(), rng.next_u64()), // fully random (hits NaN/inf/subnormal)
        2 | 3 => {
            // normal-ish, full exponent range
            let sign = (rng.next_u64() & 1) << 63;
            let exp = (rng.next_u64() % 0x7FFE + 1) << 48; // [1, 0x7FFE]
            let frac_hi = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
            (rng.next_u64(), sign | exp | frac_hi)
        }
        4 => {
            // narrow exponent band around 1.0 so binary ops stay finite and
            // exercise rounding / ties heavily
            let sign = (rng.next_u64() & 1) << 63;
            let exp = (0x3FFFu64
                .wrapping_add(rng.next_u64() % 128)
                .wrapping_sub(64))
                << 48;
            let frac_hi = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
            (rng.next_u64(), sign | exp | frac_hi)
        }
        5 => {
            // subnormal (exp == 0, nonzero fraction)
            let sign = (rng.next_u64() & 1) << 63;
            let frac_hi = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
            (rng.next_u64(), sign | frac_hi)
        }
        6 => {
            // small integers / powers of two as f128 (good for int conversions)
            let sign = (rng.next_u64() & 1) << 63;
            let e = 0x3FFF + (rng.next_u64() % 130) as i64 - 2; // ~ 2^-2 .. 2^127
            let exp = ((e as u64) & 0x7FFF) << 48;
            let frac_hi = if rng.next_u64() & 1 == 0 {
                0
            } else {
                rng.next_u64() & 0x0000_FFFF_FFFF_FFFF
            };
            let lo = if rng.next_u64() & 1 == 0 {
                0
            } else {
                rng.next_u64()
            };
            (lo, sign | exp | frac_hi)
        }
        _ => *pick(&F128_EDGES, rng),
    }
}

fn gen_f32_bits(rng: &mut SplitMix64) -> u32 {
    match rng.next_u64() % 6 {
        0 | 1 => rng.next_u32(),
        2 => {
            let sign = (rng.next_u32() & 1) << 31;
            let exp = (rng.next_u32() % 0xFE + 1) << 23;
            sign | exp | (rng.next_u32() & 0x7F_FFFF)
        }
        3 => (rng.next_u32() & 0x8000_0000) | (rng.next_u32() & 0x7F_FFFF), // subnormal/zero
        _ => *pick(&F32_EDGES, rng),
    }
}

fn gen_f64_bits(rng: &mut SplitMix64) -> u64 {
    match rng.next_u64() % 6 {
        0 | 1 => rng.next_u64(),
        2 => {
            let sign = (rng.next_u64() & 1) << 63;
            let exp = (rng.next_u64() % 0x7FE + 1) << 52;
            sign | exp | (rng.next_u64() & 0x000F_FFFF_FFFF_FFFF)
        }
        3 => (rng.next_u64() & 0x8000_0000_0000_0000) | (rng.next_u64() & 0x000F_FFFF_FFFF_FFFF),
        _ => *pick(&F64_EDGES, rng),
    }
}

fn pick<'a, T>(slice: &'a [T], rng: &mut SplitMix64) -> &'a T {
    &slice[(rng.next_u64() as usize) % slice.len()]
}

// ---------------------------------------------------------------------------
// Explicit edge-case tables.
// ---------------------------------------------------------------------------

// (lo, hi)
const F128_EDGES: &[(u64, u64)] = &[
    (0, 0),                                         // +0
    (0, 0x8000_0000_0000_0000),                     // -0
    (0, 0x7FFF_0000_0000_0000),                     // +inf
    (0, 0xFFFF_0000_0000_0000),                     // -inf
    (0, 0x7FFF_8000_0000_0000),                     // +qNaN (canonical)
    (0, 0xFFFF_8000_0000_0000),                     // -qNaN (softfloat default NaN)
    (1, 0x7FFF_0000_0000_0000),                     // +sNaN (payload in lo)
    (0, 0x7FFF_0000_0000_0001),                     // +sNaN (payload in hi)
    (0xDEAD_BEEF, 0x7FFF_4000_0000_0000),           // qNaN, arbitrary payload
    (0xDEAD_BEEF, 0x7FFF_0000_0000_0000),           // sNaN, arbitrary payload
    (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_7FFF_FFFF_FFFF), // -sNaN, all-ones-ish payload
    (0, 0x0001_0000_0000_0000),                     // smallest positive normal
    (0xFFFF_FFFF_FFFF_FFFF, 0x7FFE_FFFF_FFFF_FFFF), // largest finite
    (0xFFFF_FFFF_FFFF_FFFF, 0xFFFE_FFFF_FFFF_FFFF), // most negative finite
    (1, 0),                                         // smallest positive subnormal
    (0xFFFF_FFFF_FFFF_FFFF, 0x0000_FFFF_FFFF_FFFF), // largest subnormal
    (0, 0x3FFF_0000_0000_0000),                     // 1.0
    (0, 0xBFFF_0000_0000_0000),                     // -1.0
    (0, 0x4000_0000_0000_0000),                     // 2.0
    (0, 0x3FFE_0000_0000_0000),                     // 0.5
    (0, 0x4005_0000_0000_0000),                     // 64.0
    (0, 0x400C_0000_0000_0000),                     // 8192.0
    // half-way values (mantissa LSBs set) to exercise round-to-nearest-even
    (0x0000_0000_0000_0800, 0x3FFF_0000_0000_0000),
    (0x0000_0000_0000_1800, 0x3FFF_0000_0000_0000),
    (0xFFFF_FFFF_FFFF_FFFF, 0x3FFE_FFFF_FFFF_FFFF),
    // ~ 2^31, 2^32, 2^63, 2^64, 2^127 (int-conversion boundaries)
    (0, 0x401E_0000_0000_0000), // 2^31
    (0, 0x401F_0000_0000_0000), // 2^32
    (0, 0x403E_0000_0000_0000), // 2^63
    (0, 0x403F_0000_0000_0000), // 2^64
    (0, 0x407E_0000_0000_0000), // 2^127
    (0, 0x407F_0000_0000_0000), // 2^128
    (0, 0xC01E_0000_0000_0000), // -2^31
    (0, 0xC03E_0000_0000_0000), // -2^63
];

const F32_EDGES: &[u32] = &[
    0x0000_0000, // +0
    0x8000_0000, // -0
    0x7F80_0000, // +inf
    0xFF80_0000, // -inf
    0x7FC0_0000, // +qNaN
    0xFFC0_0000, // -qNaN
    0x7F80_0001, // +sNaN
    0x7FA0_0000, // sNaN payload
    0x0000_0001, // smallest subnormal
    0x007F_FFFF, // largest subnormal
    0x0080_0000, // smallest normal
    0x7F7F_FFFF, // largest finite
    0x3F80_0000, // 1.0
    0xBF80_0000, // -1.0
    0x4000_0000, // 2.0
    0x4B00_0000, // 2^23
    0x4F00_0000, // 2^31
    0x5F00_0000, // 2^63
    0x7F00_0000, // 2^127
];

const F64_EDGES: &[u64] = &[
    0x0000_0000_0000_0000, // +0
    0x8000_0000_0000_0000, // -0
    0x7FF0_0000_0000_0000, // +inf
    0xFFF0_0000_0000_0000, // -inf
    0x7FF8_0000_0000_0000, // +qNaN
    0xFFF8_0000_0000_0000, // -qNaN
    0x7FF0_0000_0000_0001, // +sNaN
    0x7FF4_0000_0000_0000, // sNaN payload
    0x0000_0000_0000_0001, // smallest subnormal
    0x000F_FFFF_FFFF_FFFF, // largest subnormal
    0x0010_0000_0000_0000, // smallest normal
    0x7FEF_FFFF_FFFF_FFFF, // largest finite
    0x3FF0_0000_0000_0000, // 1.0
    0xBFF0_0000_0000_0000, // -1.0
    0x4000_0000_0000_0000, // 2.0
    0x41E0_0000_0000_0000, // 2^31
    0x43E0_0000_0000_0000, // 2^63
    0x46F0_0000_0000_0000, // 2^112
    0x47F0_0000_0000_0000, // 2^128
];

const I32_EDGES: &[i32] = &[
    0,
    1,
    -1,
    2,
    -2,
    i32::MAX,
    i32::MIN,
    0x7FFF_FFFE,
    -0x7FFF_FFFF,
    12345,
    -98765,
];
const U32_EDGES: &[u32] = &[
    0,
    1,
    2,
    u32::MAX,
    u32::MAX - 1,
    0x8000_0000,
    0x7FFF_FFFF,
    305419896,
];
const U64_EDGES: &[u64] = &[
    0,
    1,
    2,
    u64::MAX,
    u64::MAX - 1,
    0x8000_0000_0000_0000,
    0x7FFF_FFFF_FFFF_FFFF,
    i64::MAX as u64,
    i64::MIN as u64,
    1234567890123456789,
];

// (lo, hi) forming a full 128-bit integer
const U128_EDGES: &[(u64, u64)] = &[
    (0, 0),
    (1, 0),
    (u64::MAX, 0),
    (0, 1),
    (u64::MAX, u64::MAX),
    (0, 0x8000_0000_0000_0000),        // i128::MIN
    (u64::MAX, 0x7FFF_FFFF_FFFF_FFFF), // i128::MAX
    (0xFFFF_FFFF, 0),
    (0, 0xFFFF_FFFF_FFFF_FFFF),
];

// ---------------------------------------------------------------------------
// Comparison helpers + failure accumulation.
// ---------------------------------------------------------------------------

fn cpp_u128(r: cxx_oracle::Float128) -> u128 {
    ((r.hi as u128) << 64) | r.lo as u128
}
fn cpp_i128(r: cxx_oracle::I128) -> u128 {
    ((r.hi as u128) << 64) | r.lo as u128
}
fn cpp_u128_of(r: cxx_oracle::U128) -> u128 {
    ((r.hi as u128) << 64) | r.lo as u128
}

#[derive(Default)]
struct Report {
    op: &'static str,
    cases: u64,
    fails: Vec<String>,
}

impl Report {
    fn new(op: &'static str) -> Self {
        Report {
            op,
            cases: 0,
            fails: Vec::new(),
        }
    }
    fn check(&mut self, ok: bool, detail: impl FnOnce() -> String) {
        self.cases += 1;
        if !ok && self.fails.len() < 12 {
            self.fails.push(detail());
        } else if !ok {
            self.fails.push(String::new()); // count only
        }
    }
    fn finish(&self) -> (u64, u64) {
        (self.cases, self.fails.len() as u64)
    }
    fn report(&self, out: &mut Vec<String>) {
        let (cases, fails) = self.finish();
        if fails == 0 {
            out.push(format!("  {:<12} {:>8} cases  BIT-EXACT", self.op, cases));
        } else {
            out.push(format!(
                "  {:<12} {:>8} cases  {} MISMATCH(es):",
                self.op, cases, fails
            ));
            for d in self.fails.iter().filter(|s| !s.is_empty()) {
                out.push(format!("      {d}"));
            }
        }
    }
    fn any_fail(&self) -> bool {
        !self.fails.is_empty()
    }
}

const N: usize = 40_000;

#[test]
fn softfloat_bit_exact_cross_validation() {
    let mut rng = SplitMix64::new(0x0BAD_C0DE_1234_5678);
    let mut reports: Vec<Report> = Vec::new();

    // Build a combined pool of f128 inputs: random draws + all edges, so binary
    // ops also see edge x edge and edge x random combinations.
    let mut f128_pool: Vec<(u64, u64)> = F128_EDGES.to_vec();
    for _ in 0..N {
        f128_pool.push(gen_f128(&mut rng));
    }

    // ---- binary arithmetic --------------------------------------------------
    macro_rules! bin_arith {
        ($name:literal, $cpp:path, $rs:path) => {{
            let mut r = Report::new($name);
            for _ in 0..N {
                let (la, ha) = gen_f128(&mut rng);
                let (lb, hb) = gen_f128(&mut rng);
                let c = cpp_u128($cpp(la, ha, lb, hb));
                let g = $rs(la, ha, lb, hb);
                r.check(c == g, || {
                    format!(
                        "a=({la:#018x},{ha:#018x}) b=({lb:#018x},{hb:#018x}) cpp={c:#034x} rs={g:#034x}"
                    )
                });
            }
            // edge x edge
            for &(la, ha) in F128_EDGES {
                for &(lb, hb) in F128_EDGES {
                    let c = cpp_u128($cpp(la, ha, lb, hb));
                    let g = $rs(la, ha, lb, hb);
                    r.check(c == g, || {
                        format!(
                            "a=({la:#018x},{ha:#018x}) b=({lb:#018x},{hb:#018x}) cpp={c:#034x} rs={g:#034x}"
                        )
                    });
                }
            }
            reports.push(r);
        }};
    }
    bin_arith!("addtf3", cxx_oracle::addtf3, rs::addtf3);
    bin_arith!("subtf3", cxx_oracle::subtf3, rs::subtf3);
    bin_arith!("multf3", cxx_oracle::multf3, rs::multf3);
    bin_arith!("divtf3", cxx_oracle::divtf3, rs::divtf3);

    // ---- negtf2 -------------------------------------------------------------
    {
        let mut r = Report::new("negtf2");
        for &(la, ha) in f128_pool.iter() {
            let c = cpp_u128(cxx_oracle::negtf2(la, ha));
            let g = rs::negtf2(la, ha);
            r.check(c == g, || {
                format!("a=({la:#018x},{ha:#018x}) cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }

    // ---- comparisons --------------------------------------------------------
    macro_rules! cmp_op {
        ($name:literal, $cpp:path, $rs:path) => {{
            let mut r = Report::new($name);
            for _ in 0..N {
                let (la, ha) = gen_f128(&mut rng);
                let (lb, hb) = gen_f128(&mut rng);
                let c = $cpp(la, ha, lb, hb);
                let g = $rs(la, ha, lb, hb);
                r.check(c == g, || {
                    format!("a=({la:#018x},{ha:#018x}) b=({lb:#018x},{hb:#018x}) cpp={c} rs={g}")
                });
            }
            for &(la, ha) in F128_EDGES {
                for &(lb, hb) in F128_EDGES {
                    let c = $cpp(la, ha, lb, hb);
                    let g = $rs(la, ha, lb, hb);
                    r.check(c == g, || {
                        format!(
                            "a=({la:#018x},{ha:#018x}) b=({lb:#018x},{hb:#018x}) cpp={c} rs={g}"
                        )
                    });
                }
            }
            reports.push(r);
        }};
    }
    cmp_op!("unordtf2", cxx_oracle::unordtf2, rs::unordtf2);
    cmp_op!("eqtf2", cxx_oracle::eqtf2, rs::eqtf2);
    cmp_op!("netf2", cxx_oracle::netf2, rs::netf2);
    cmp_op!("getf2", cxx_oracle::getf2, rs::getf2);
    cmp_op!("gttf2", cxx_oracle::gttf2, rs::gttf2);
    cmp_op!("letf2", cxx_oracle::letf2, rs::letf2);
    cmp_op!("lttf2", cxx_oracle::lttf2, rs::lttf2);
    cmp_op!("cmptf2", cxx_oracle::cmptf2, rs::cmptf2);

    // ---- widening f32/f64 -> f128 ------------------------------------------
    {
        let mut r = Report::new("extendsftf2");
        for _ in 0..N {
            let b = gen_f32_bits(&mut rng);
            let f = f32::from_bits(b);
            let c = cpp_u128(cxx_oracle::extendsftf2(f));
            let g = rs::extendsftf2(f);
            r.check(c == g, || {
                format!("f32={b:#010x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        for &b in F32_EDGES {
            let f = f32::from_bits(b);
            let c = cpp_u128(cxx_oracle::extendsftf2(f));
            let g = rs::extendsftf2(f);
            r.check(c == g, || {
                format!("f32={b:#010x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("extenddftf2");
        for _ in 0..N {
            let b = gen_f64_bits(&mut rng);
            let f = f64::from_bits(b);
            let c = cpp_u128(cxx_oracle::extenddftf2(f));
            let g = rs::extenddftf2(f);
            r.check(c == g, || {
                format!("f64={b:#018x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        for &b in F64_EDGES {
            let f = f64::from_bits(b);
            let c = cpp_u128(cxx_oracle::extenddftf2(f));
            let g = rs::extenddftf2(f);
            r.check(c == g, || {
                format!("f64={b:#018x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }

    // ---- narrowing f128 -> f64/f32 -----------------------------------------
    {
        let mut r = Report::new("trunctfdf2");
        for &(l, h) in f128_pool.iter() {
            let c = cxx_oracle::trunctfdf2(l, h).to_bits();
            let g = rs::trunctfdf2(l, h).to_bits();
            r.check(c == g, || {
                format!("a=({l:#018x},{h:#018x}) cpp={c:#018x} rs={g:#018x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("trunctfsf2");
        for &(l, h) in f128_pool.iter() {
            let c = cxx_oracle::trunctfsf2(l, h).to_bits();
            let g = rs::trunctfsf2(l, h).to_bits();
            r.check(c == g, || {
                format!("a=({l:#018x},{h:#018x}) cpp={c:#010x} rs={g:#010x}")
            });
        }
        reports.push(r);
    }

    // ---- f128 -> integer ----------------------------------------------------
    macro_rules! f128_to_int {
        ($name:literal, $cpp:path, $rs:path) => {{
            let mut r = Report::new($name);
            for &(l, h) in f128_pool.iter() {
                let c = $cpp(l, h);
                let g = $rs(l, h);
                r.check(c == g, || format!("a=({l:#018x},{h:#018x}) cpp={c} rs={g}"));
            }
            reports.push(r);
        }};
    }
    f128_to_int!("fixtfsi", cxx_oracle::fixtfsi, rs::fixtfsi);
    f128_to_int!("fixtfdi", cxx_oracle::fixtfdi, rs::fixtfdi);
    f128_to_int!("fixunstfsi", cxx_oracle::fixunstfsi, rs::fixunstfsi);
    f128_to_int!("fixunstfdi", cxx_oracle::fixunstfdi, rs::fixunstfdi);

    // ---- f128 -> i128/u128 (compiler-rt truncating) ------------------------
    {
        let mut r = Report::new("fixtfti");
        for &(l, h) in f128_pool.iter() {
            let c = cpp_i128(cxx_oracle::fixtfti(l, h));
            let g = rs::fixtfti(l, h) as u128;
            r.check(c == g, || {
                format!("a=({l:#018x},{h:#018x}) cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("fixunstfti");
        for &(l, h) in f128_pool.iter() {
            let c = cpp_u128_of(cxx_oracle::fixunstfti(l, h));
            let g = rs::fixunstfti(l, h);
            r.check(c == g, || {
                format!("a=({l:#018x},{h:#018x}) cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }

    // ---- f32/f64 -> i128/u128 ----------------------------------------------
    {
        let mut r = Report::new("fixsfti");
        let mut cases: Vec<u32> = F32_EDGES.to_vec();
        for _ in 0..N {
            cases.push(gen_f32_bits(&mut rng));
        }
        for b in cases {
            let f = f32::from_bits(b);
            let c = cpp_i128(cxx_oracle::fixsfti(f));
            let g = rs::fixsfti(f) as u128;
            r.check(c == g, || {
                format!("f32={b:#010x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("fixunssfti");
        let mut cases: Vec<u32> = F32_EDGES.to_vec();
        for _ in 0..N {
            cases.push(gen_f32_bits(&mut rng));
        }
        for b in cases {
            let f = f32::from_bits(b);
            let c = cpp_u128_of(cxx_oracle::fixunssfti(f));
            let g = rs::fixunssfti(f);
            r.check(c == g, || {
                format!("f32={b:#010x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("fixdfti");
        let mut cases: Vec<u64> = F64_EDGES.to_vec();
        for _ in 0..N {
            cases.push(gen_f64_bits(&mut rng));
        }
        for b in cases {
            let f = f64::from_bits(b);
            let c = cpp_i128(cxx_oracle::fixdfti(f));
            let g = rs::fixdfti(f) as u128;
            r.check(c == g, || {
                format!("f64={b:#018x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("fixunsdfti");
        let mut cases: Vec<u64> = F64_EDGES.to_vec();
        for _ in 0..N {
            cases.push(gen_f64_bits(&mut rng));
        }
        for b in cases {
            let f = f64::from_bits(b);
            let c = cpp_u128_of(cxx_oracle::fixunsdfti(f));
            let g = rs::fixunsdfti(f);
            r.check(c == g, || {
                format!("f64={b:#018x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }

    // ---- integer -> float/f128 ---------------------------------------------
    {
        let mut r = Report::new("floatsidf");
        let mut cases: Vec<i32> = I32_EDGES.to_vec();
        for _ in 0..N {
            cases.push(rng.next_u32() as i32);
        }
        for a in cases {
            let c = cxx_oracle::floatsidf(a).to_bits();
            let g = rs::floatsidf(a).to_bits();
            r.check(c == g, || format!("i32={a} cpp={c:#018x} rs={g:#018x}"));
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("floatsitf");
        let mut cases: Vec<i32> = I32_EDGES.to_vec();
        for _ in 0..N {
            cases.push(rng.next_u32() as i32);
        }
        for a in cases {
            let c = cpp_u128(cxx_oracle::floatsitf(a));
            let g = rs::floatsitf(a);
            r.check(c == g, || format!("i32={a} cpp={c:#034x} rs={g:#034x}"));
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("floatunsitf");
        let mut cases: Vec<u32> = U32_EDGES.to_vec();
        for _ in 0..N {
            cases.push(rng.next_u32());
        }
        for a in cases {
            let c = cpp_u128(cxx_oracle::floatunsitf(a));
            let g = rs::floatunsitf(a);
            r.check(c == g, || format!("u32={a} cpp={c:#034x} rs={g:#034x}"));
        }
        reports.push(r);
    }
    {
        // floatditf: bridge takes u64 but treats it as i64
        let mut r = Report::new("floatditf");
        let mut cases: Vec<u64> = U64_EDGES.to_vec();
        for _ in 0..N {
            cases.push(rng.next_u64());
        }
        for a in cases {
            let c = cpp_u128(cxx_oracle::floatditf(a));
            let g = rs::floatditf(a);
            r.check(c == g, || {
                format!("u64={a:#018x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("floatunditf");
        let mut cases: Vec<u64> = U64_EDGES.to_vec();
        for _ in 0..N {
            cases.push(rng.next_u64());
        }
        for a in cases {
            let c = cpp_u128(cxx_oracle::floatunditf(a));
            let g = rs::floatunditf(a);
            r.check(c == g, || {
                format!("u64={a:#018x} cpp={c:#034x} rs={g:#034x}")
            });
        }
        reports.push(r);
    }

    // ---- 128-bit integer -> double -----------------------------------------
    {
        let mut r = Report::new("floattidf");
        let mut cases: Vec<(u64, u64)> = U128_EDGES.to_vec();
        for _ in 0..N {
            cases.push((rng.next_u64(), rng.next_u64()));
        }
        for (l, h) in cases {
            let c = cxx_oracle::floattidf(l, h).to_bits();
            let g = rs::floattidf(l, h).to_bits();
            r.check(c == g, || {
                format!("i128=({l:#018x},{h:#018x}) cpp={c:#018x} rs={g:#018x}")
            });
        }
        reports.push(r);
    }
    {
        let mut r = Report::new("floatuntidf");
        let mut cases: Vec<(u64, u64)> = U128_EDGES.to_vec();
        for _ in 0..N {
            cases.push((rng.next_u64(), rng.next_u64()));
        }
        for (l, h) in cases {
            let c = cxx_oracle::floatuntidf(l, h).to_bits();
            let g = rs::floatuntidf(l, h).to_bits();
            r.check(c == g, || {
                format!("u128=({l:#018x},{h:#018x}) cpp={c:#018x} rs={g:#018x}")
            });
        }
        reports.push(r);
    }

    // ---- summary ------------------------------------------------------------
    let mut out = vec![String::from(
        "\n=== pulsevm_softfloat vs C++ Berkeley SoftFloat cross-validation ===",
    )];
    for rep in &reports {
        rep.report(&mut out);
    }
    let total_ops = reports.len();
    let failing_ops = reports.iter().filter(|r| r.any_fail()).count();
    out.push(format!(
        "=== {total_ops} ops, {} bit-exact, {failing_ops} with mismatches ===",
        total_ops - failing_ops
    ));
    println!("{}", out.join("\n"));

    assert!(
        failing_ops == 0,
        "{failing_ops}/{total_ops} softfloat ops diverged from the C++ oracle (see report above)"
    );
}
