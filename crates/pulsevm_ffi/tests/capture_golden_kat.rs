//! One-shot capture of known-answer test (KAT) vectors from the live C++ oracle.
//!
//! The pure-Rust consensus ports (`pulsevm_softfloat`, `pulsevm_crypto::k1`) are
//! validated bit-for-bit against C++ by the sibling `*_cross_validation` tests.
//! Those tests die with the C++ bridge, so before the bridge is removed this
//! harness freezes a deterministic slice of the oracle's answers into golden
//! files that live in the target crates. Standalone replay tests there
//! (`pulsevm_softfloat/tests/softfloat_kat.rs`, `pulsevm_crypto/tests/k1_kat.rs`)
//! then guard the ports against regression with no C++ in the build.
//!
//! Every vector written here is first asserted equal between the Rust port and
//! the C++ oracle, so the golden files are C++-attested at capture time.
//!
//! This is opt-in (it writes into the source tree) and only runs when asked:
//!
//! ```text
//! LLVM_SYS_221_PREFIX=... BOOST_HEADERS=... BOOST_LIB=... ZLIB_ROOT=... \
//!   PULSEVM_CAPTURE_KAT=1 cargo test -p pulsevm_ffi --features arena-shadow \
//!   --test capture_golden_kat -- --nocapture
//! ```

use std::{
    fmt::Write as _,
    path::PathBuf,
};

use pulsevm_crypto::k1::K1PrivateKey;
use pulsevm_ffi as cxx_oracle;
use pulsevm_softfloat as rs;

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) -- identical to the cross-validation test so
// the captured inputs cover the same structured bit patterns.
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

fn gen_f128(rng: &mut SplitMix64) -> (u64, u64) {
    match rng.next_u64() % 8 {
        0 | 1 => (rng.next_u64(), rng.next_u64()),
        2 | 3 => {
            let sign = (rng.next_u64() & 1) << 63;
            let exp = (rng.next_u64() % 0x7FFE + 1) << 48;
            let frac_hi = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
            (rng.next_u64(), sign | exp | frac_hi)
        }
        4 => {
            let sign = (rng.next_u64() & 1) << 63;
            let exp = (0x3FFFu64
                .wrapping_add(rng.next_u64() % 128)
                .wrapping_sub(64))
                << 48;
            let frac_hi = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
            (rng.next_u64(), sign | exp | frac_hi)
        }
        5 => {
            let sign = (rng.next_u64() & 1) << 63;
            let frac_hi = rng.next_u64() & 0x0000_FFFF_FFFF_FFFF;
            (rng.next_u64(), sign | frac_hi)
        }
        6 => {
            let sign = (rng.next_u64() & 1) << 63;
            let e = 0x3FFF + (rng.next_u64() % 130) as i64 - 2;
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
        _ => *pick(F128_EDGES, rng),
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
        3 => (rng.next_u32() & 0x8000_0000) | (rng.next_u32() & 0x7F_FFFF),
        _ => *pick(F32_EDGES, rng),
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
        _ => *pick(F64_EDGES, rng),
    }
}

fn pick<'a, T>(slice: &'a [T], rng: &mut SplitMix64) -> &'a T {
    &slice[(rng.next_u64() as usize) % slice.len()]
}

// ---------------------------------------------------------------------------
// Edge-case tables (copied from the cross-validation test).
// ---------------------------------------------------------------------------

const F128_EDGES: &[(u64, u64)] = &[
    (0, 0),
    (0, 0x8000_0000_0000_0000),
    (0, 0x7FFF_0000_0000_0000),
    (0, 0xFFFF_0000_0000_0000),
    (0, 0x7FFF_8000_0000_0000),
    (0, 0xFFFF_8000_0000_0000),
    (1, 0x7FFF_0000_0000_0000),
    (0, 0x7FFF_0000_0000_0001),
    (0xDEAD_BEEF, 0x7FFF_4000_0000_0000),
    (0xDEAD_BEEF, 0x7FFF_0000_0000_0000),
    (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_7FFF_FFFF_FFFF),
    (0, 0x0001_0000_0000_0000),
    (0xFFFF_FFFF_FFFF_FFFF, 0x7FFE_FFFF_FFFF_FFFF),
    (0xFFFF_FFFF_FFFF_FFFF, 0xFFFE_FFFF_FFFF_FFFF),
    (1, 0),
    (0xFFFF_FFFF_FFFF_FFFF, 0x0000_FFFF_FFFF_FFFF),
    (0, 0x3FFF_0000_0000_0000),
    (0, 0xBFFF_0000_0000_0000),
    (0, 0x4000_0000_0000_0000),
    (0, 0x3FFE_0000_0000_0000),
    (0, 0x4005_0000_0000_0000),
    (0, 0x400C_0000_0000_0000),
    (0x0000_0000_0000_0800, 0x3FFF_0000_0000_0000),
    (0x0000_0000_0000_1800, 0x3FFF_0000_0000_0000),
    (0xFFFF_FFFF_FFFF_FFFF, 0x3FFE_FFFF_FFFF_FFFF),
    (0, 0x401E_0000_0000_0000),
    (0, 0x401F_0000_0000_0000),
    (0, 0x403E_0000_0000_0000),
    (0, 0x403F_0000_0000_0000),
    (0, 0x407E_0000_0000_0000),
    (0, 0x407F_0000_0000_0000),
    (0, 0xC01E_0000_0000_0000),
    (0, 0xC03E_0000_0000_0000),
];

const F32_EDGES: &[u32] = &[
    0x0000_0000,
    0x8000_0000,
    0x7F80_0000,
    0xFF80_0000,
    0x7FC0_0000,
    0xFFC0_0000,
    0x7F80_0001,
    0x7FA0_0000,
    0x0000_0001,
    0x007F_FFFF,
    0x0080_0000,
    0x7F7F_FFFF,
    0x3F80_0000,
    0xBF80_0000,
    0x4000_0000,
    0x4B00_0000,
    0x4F00_0000,
    0x5F00_0000,
    0x7F00_0000,
];

const F64_EDGES: &[u64] = &[
    0x0000_0000_0000_0000,
    0x8000_0000_0000_0000,
    0x7FF0_0000_0000_0000,
    0xFFF0_0000_0000_0000,
    0x7FF8_0000_0000_0000,
    0xFFF8_0000_0000_0000,
    0x7FF0_0000_0000_0001,
    0x7FF4_0000_0000_0000,
    0x0000_0000_0000_0001,
    0x000F_FFFF_FFFF_FFFF,
    0x0010_0000_0000_0000,
    0x7FEF_FFFF_FFFF_FFFF,
    0x3FF0_0000_0000_0000,
    0xBFF0_0000_0000_0000,
    0x4000_0000_0000_0000,
    0x41E0_0000_0000_0000,
    0x43E0_0000_0000_0000,
    0x46F0_0000_0000_0000,
    0x47F0_0000_0000_0000,
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
const U128_EDGES: &[(u64, u64)] = &[
    (0, 0),
    (1, 0),
    (u64::MAX, 0),
    (0, 1),
    (u64::MAX, u64::MAX),
    (0, 0x8000_0000_0000_0000),
    (u64::MAX, 0x7FFF_FFFF_FFFF_FFFF),
    (0xFFFF_FFFF, 0),
    (0, 0xFFFF_FFFF_FFFF_FFFF),
];

// ---------------------------------------------------------------------------
// Oracle unwrappers.
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

// A captured golden line: the op, its input tokens, and the result tokens.
struct Golden(String);

impl Golden {
    fn new() -> Self {
        Golden(String::new())
    }
    fn line(&mut self, op: &str, args: &[u64], res: &[u64]) {
        let mut s = String::new();
        s.push_str(op);
        for a in args {
            write!(s, " {a:x}").unwrap();
        }
        s.push_str(" =>");
        for r in res {
            write!(s, " {r:x}").unwrap();
        }
        s.push('\n');
        self.0.push_str(&s);
    }
}

fn split128(v: u128) -> [u64; 2] {
    [v as u64, (v >> 64) as u64]
}

// ---------------------------------------------------------------------------
// softfloat capture: for each op, assert Rust == C++ and record the answer.
// ---------------------------------------------------------------------------

fn capture_softfloat() -> String {
    let mut rng = SplitMix64::new(0x0BAD_C0DE_1234_5678);
    let mut g = Golden::new();

    // Input pools.
    let mut f128_pool: Vec<(u64, u64)> = F128_EDGES.to_vec();
    for _ in 0..96 {
        f128_pool.push(gen_f128(&mut rng));
    }
    // Binary/cmp pairs: full edge x edge (special-case coverage) + random pairs.
    let mut f128_pairs: Vec<((u64, u64), (u64, u64))> = Vec::new();
    for &a in F128_EDGES {
        for &b in F128_EDGES {
            f128_pairs.push((a, b));
        }
    }
    for _ in 0..256 {
        f128_pairs.push((gen_f128(&mut rng), gen_f128(&mut rng)));
    }

    macro_rules! bin_arith {
        ($name:literal, $cpp:path, $rs:path) => {{
            for &((la, ha), (lb, hb)) in &f128_pairs {
                let c = cpp_u128($cpp(la, ha, lb, hb));
                let r = $rs(la, ha, lb, hb);
                assert_eq!(c, r, concat!($name, " rust != cpp"));
                g.line($name, &[la, ha, lb, hb], &split128(r));
            }
        }};
    }
    bin_arith!("addtf3", cxx_oracle::addtf3, rs::addtf3);
    bin_arith!("subtf3", cxx_oracle::subtf3, rs::subtf3);
    bin_arith!("multf3", cxx_oracle::multf3, rs::multf3);
    bin_arith!("divtf3", cxx_oracle::divtf3, rs::divtf3);

    for &(la, ha) in &f128_pool {
        let c = cpp_u128(cxx_oracle::negtf2(la, ha));
        let r = rs::negtf2(la, ha);
        assert_eq!(c, r, "negtf2 rust != cpp");
        g.line("negtf2", &[la, ha], &split128(r));
    }

    macro_rules! cmp_op {
        ($name:literal, $cpp:path, $rs:path) => {{
            for &((la, ha), (lb, hb)) in &f128_pairs {
                let c = $cpp(la, ha, lb, hb);
                let r = $rs(la, ha, lb, hb);
                assert_eq!(c, r, concat!($name, " rust != cpp"));
                g.line($name, &[la, ha, lb, hb], &[r as u32 as u64]);
            }
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

    // widening f32/f64 -> f128
    {
        let mut cases: Vec<u32> = F32_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(gen_f32_bits(&mut rng));
        }
        for b in cases {
            let f = f32::from_bits(b);
            let c = cpp_u128(cxx_oracle::extendsftf2(f));
            let r = rs::extendsftf2(f);
            assert_eq!(c, r, "extendsftf2 rust != cpp");
            g.line("extendsftf2", &[b as u64], &split128(r));
        }
    }
    {
        let mut cases: Vec<u64> = F64_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(gen_f64_bits(&mut rng));
        }
        for b in cases {
            let f = f64::from_bits(b);
            let c = cpp_u128(cxx_oracle::extenddftf2(f));
            let r = rs::extenddftf2(f);
            assert_eq!(c, r, "extenddftf2 rust != cpp");
            g.line("extenddftf2", &[b], &split128(r));
        }
    }

    // narrowing f128 -> f64/f32
    for &(l, h) in &f128_pool {
        let c = cxx_oracle::trunctfdf2(l, h).to_bits();
        let r = rs::trunctfdf2(l, h).to_bits();
        assert_eq!(c, r, "trunctfdf2 rust != cpp");
        g.line("trunctfdf2", &[l, h], &[r]);
    }
    for &(l, h) in &f128_pool {
        let c = cxx_oracle::trunctfsf2(l, h).to_bits();
        let r = rs::trunctfsf2(l, h).to_bits();
        assert_eq!(c, r, "trunctfsf2 rust != cpp");
        g.line("trunctfsf2", &[l, h], &[r as u64]);
    }

    // f128 -> integer (32/64-bit)
    macro_rules! f128_to_int {
        ($name:literal, $cpp:path, $rs:path) => {{
            for &(l, h) in &f128_pool {
                let c = $cpp(l, h) as i64 as u64;
                let r = $rs(l, h) as i64 as u64;
                assert_eq!(c, r, concat!($name, " rust != cpp"));
                g.line($name, &[l, h], &[r]);
            }
        }};
    }
    f128_to_int!("fixtfsi", cxx_oracle::fixtfsi, rs::fixtfsi);
    f128_to_int!("fixtfdi", cxx_oracle::fixtfdi, rs::fixtfdi);
    f128_to_int!("fixunstfsi", cxx_oracle::fixunstfsi, rs::fixunstfsi);
    f128_to_int!("fixunstfdi", cxx_oracle::fixunstfdi, rs::fixunstfdi);

    // f128 -> i128/u128
    for &(l, h) in &f128_pool {
        let c = cpp_i128(cxx_oracle::fixtfti(l, h));
        let r = rs::fixtfti(l, h) as u128;
        assert_eq!(c, r, "fixtfti rust != cpp");
        g.line("fixtfti", &[l, h], &split128(r));
    }
    for &(l, h) in &f128_pool {
        let c = cpp_u128_of(cxx_oracle::fixunstfti(l, h));
        let r = rs::fixunstfti(l, h);
        assert_eq!(c, r, "fixunstfti rust != cpp");
        g.line("fixunstfti", &[l, h], &split128(r));
    }

    // f32/f64 -> i128/u128
    {
        let mut cases: Vec<u32> = F32_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(gen_f32_bits(&mut rng));
        }
        for b in cases {
            let f = f32::from_bits(b);
            let c = cpp_i128(cxx_oracle::fixsfti(f));
            let r = rs::fixsfti(f) as u128;
            assert_eq!(c, r, "fixsfti rust != cpp");
            g.line("fixsfti", &[b as u64], &split128(r));
            let c = cpp_u128_of(cxx_oracle::fixunssfti(f));
            let r = rs::fixunssfti(f);
            assert_eq!(c, r, "fixunssfti rust != cpp");
            g.line("fixunssfti", &[b as u64], &split128(r));
        }
    }
    {
        let mut cases: Vec<u64> = F64_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(gen_f64_bits(&mut rng));
        }
        for b in cases {
            let f = f64::from_bits(b);
            let c = cpp_i128(cxx_oracle::fixdfti(f));
            let r = rs::fixdfti(f) as u128;
            assert_eq!(c, r, "fixdfti rust != cpp");
            g.line("fixdfti", &[b], &split128(r));
            let c = cpp_u128_of(cxx_oracle::fixunsdfti(f));
            let r = rs::fixunsdfti(f);
            assert_eq!(c, r, "fixunsdfti rust != cpp");
            g.line("fixunsdfti", &[b], &split128(r));
        }
    }

    // integer -> float/f128
    {
        let mut cases: Vec<i32> = I32_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(rng.next_u32() as i32);
        }
        for a in cases {
            let c = cxx_oracle::floatsidf(a).to_bits();
            let r = rs::floatsidf(a).to_bits();
            assert_eq!(c, r, "floatsidf rust != cpp");
            g.line("floatsidf", &[a as u32 as u64], &[r]);
            let c = cpp_u128(cxx_oracle::floatsitf(a));
            let r = rs::floatsitf(a);
            assert_eq!(c, r, "floatsitf rust != cpp");
            g.line("floatsitf", &[a as u32 as u64], &split128(r));
        }
    }
    {
        let mut cases: Vec<u32> = U32_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(rng.next_u32());
        }
        for a in cases {
            let c = cpp_u128(cxx_oracle::floatunsitf(a));
            let r = rs::floatunsitf(a);
            assert_eq!(c, r, "floatunsitf rust != cpp");
            g.line("floatunsitf", &[a as u64], &split128(r));
        }
    }
    {
        let mut cases: Vec<u64> = U64_EDGES.to_vec();
        for _ in 0..96 {
            cases.push(rng.next_u64());
        }
        for a in cases {
            let c = cpp_u128(cxx_oracle::floatditf(a));
            let r = rs::floatditf(a);
            assert_eq!(c, r, "floatditf rust != cpp");
            g.line("floatditf", &[a], &split128(r));
            let c = cpp_u128(cxx_oracle::floatunditf(a));
            let r = rs::floatunditf(a);
            assert_eq!(c, r, "floatunditf rust != cpp");
            g.line("floatunditf", &[a], &split128(r));
        }
    }

    // 128-bit integer -> double
    {
        let mut cases: Vec<(u64, u64)> = U128_EDGES.to_vec();
        for _ in 0..96 {
            cases.push((rng.next_u64(), rng.next_u64()));
        }
        for (l, h) in cases {
            let c = cxx_oracle::floattidf(l, h).to_bits();
            let r = rs::floattidf(l, h).to_bits();
            assert_eq!(c, r, "floattidf rust != cpp");
            g.line("floattidf", &[l, h], &[r]);
            let c = cxx_oracle::floatuntidf(l, h).to_bits();
            let r = rs::floatuntidf(l, h).to_bits();
            assert_eq!(c, r, "floatuntidf rust != cpp");
            g.line("floatuntidf", &[l, h], &[r]);
        }
    }

    g.0
}

// ---------------------------------------------------------------------------
// k1 capture: identity fields are asserted equal to C++; the deterministic
// (RFC6979) Rust signature is frozen and its recovery re-checked against C++.
// ---------------------------------------------------------------------------

fn capture_k1() -> String {
    let mut rng = SplitMix64::new(0x51F3_2A17_C0DE_9E55);
    let mut out = String::new();
    out.push_str("# seed_hex digest_hex => priv_str pub_packed_hex pub_str sig_packed_hex\n");

    let mut seeds: Vec<[u8; 32]> = Vec::new();
    for i in 0..64u64 {
        let mut s = [0u8; 32];
        for chunk in s.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        // avoid the astronomically unlikely invalid scalar
        if secp256k1::SecretKey::from_slice(&s).is_err() {
            s[31] ^= 1;
        }
        let _ = i;
        seeds.push(s);
    }

    // packed keys captured for the ordering check, paired with their C++ index
    let mut packed_keys: Vec<[u8; 34]> = Vec::new();

    for scalar in &seeds {
        let mut digest = [0u8; 32];
        for chunk in digest.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
        }

        // Rust side.
        let r_priv = K1PrivateKey::from_scalar(scalar).expect("rust priv");
        let r_priv_str = r_priv.to_string();
        let r_pub = r_priv.public_key();
        let r_pub_packed = r_pub.to_packed();
        let r_pub_str = r_pub.to_string();
        let r_sig = r_priv.sign(&digest);
        assert!(r_sig.is_canonical(), "rust sig not canonical");
        let r_sig_packed = r_sig.to_packed();

        // C++ oracle: assert identity fields agree, and that C++ recovers the
        // signer from the Rust signature (the property the chain relies on).
        let c_digest = pulsevm_ffi::make_shared_digest_from_existing_hash(scalar);
        let c_priv = pulsevm_ffi::make_k1_private_key(c_digest.as_ref().unwrap());
        let c_priv_ref = c_priv.as_ref().unwrap();
        assert_eq!(
            r_priv_str,
            pulsevm_ffi::private_key_to_string(c_priv_ref),
            "priv str != cpp"
        );
        let c_pub = pulsevm_ffi::get_public_key_from_private_key(c_priv_ref);
        let c_pub_ref = c_pub.as_ref().unwrap();
        assert_eq!(
            r_pub_packed.as_slice(),
            pulsevm_ffi::packed_public_key_bytes(c_pub_ref).as_slice(),
            "pub packed != cpp"
        );
        assert_eq!(
            r_pub_str,
            pulsevm_ffi::public_key_to_string(c_pub_ref),
            "pub str != cpp"
        );
        let c_dig = pulsevm_ffi::make_shared_digest_from_existing_hash(&digest);
        let c_sig_from_rust =
            pulsevm_ffi::parse_signature_from_bytes(&r_sig_packed).expect("cpp parse rust sig");
        let c_recovered = pulsevm_ffi::recover_public_key_from_signature(
            c_sig_from_rust.as_ref().unwrap(),
            c_dig.as_ref().unwrap(),
        )
        .expect("cpp recover");
        assert_eq!(
            pulsevm_ffi::packed_public_key_bytes(c_recovered.as_ref().unwrap()).as_slice(),
            r_pub_packed.as_slice(),
            "cpp failed to recover signer from rust sig"
        );

        packed_keys.push(r_pub_packed);

        writeln!(
            out,
            "{} {} => {} {} {} {}",
            hex(scalar),
            hex(&digest),
            r_priv_str,
            hex(&r_pub_packed),
            r_pub_str,
            hex(&r_sig_packed),
        )
        .unwrap();
    }

    // Ordering: freeze the C++ public_key_type::cmp ordering of the KAT keys so
    // the native unsigned-bytes compare in Authority::validate stays faithful.
    let mut idx: Vec<usize> = (0..packed_keys.len()).collect();
    idx.sort_by(|&i, &j| {
        let a = pulsevm_ffi::parse_public_key_from_bytes(&packed_keys[i]).expect("parse a");
        let b = pulsevm_ffi::parse_public_key_from_bytes(&packed_keys[j]).expect("parse b");
        match a.cmp(&b).signum() {
            -1 => std::cmp::Ordering::Less,
            1 => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        }
    });
    out.push_str("# cxx_cmp_sorted_order (indices into the vectors above)\n#order");
    for i in idx {
        write!(out, " {i}").unwrap();
    }
    out.push('\n');

    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn target_tests_dir(crate_name: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR is .../crates/pulsevm_ffi
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().join(crate_name).join("tests")
}

#[test]
fn capture_golden_kat() {
    if std::env::var("PULSEVM_CAPTURE_KAT").is_err() {
        eprintln!("skipping capture; set PULSEVM_CAPTURE_KAT=1 to regenerate golden KAT files");
        return;
    }

    let softfloat = capture_softfloat();
    let sf_path = target_tests_dir("pulsevm_softfloat").join("softfloat_kat.txt");
    let sf_lines = softfloat.lines().count();
    std::fs::write(&sf_path, &softfloat).expect("write softfloat golden");
    eprintln!("wrote {} ({sf_lines} vectors)", sf_path.display());

    let k1 = capture_k1();
    let k1_path = target_tests_dir("pulsevm_crypto").join("k1_kat.txt");
    std::fs::write(&k1_path, &k1).expect("write k1 golden");
    eprintln!("wrote {} ({} lines)", k1_path.display(), k1.lines().count());
}
