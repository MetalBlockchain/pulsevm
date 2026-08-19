//! Known-answer regression test for the pure-Rust softfloat port.
//!
//! `softfloat_kat.txt` was frozen from the C++ Berkeley SoftFloat oracle (see
//! `pulsevm_database/tests/capture_golden_kat.rs`); every vector was asserted equal
//! between this port and C++ at capture time. This test replays the same inputs
//! through the port and requires the recorded answers, so it keeps the
//! consensus-critical softfloat routines pinned after the C++ bridge is gone.
//!
//! Regenerate with `PULSEVM_CAPTURE_KAT=1 cargo test -p pulsevm_database
//! --test capture_golden_kat` while the bridge exists.

use pulsevm_softfloat as rs;

fn parse(tok: &str) -> u64 {
    u64::from_str_radix(tok, 16).unwrap_or_else(|_| panic!("bad hex token {tok:?}"))
}

fn split128(v: u128) -> Vec<u64> {
    vec![v as u64, (v >> 64) as u64]
}

/// Compute the token(s) this op produces for the given input tokens, exactly as
/// the capture harness recorded them.
fn eval(op: &str, a: &[u64]) -> Vec<u64> {
    match op {
        "addtf3" => split128(rs::addtf3(a[0], a[1], a[2], a[3])),
        "subtf3" => split128(rs::subtf3(a[0], a[1], a[2], a[3])),
        "multf3" => split128(rs::multf3(a[0], a[1], a[2], a[3])),
        "divtf3" => split128(rs::divtf3(a[0], a[1], a[2], a[3])),
        "negtf2" => split128(rs::negtf2(a[0], a[1])),
        "unordtf2" => vec![rs::unordtf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "eqtf2" => vec![rs::eqtf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "netf2" => vec![rs::netf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "getf2" => vec![rs::getf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "gttf2" => vec![rs::gttf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "letf2" => vec![rs::letf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "lttf2" => vec![rs::lttf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "cmptf2" => vec![rs::cmptf2(a[0], a[1], a[2], a[3]) as u32 as u64],
        "extendsftf2" => split128(rs::extendsftf2(f32::from_bits(a[0] as u32))),
        "extenddftf2" => split128(rs::extenddftf2(f64::from_bits(a[0]))),
        "trunctfdf2" => vec![rs::trunctfdf2(a[0], a[1]).to_bits()],
        "trunctfsf2" => vec![rs::trunctfsf2(a[0], a[1]).to_bits() as u64],
        "fixtfsi" => vec![rs::fixtfsi(a[0], a[1]) as i64 as u64],
        "fixtfdi" => vec![rs::fixtfdi(a[0], a[1]) as i64 as u64],
        "fixunstfsi" => vec![rs::fixunstfsi(a[0], a[1]) as i64 as u64],
        "fixunstfdi" => vec![rs::fixunstfdi(a[0], a[1]) as i64 as u64],
        "fixtfti" => split128(rs::fixtfti(a[0], a[1]) as u128),
        "fixunstfti" => split128(rs::fixunstfti(a[0], a[1])),
        "fixsfti" => split128(rs::fixsfti(f32::from_bits(a[0] as u32)) as u128),
        "fixunssfti" => split128(rs::fixunssfti(f32::from_bits(a[0] as u32))),
        "fixdfti" => split128(rs::fixdfti(f64::from_bits(a[0])) as u128),
        "fixunsdfti" => split128(rs::fixunsdfti(f64::from_bits(a[0]))),
        "floatsidf" => vec![rs::floatsidf(a[0] as u32 as i32).to_bits()],
        "floatsitf" => split128(rs::floatsitf(a[0] as u32 as i32)),
        "floatunsitf" => split128(rs::floatunsitf(a[0] as u32)),
        "floatditf" => split128(rs::floatditf(a[0])),
        "floatunditf" => split128(rs::floatunditf(a[0])),
        "floattidf" => vec![rs::floattidf(a[0], a[1]).to_bits()],
        "floatuntidf" => vec![rs::floatuntidf(a[0], a[1]).to_bits()],
        other => panic!("unknown op {other:?} in golden file"),
    }
}

#[test]
fn softfloat_matches_frozen_oracle_vectors() {
    let text = include_str!("softfloat_kat.txt");
    let mut ops = std::collections::BTreeMap::<String, u64>::new();
    let mut total = 0u64;

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (lhs, rhs) = line
            .split_once("=>")
            .unwrap_or_else(|| panic!("line {}: no '=>'", lineno + 1));
        let mut lhs = lhs.split_whitespace();
        let op = lhs.next().expect("op").to_string();
        let args: Vec<u64> = lhs.map(parse).collect();
        let want: Vec<u64> = rhs.split_whitespace().map(parse).collect();

        let got = eval(&op, &args);
        assert_eq!(
            got,
            want,
            "line {}: {op} {args:x?} -> got {got:x?} want {want:x?}",
            lineno + 1
        );

        *ops.entry(op).or_default() += 1;
        total += 1;
    }

    assert!(total > 0, "golden file was empty");
    // All 34 softfloat routines must appear, or the frozen file lost coverage.
    assert_eq!(ops.len(), 34, "expected 34 distinct ops, got {}", ops.len());
    eprintln!(
        "softfloat KAT: {total} vectors across {} ops replayed",
        ops.len()
    );
}
