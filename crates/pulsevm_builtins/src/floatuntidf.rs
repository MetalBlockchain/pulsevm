const DBL_MANT_DIG: u32 = 53;

/// compiler-rt ___floatuntidf: u128 -> f64, round-to-nearest-even
pub fn floatuntidf(a: u128) -> f64 {
    if a == 0 {
        return 0.0;
    }

    const N: u32 = 128;
    let mut a = a;
    let sd: u32 = N - a.leading_zeros(); // significant digits (__clzti2)
    let mut e: i32 = sd as i32 - 1;      // unbiased exponent

    if sd > DBL_MANT_DIG {
        // Reduce to MANT_DIG + 2 bits: keep the top 54 bits plus a sticky
        // bit (R) that ORs together everything shifted out, then round.
        match sd {
            s if s == DBL_MANT_DIG + 1 => a <<= 1,
            s if s == DBL_MANT_DIG + 2 => {}
            _ => {
                let sticky_mask = u128::MAX >> ((N + DBL_MANT_DIG + 2) - sd);
                let sticky = ((a & sticky_mask) != 0) as u128;
                a = (a >> (sd - (DBL_MANT_DIG + 2))) | sticky;
            }
        }

        a |= ((a & 4) != 0) as u128; // Or P into R (ties-to-even trick)
        a += 1;                      // round; may add a significant bit
        a >>= 2;                     // dump Q and R

        // Rounding may have carried into bit 53
        if a & (1u128 << DBL_MANT_DIG) != 0 {
            a >>= 1;
            e += 1;
        }
    } else {
        a <<= DBL_MANT_DIG - sd;
    }

    // Assemble: biased exponent into bits 62..52, mantissa low 52 bits
    // (the implicit leading 1 in `a` is masked off by the 52-bit mask)
    let bits: u64 = (((e + 1023) as u64) << 52)
        | ((a as u64) & 0x000F_FFFF_FFFF_FFFF);
    f64::from_bits(bits)
}