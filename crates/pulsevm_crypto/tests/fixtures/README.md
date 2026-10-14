# ML-DSA verification fixtures

`ml_dsa_wycheproof.json` freezes 12 verification cases for each FIPS 204 parameter
set from [C2SP Wycheproof](https://github.com/C2SP/wycheproof). The source URL and
SHA-256 of each complete downloaded source file are included in the fixture.
These vectors are distributed under Wycheproof's
[Apache 2.0 license](https://github.com/C2SP/wycheproof/blob/main/LICENSE).

The subset covers empty and nonempty contexts, the context-length boundary,
truncated and overlong signatures, modified challenge bytes, reversed and
repeated hints, excess hints, and nonzero hint padding. It includes the regression
for [CVE-2026-24850](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9).
