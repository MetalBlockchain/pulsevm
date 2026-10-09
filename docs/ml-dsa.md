# ML-DSA account keys and contract verification

PulseVM protocol version 2 enables FIPS 204 pure ML-DSA-44, ML-DSA-65, and
ML-DSA-87 account authorities, transaction signatures, and contract verification.
The implementation uses the exact pinned RustCrypto `ml-dsa` version in
`pulsevm_crypto/Cargo.toml`. Verification uses integer lattice arithmetic and
canonical signature decoding. Independent Wycheproof vectors cover all three
parameter sets, including repeated hint indices, hint padding, and context limits.

This is a PulseVM extension to Antelope's key and signature variants. Existing
K1, R1, and WebAuthn wire tags and encodings retain their original values.
Producer keys and block signing continue to use the existing K1 representation.

## Activation and compatibility

`ProtocolFeature::MlDsa` permanently maps to protocol version 2. Stable and
nightly builds implement version 2, while genesis remains version 1. Installing
the binary does not activate ML-DSA. Operators must deploy supporting binaries
and coordinate the height schedule as described in
[protocol-features.md](./protocol-features.md). For example:

```json
{"protocol_upgrades":[{"protocol_version":2,"activation_height":1000000}]}
```

Before activation, `newaccount` and `updateauth` reject ML-DSA authorities,
transaction admission and execution reject ML-DSA signatures, and WASM execution
rejects imports of the new intrinsics even when the imported function is unused.
Permission-check intrinsics reject ML-DSA supplied keys before activation.
The candidate block context controls all these checks, including trusted replay
and instances reused across forks. Historical version-1 receipts and roots retain
their existing behavior. Old binaries cannot execute the activation block or
install its versioned state summary.

## Keys and signatures

| Parameter set | Wire tag | Public-key bytes | Detached-signature bytes | Transaction-envelope bytes |
|---|---:|---:|---:|---:|
| ML-DSA-44 | 3 | 1,312 | 2,420 | 3,733 |
| ML-DSA-65 | 4 | 1,952 | 3,309 | 5,262 |
| ML-DSA-87 | 5 | 2,592 | 4,627 | 7,220 |

A packed public key is the one-byte canonical variant tag followed by its
fixed-size FIPS 204 public key. A packed transaction signature is its variant tag,
the corresponding fixed-size public key, then the fixed-size detached signature.
There are no length fields in either payload. Structured ordering follows the
tags above and then lexicographic public-key bytes. Permission storage, PulseVM arena snapshots,
state roots, RAM accounting, RPC rendering, and ABI decoding use these packed
values. Existing permission RAM billing already includes the full packed key size.

ML-DSA cannot recover a public key from a signature. The envelope's key becomes
an authorization factor only after verification succeeds. Duplicate verified keys
remain an error, including two signatures carrying the same key. Weighted
authorities can combine ML-DSA keys with existing key types or account permissions.

Transaction signing uses the existing 32-byte transaction signing digest, which
binds chain ID, transaction bytes, and context-free data, as the ML-DSA message.
It uses the exact ASCII FIPS 204 context `PulseVM transaction`. This is pure
ML-DSA applied to that digest, rather than the distinct HashML-DSA algorithm.
The signing API produces deterministic FIPS 204 signatures; verification also
accepts conforming randomized signatures.

JSON uses `PUB_MLDSA44_`, `PUB_MLDSA65_`, or `PUB_MLDSA87_` followed by base58 of
the public-key payload plus a four-byte RIPEMD-160 checksum. Signature JSON uses
the corresponding `SIG_` prefix and the public-key-plus-signature payload.
Private keys use `PVT_` with the same algorithm suffix and a 32-byte secret seed.
The checksum is the first four bytes of RIPEMD-160 of `payload || suffix`, where
the suffix is ASCII `MLDSA44`, `MLDSA65`, or `MLDSA87`. Base58 input is bounded
before decoding. Secret seeds are zeroized on drop and omitted from `Debug`.

Generate and import keys with the CLI and wallet:

```sh
pulse create key --key-type MLDSA65 --to-console
pulse wallet create_key default MLDSA65
pulse wallet import --help
pulse create account creator newaccount PUB_MLDSA65_...
```

Wallet generation accepts `K1`, `MLDSA44`, `MLDSA65`, and `MLDSA87`; an empty
wallet key type retains the K1 default. Encrypted wallet storage supports
importing, reopening, and transaction signing with all three ML-DSA seeds.
Rust callers can use `MlDsaPrivateKey`, `SignedTransaction::sign_ml_dsa`, and
`recovered_authority_keys_with_protocol`. The older context-free recovery helper
continues to select genesis rules.

## WASM host ABI

Both functions are imported from `env`. Every pointer and length is an `i32`
WASM value representing an unsigned linear-memory offset or byte length:

```c
int32_t verify_mldsa(
    const void* message, uint32_t message_len,
    const void* signature, uint32_t signature_len,
    const void* public_key, uint32_t public_key_len,
    const void* context, uint32_t context_len);

void assert_verify_mldsa(
    const void* message, uint32_t message_len,
    const void* signature, uint32_t signature_len,
    const void* public_key, uint32_t public_key_len,
    const void* context, uint32_t context_len);
```

`public_key` is a packed public key, including its tag. `signature` is a detached
FIPS 204 signature, without an envelope or tag. The public-key tag selects the
parameter set. Contexts may be empty and are limited to 255 bytes; messages are
limited to 1,048,576 bytes. Both limits are inclusive. These crypto intrinsics
are available to context-free actions.

`verify_mldsa` returns 1 on success and 0 for a cryptographic verification failure,
including malformed canonical signature content. `assert_verify_mldsa` traps on
verification failure. Both trap for an inactive feature, unknown key tag,
incorrect fixed length, oversized message or context, invalid memory range, or
insufficient CPU. Verification checks cheap bounds and bills CPU before reading
the full message or expanding the public lattice.

The existing `recover_key` and `assert_recover_key` also accept the new transaction
signature envelopes after activation. They verify the transaction context and
digest before returning or comparing the embedded packed public key. The existing
partial-output behavior of `recover_key` is retained: it returns the full packed
key length while copying as much as the output capacity permits. New envelopes
must consume their declared input exactly.

## Deterministic resource billing

Native verification is billed as a fixed parameter-set cost plus 100 points per
message or context byte:

| Parameter set | Base CPU points |
|---|---:|
| ML-DSA-44 | 20,000,000 |
| ML-DSA-65 | 35,000,000 |
| ML-DSA-87 | 55,000,000 |

These provisional values include public-matrix expansion. They need estimator
calibration before a production rollout; changing them after activation requires
another protocol version. See [intrinsic-cost-model.md](./intrinsic-cost-model.md).
Saturating arithmetic protects the cost computation from overflow.

Transaction verification charges the same formula for the 32-byte signing digest
and 19-byte transaction context, once per ML-DSA signature. Admission and execution
reject signature sets exceeding the transaction CPU ceiling before cryptography.
Measured execution adds this cost to the receipt, first-time peer validation
remeasures it independently, and trusted replay restores the already validated
receipt. The existing signature-count and packed-transaction byte limits also
apply. K1, R1, and WebAuthn signature billing retains its existing behavior.

The pinned RustCrypto library reports no independent audit. The interoperability,
malformed-input, activation, CPU, block-verification, and restart tests establish
the behavior exercised by this change; a production cryptographic review and
reference-hardware calibration remain release requirements.
