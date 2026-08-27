# Cross-chain messaging (Avalanche ICM / warp)

PulseVM implements cross-chain messaging the Avalanche-native way: **Avalanche
Interchain Messaging (ICM)**, historically called **Avalanche Warp Messaging
(AWM)**. A source chain emits a message, the validators of its subnet sign it
with their BLS keys, a relayer aggregates enough signatures by stake, and the
destination chain verifies the aggregate against the source subnet's validator
set before handing the payload to a contract.

This document describes the on-VM implementation and the boundary to MetalGo.
Where a wire format is described, **it mirrors AvalancheGo byte-for-byte** so
PulseVM interoperates with MetalGo validators and existing ICM relayers — the
code is authoritative; a divergence from AvalancheGo is a bug.

---

## 1. Where the pieces live

| Concern | Location |
|---|---|
| BLS12-381 signatures (min-pk, blst) | `pulsevm_crypto::bls` |
| Wire codec (big-endian, versioned) | `pulsevm_core::chain::warp::codec` |
| Payloads (`AddressedCall`, `Hash`) | `…::warp::payload` |
| Envelopes (`UnsignedMessage`, `Message`, `BitSetSignature`) | `…::warp::message` |
| Canonical validator set + signer bitset | `…::warp::validator` |
| Weighted-quorum aggregate verification | `…::warp::verify` |
| Signer boundary (`WarpSigner`, `LocalBlsSigner`) | `…::warp::signer` |
| Validator-set boundary (`ValidatorSetSource`) | `…::warp::validator_source` |
| VM entry point (`WarpManager`) | `…::warp::manager` |
| WASM host functions | `…::webassembly::warp` |
| Controller wiring | `Controller::configure_warp` |

---

## 2. Cryptography

ICM uses BLS12-381 in the **min-pk** arrangement: public keys are G1 points
(48-byte compressed), signatures are G2 points (96-byte compressed). PulseVM
wraps `blst` — the same library AvalancheGo uses — so the curve arithmetic is
identical, not merely equivalent.

Two domain separation tags are pinned, taken verbatim from AvalancheGo
`utils/crypto/bls`:

- message signing — `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`
- proof of possession — `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`

> **Consensus-critical.** The DSTs, the 48/96/32-byte lengths, and the
> compressed encodings must match MetalGo exactly. Changing any of them silently
> breaks verification of every message signed by a real validator.

Signatures over the **same** message aggregate: the verifier combines the
signers' public keys into one, combines their signatures into one, and checks a
single pairing. That is exactly the ICM verification path.

## 3. Wire format

The codec is AvalancheGo's, **not** PulseVM's little-endian EOS codec: big-endian
integers, a leading `uint16` version (0), fixed-size arrays written raw, and
variable `[]byte` fields length-prefixed with a `uint32`. Interface values (the
signature, the payload) carry a `uint32` type id.

```
UnsignedMessage = version(2) ‖ network_id(4) ‖ source_chain_id(32)
                  ‖ len(payload)(4) ‖ payload
id              = sha256(UnsignedMessage bytes)

Message         = version(2) ‖ network_id(4) ‖ source_chain_id(32)
                  ‖ len(payload)(4) ‖ payload
                  ‖ sig_type_id(4)=0        (BitSetSignature)
                  ‖ len(signers)(4) ‖ signers ‖ signature(96)

AddressedCall   = version(2) ‖ type_id(4)=1
                  ‖ len(source_address)(4) ‖ source_address
                  ‖ len(payload)(4) ‖ payload
```

`signers` is a big-endian bit set (AvalancheGo `set.Bits`): bit *i* set means the
validator at canonical index *i* contributed. Validators are ordered
**ascending by 48-byte compressed public key**, with equal-key validators merged
and their weights summed. Signer and verifier must derive the identical order or
the bit set names different validators on each side.

## 4. Verification

`verify::verify_message` checks, in order:

1. the source subnet's validator set is non-empty;
2. the signer bit set references only in-range validators;
3. the signers' combined stake meets the quorum —
   `signed_weight × quorum_den ≥ total_weight × quorum_num`, evaluated in `u128`
   (default quorum 67 %, matching AvalancheGo);
4. the aggregate signature verifies against the aggregate public key over the
   unsigned message bytes.

Both the weight check and the signature check are required: sufficient stake with
a bad signature is rejected, and a valid signature from too little stake is
rejected.

## 5. Host functions

Two intrinsics, mirroring AvalancheGo's Warp precompile:

- `pulse_send_warp_message(payload, payload_len, id)` — the calling contract
  emits a message. The VM wraps `payload` in an `AddressedCall` whose
  `source_address` is the **calling contract account** (8-byte little-endian
  name), stamps it with this chain's `network_id` and blockchain id, records the
  unsigned message for signing/relay, and writes the 32-byte id back.
- `pulse_verify_warp_message(message, message_len, out, out_len) -> i32` —
  verifies a signed inbound message. Returns `-1` on any failure (malformed, bad
  signature, insufficient weight, unknown source chain, wrong network); otherwise
  returns the length of, and writes, an authenticated record
  `id(32) ‖ source_chain_id(32) ‖ len(source_address)(4) ‖ source_address ‖ payload`.

**Verification is stateless.** Replay protection is the contract's job, keyed on
the returned message id — the same division of responsibility as AvalancheGo,
where the precompile authenticates and the application dedups. Emitted messages
accumulate on the apply context (`ApplyContext::emit_warp_message`) and are
drained after execution, analogous to action return values.

Costs (`webassembly::cost::warp_send`, `warp_verify`) are **provisional** — hand
-scaled above `RECOVER_KEY` because a BLS pairing is heavier than a secp256k1
recovery, pending measurement per `intrinsic-cost-model.md`. Like every intrinsic
cost they are consensus state once contracts depend on them.

## 6. The MetalGo boundary

Two boundaries are modeled as traits so the messaging logic is independent of
where trust comes from:

- **`WarpSigner`** — produces the local validator's signature over an unsigned
  message. `LocalBlsSigner` signs in-process with a real key (local/dev, or
  wherever MetalGo exposes the key). In production rpcchainvm the key stays inside
  MetalGo — PulseVM receives only the *public* key at `Initialize` (`vm.proto`
  `public_key`) — and signing happens over gRPC against MetalGo's warp signer;
  that transport implements the same trait.
- **`ValidatorSetSource`** — supplies a source subnet's canonical validator set
  for inbound verification. `StaticValidatorSource` serves tests and single-subnet
  local clusters. In production it is backed by MetalGo's validator-state service
  (resolve blockchain id → subnet, fetch `{nodeID → weight, BLS key}` at a
  P-chain height).

`Controller::configure_warp` binds this chain's `network_id` (from the init
request) and blockchain id to a `WarpManager`, which the `WasmRuntime` carries
into every `WasmContext`. It is called during VM `initialize`.

## 7. Status and open work

Implemented and unit-tested on the VM side (BLS, codec, verification, host
functions, controller wiring). What remains for a fully live production path:

1. **MetalGo warp signer gRPC client** — so a validator that does not hold its key
   in-process can have outbound messages signed. Requires MetalGo's signer proto.
2. **MetalGo validator-state gRPC client** behind `ValidatorSetSource` — so
   inbound verification resolves real source-subnet validator sets at a P-chain
   height rather than a static map. Until wired, `verify` returns
   *unknown source chain* for any real chain.
3. **Accepted-block signing hook** — sign emitted messages once their block is
   accepted (the AvalancheGo model) and expose them for a relayer to fetch by id.
4. **Cost calibration** — replace the provisional `warp_send` / `warp_verify`
   prices with measured values.

Items 1–2 depend on proto definitions from MetalGo (`metalgo`) that are not
vendored in this repository; they are the reason this feature is marked
"MetalGo gRPC boundary pending" in the docs index.

## 8. Open questions

1. Should `source_address` be the raw 8-byte account name, or an ABI-stable
   address type shared with any future EVM-compatible sibling chains? The current
   choice keeps it a bare name; a wider address type would need a versioned
   `AddressedCall` payload.
2. Should replay protection get a consensus-level helper (a persisted consumed-id
   set) rather than leaving every contract to implement its own, given how easy it
   is to get wrong?
