# PulseVM Documentation

Design documentation for PulseVM, a Rust implementation of an EOSIO/Antelope-compatible WebAssembly virtual machine running as a subnet VM on MetalGo.

These documents describe **how PulseVM works and why**, at a level of detail
intended for people modifying or operating the implementation. They are not a
normative specification — where a document and the code disagree, the code is
authoritative and the document is a bug.

---

## Index

| Document | Covers | Status |
|---|---|---|
| [protocol-features.md](./protocol-features.md) | Compile-time feature availability, consensus-version selection, upgrade schedules, safe rollout, and activation testing | Framework implemented; only v1/Baseline |
| [mempool-admission.md](./mempool-admission.md) | Local admission preflight, shared-state concurrency, detached batches, expiry, capacity, and observability | Current behavior |
| [resource-model.md](./resource-model.md) | CPU, NET, and RAM accounting; WASM metering cost function; input vs implicit transaction billing | Draft |
| [intrinsic-cost-model.md](./intrinsic-cost-model.md) | Host-intrinsic CPU pricing, estimator methodology, and calibration | Working reference |
| [wasm-determinism.md](./wasm-determinism.md) | WASM feature pinning, floating-point behavior, database key ordering, and replay validation | Working reference |
| [cross-chain-messaging.md](./cross-chain-messaging.md) | Avalanche Interchain Messaging (ICM / warp): BLS scheme, wire formats, host functions, verification, and the MetalGo signer/validator boundary | VM-side implemented; MetalGo gRPC boundary pending |

---

## Consensus-critical material

Several documents describe behaviour where a change of any kind produces a chain split. Those sections are marked inline. The general rule:

> If two nodes running different released binaries could receive the same valid
> inputs and disagree about block validity or any consensus-observable output,
> the change requires a
> [protocol feature gate](./protocol-features.md).

This applies to — non-exhaustively — the WASM instruction cost table, the SoftFloat build flags, Merkle tree canonicalization, map iteration order in any structure that feeds a hash, and every resource accounting constant.

## Conventions

- One topic per file, kebab-case filename.
- Open questions belong in a numbered section at the end of the document, not scattered inline.
- Known defects belong in the issue tracker with a one-line reference from the document. A defect that lives only in a design doc reads as accepted behaviour six months later.
- Where a document describes a constant or table that exists in code, the code carries a doc comment pointing back at the section:

  ```rust
  /// WASM instruction cost table. See `docs/resource-model.md` §3.2.
  ///
  /// Changing any value here is consensus-breaking and requires a
  /// protocol feature gate plus invalidation of cached modules.
  ```

  This is what keeps the two from drifting.

## Divergence from Antelope

PulseVM aims for Antelope compatibility but is not a transliteration of `nodeos`. Where behaviour differs deliberately, the relevant document says so explicitly and explains the reasoning — see for instance the deterministic op-based CPU metering in [resource-model.md](./resource-model.md) §3.4, which replaces Antelope's wall-clock microsecond billing.

Undocumented divergence is a bug, whether the divergence itself was intended or not.
