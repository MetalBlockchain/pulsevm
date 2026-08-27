# Protocol features

Protocol features are PulseVM's mechanism for changing consensus rules without
making activation depend on when a node installs a binary. The model assigns
each gated consensus-breaking behavior a name and a first protocol version. For
each block, the chain's upgrade schedule selects a protocol version from the
block height, and that version selects the enabled features.

The invariant is simple:

> Honest nodes using the same schedule select the same active version at a
> height. Nodes that implement that version must apply the same rules; binaries
> that do not support it must stop processing blocks at that height.

Protocol features are therefore deterministic consensus switches. Temporary
Cargo features can keep unfinished implementations out of stable binaries, but
those build flags never activate chain behavior. Protocol features are not
runtime experiments, contract-controlled activations, or a replacement for
deploying code that implements the new rules.

> **Current status:** the genesis, minimum-supported, and maximum-supported
> protocol versions are all `1`. Both normal and `nightly` builds therefore
> report maximum version `1`; `nightly` does not aggregate any unfinished
> `protocol_feature_*` flag yet. `Baseline` is the only feature, and no
> post-genesis behavior is gated. Schedule parsing, height selection,
> fail-closed support checks, and RPC observability are wired, but the feature
> helper has no production call site yet. A schedule that activates version `2`
> or later makes the current binary refuse transaction admission, block
> building, verification, replay, and state-sync application at that height.
> Do not schedule version `2` until a
> released binary reports support for it.

The code is authoritative. Start with
[`protocol_features.rs`](../crates/pulsevm_core/src/chain/protocol_features.rs)
when this document and the implementation disagree.

**Quick navigation:** operators should start with the
[schedule schema](#4-the-upgrade_bytes-schema),
[schedule lifecycle](#5-where-the-schedule-lives),
[failure behavior](#6-failure-behavior), [RPC fields](#7-observability-with-getinfo),
[rollout runbook](#8-operator-rollout-runbook), and
[incident rules](#11-incident-and-rollback-rules). Developers should read
[rule classification](#2-what-requires-a-protocol-feature),
[height selection](#3-how-a-block-selects-its-version),
[feature implementation](#9-adding-a-protocol-feature), and the
[test checklist](#10-test-and-release-checklist). The lifecycle and retirement
policy is in [section 9](#9-adding-a-protocol-feature).

## 1. Version vocabulary

Several unrelated values contain the word "version." Mixing them up can turn a
safe rollout into a chain halt.

| Term | Meaning |
|---|---|
| `PLUGIN_VERSION` | Compatibility version for the rpcchainvm connection between MetalGo and the PulseVM process. It does not select chain rules. |
| `GENESIS_PROTOCOL_VERSION` | Protocol version used before the first scheduled upgrade. It is currently `1`. |
| `MIN_SUPPORTED_PROTOCOL_VERSION` | Oldest chain protocol this binary can execute. It is currently `1`. |
| `STABLE_PROTOCOL_VERSION` | Newest version compiled into a normal production build. It is currently `1`. |
| `NIGHTLY_PROTOCOL_VERSION` | Newest version compiled when the aggregate `nightly` Cargo feature is enabled. It is currently `1`. |
| `PROTOCOL_VERSION` | Newest version this particular binary can execute: stable maximum normally, nightly maximum in a `nightly` build. It is not the version active at the current head. |
| `protocol_feature_*` Cargo feature | Temporary compile-time gate that includes one unfinished implementation. It does not activate the implementation. |
| `nightly` Cargo feature | Aggregate compile-time gate for all unfinished protocol implementations. It is unrelated to the Rust nightly toolchain. |
| Active protocol version | Version selected by the upgrade schedule for one particular block height. |
| `ProtocolFeature` | A named behavior enabled from a fixed protocol version onward. |
| `getInfo.protocol_version` | Active version at the last accepted block. |
| `getInfo.supported_protocol_version` | This binary's `PROTOCOL_VERSION`, meaning its maximum supported version. |
| `getInfo.protocol_upgrade_schedule_hash` | Canonical semantic hash of the complete loaded schedule, including future entries. |
| `getInfo.next_protocol_upgrade` | First scheduled transition after the accepted head, or `null`. |

Installing a binary with a larger `PROTOCOL_VERSION` does not activate its new
rules. Loading a schedule does not teach an old binary those rules. A successful
upgrade needs both pieces:

1. every consensus-participating node runs code that supports the target
   version; and
2. every participating node, plus any node expected to verify or state-sync at
   or after activation, loads the same schedule.

### 1.1 Two independent gates

PulseVM follows nearcore's separation between build availability and chain
activation:

| Gate | Evaluated | Controls | Must not control |
|---|---|---|---|
| Cargo `#[cfg(feature = "protocol_feature_...")]` | At compilation | Whether unfinished implementation code exists in the binary | Which rules a block uses |
| `ProtocolExecutionContext::feature_enabled(feature)` | While evaluating a block | Whether compiled legacy or new rules apply at that height | Whether the new code was compiled |

The expected lifecycle for a future version `2` is:

1. A temporary `protocol_feature_*` flag hides the implementation from normal
   builds and is included by `nightly`.
2. A nightly binary compiles the implementation and advertises nightly maximum
   version `2`, but still executes version-1 rules before activation.
3. After review and testing, the implementation is compiled into the normal
   production build and the stable maximum becomes `2`.
4. Operators deploy that stable binary everywhere.
5. Only then does the common height schedule activate version `2`.

This prevents unfinished code from entering stable artifacts while preserving
historical replay in binaries that do contain the new implementation.

## 2. What requires a protocol feature

Use this test:

> Could two nodes running different released binaries receive the same valid
> inputs and disagree about block validity or any consensus-observable output?

If the answer is yes, preserve the old behavior and put the new behavior behind
a named feature. Examples include changes to:

- transaction or block validation;
- state transitions, database ordering, or state-root calculation;
- receipt contents, action digests, block IDs, or other committed bytes;
- CPU, NET, or RAM charging when it affects validity or committed receipts;
- WASM validation, enabled proposals, execution, traps, or host intrinsics;
- cryptography, floating-point behavior, serialization, and canonicalization;
- authorization, producer-schedule validation, and objective failure classes;
- iteration order or any constant that feeds a hash.

A gate is normally unnecessary for RPC-only presentation changes, logs,
metrics, documentation, tooling, or a performance optimization proven to
preserve results, errors, and metering. If that proof is uncertain, treat the
change as consensus-breaking and gate it.

## 3. How a block selects its version

The active version is a pure function of block height and the validated upgrade
schedule:

```text
version(height) = version from the last schedule entry whose
                  activation_height <= height
                  or GENESIS_PROTOCOL_VERSION when no entry applies
```

An activation height is inclusive: it is the first block evaluated under the
new version. With version `2` at height `1,000,000` and version `3` at height
`1,500,000`, selection is:

| Block height | Selected version |
|---:|---:|
| Heights below `1,000,000` | `1` |
| `1,000,000` through `1,499,999` | `2` |
| `1,500,000` and later | `3` |

The relevant height depends on the operation:

| Operation | Height used |
|---|---|
| Build a block | Preferred block height plus one |
| Verify a block | The candidate block's own height |
| Admit a transaction | The next block above the materialized pending tip |
| Execute or replay a block | The block's own height, carried through transaction, action, and WASM contexts |
| Apply a state-sync snapshot | The snapshot block's height |
| Initialize an existing database | The last accepted block's height |
| `pulsevm.getInfo` | The last accepted block's height |

This distinction matters at a boundary. If the accepted head is `999,999` and
version `2` activates at `1,000,000`, `getInfo.protocol_version` still reports
`1`, while the next build and verification of a candidate at height `1,000,000`
already require version `2`.
Activation never depends on wall-clock time, process start time, binary version,
or when a validator first observed the schedule.

Each feature maps to the first version that enables it:

```text
feature is enabled when active_version >= feature.protocol_version()
```

That is the runtime half of the decision. The complete safety condition is:

```text
new rule may run = implementation was compiled
                   AND active_version >= feature.protocol_version()
```

The entry-point support check connects the two halves. A build that excludes an
implementation must advertise a `PROTOCOL_VERSION` below that implementation's
activation version, so it rejects the block before reaching the feature branch.
Build features determine capability only; they never change the active version
selected by the schedule.

Features stay enabled in every later version, and several features may activate
together. The parser permits a schedule to jump from version `1` to version `3`;
because feature checks are monotonic, that jump enables features assigned to
versions `2` and `3` together. Operational schedules should normally use
contiguous versions unless the skipped version is deliberate.

## 4. The `upgrade_bytes` schema

MetalGo supplies the chain's upgrade data in the rpcchainvm
`InitializeRequest.upgrade_bytes` field. PulseVM expects either empty bytes or a
JSON object with this shape:

```json
{
  "protocol_upgrades": [
    {
      "protocol_version": 2,
      "activation_height": 1000000
    },
    {
      "protocol_version": 3,
      "activation_height": 1500000
    }
  ]
}
```

This example explains the schema; it is **not deployable with the current
version-1 binary**. The file may contain a future version before the binary can
execute it, but at activation the unsupported-version behavior in
[section 6](#6-failure-behavior) applies to startup, building, verification, and
state sync.

### 4.1 Validation rules

| Input | Result |
|---|---|
| Empty or ASCII-whitespace-only bytes | Valid empty schedule; version `1` remains active indefinitely |
| `{}` or `{"protocol_upgrades": []}` | Valid empty schedule |
| More than 1,024 entries | Rejected |
| Activation height `0` or `1` | Rejected; block `1` permanently uses the genesis protocol |
| Duplicate, decreasing, or unsorted activation heights | Rejected |
| A first version less than or equal to `1` | Rejected |
| Duplicate, decreasing, or unsorted protocol versions | Rejected |
| An unknown field in the root object or an entry | Rejected |
| A missing required entry field, a negative number, a non-integer, or a value outside `u32` | Rejected by JSON deserialization |
| Strictly increasing versions with gaps | Accepted |
| A future version above this binary's maximum | Accepted before activation; unsupported at and after activation |

Entries must already be in activation order; PulseVM never sorts or repairs a
schedule. Strict parsing is intentional: a typo must stop initialization instead
of silently selecting different rules.

Parsing alone does not know the current chain head. During initialization,
PulseVM compares the schedule prefix active at the accepted head with activation
records already committed in chain state. A first-time retroactive entry,
removal, reordered entry, or changed height/version is rejected.

For example, this schedule is invalid because `activation_heigth` is misspelled:

```json
{
  "protocol_upgrades": [
    {
      "protocol_version": 2,
      "activation_heigth": 1000000
    }
  ]
}
```

## 5. Where the schedule lives

The complete schedule is consensus-critical configuration. Future entries are
supplied out of band; activated history is committed in chain state.

MetalGo reads network upgrade data from
`{chain-config-dir}/{blockchainID}/upgrade.json` (or equivalent in-memory chain
configuration) and passes it to PulseVM as `upgrade_bytes` during VM
initialization. PulseVM validates those bytes and keeps the complete schedule in
memory for that process lifetime. On every restart, it is loaded again from the
new initialization request.

When a candidate reaches an activation height, PulseVM writes a
domain-separated digest of `(protocol_version, activation_height)` to
chainbase's existing `protocol_state_object`. The write happens inside that
block's undo session and before any new rule runs. A rejected block or losing
fork rolls the record back; accepting the block commits it with the rest of
state. The ordered records are included in physical snapshots and state-history
deltas.

At startup, the persisted records must exactly equal the configured schedule
prefix through the accepted head. This makes an activated entry immutable:
removing it, moving it, changing its version, or inserting a retroactive entry
fails initialization. The full future schedule is not placed in block headers
or block IDs, so future changes still require a coordinated configuration
rollout before the earliest affected height.

Pure version-1 state summaries retain the exact legacy wire format. Once a
post-genesis version is active, summaries use a new leading format marker and
carry the active version plus a canonical activated-prefix hash. The leading
marker makes pre-feature binaries reject the summary instead of ignoring an
appended field and importing unsupported state. A current receiver compares the
commitment with its local schedule before downloading or replacing state, and
the physical snapshot carries the chainbase activation records. Legacy
summaries without a commitment are accepted only for pure version-1 history.

Snapshot installation validates the staged arena's revision and activation
records before replacing live state. Immediately before that replacement,
PulseVM durably creates a `state_sync_installing` marker. It then publishes the
arena, re-bases the block log, clears the trace and chain-state logs, and writes
an atomically replaced, checksummed producer-schedule base for the re-based log.
The marker is removed and its directory synced only after every companion file
is installed. A failure after the arena swap is a fatal consistency error: the
VM aborts, and the surviving marker makes every restart fail closed until the
node's data is diagnosed and rebuilt or resynced. A re-based block log above
genesis likewise cannot start without its valid producer-schedule sidecar.

> **Operational invariant:** every validator, verifier, and state-sync node must
> load the same validated schedule on every initialization. Publish one
> canonical file, distribute it to every node, and compare
> `protocol_upgrade_schedule_hash` plus `next_protocol_upgrade` before activation.

PulseVM enforces immutability of every activated entry. The safest operational
policy is also to leave published future entries unchanged and append only new,
strictly later versions. If an unactivated entry must be corrected, handle it as
a coordinated chain-wide configuration migration while the accepted head is
still below the earliest changed height; never edit only a subset of nodes.

There is no transaction or PulseVM RPC method that installs, edits, cancels, or
hot-reloads this schedule. Deployment wiring is controlled by MetalGo and the
network tooling. MetalGo documents the upgrade-file location and restart
requirement under
[Chain Configs](https://docs.metalblockchain.org/nodes/maintain/metalgo-config-flags#chain-configs).
For local networks,
[metal-network-runner](https://github.com/MetalBlockchain/metal-network-runner)
accepts the file through a blockchain specification's `network_upgrade` field.

## 6. Failure behavior

PulseVM rejects malformed schedules and refuses block or state-sync entry points
when the selected version is outside the binary's declared support range.

| Situation | Behavior |
|---|---|
| Upgrade bytes are malformed or fail schedule validation | VM initialization fails |
| A future unsupported version is scheduled but not active | Initialization and block processing continue under the current supported version |
| The configured active prefix differs from chainbase's persisted activation records | Initialization or execution fails; accepted history is never reinterpreted |
| The schedule reaches a version excluded by this binary's Cargo profile | Unsupported-version failure before the new rules execute |
| The last accepted block already requires an unsupported version | Restart/initialization fails |
| The next block to build requires an unsupported version | Block building fails before block execution |
| Transaction admission targets an unsupported next block | Admission fails before mempool insertion or gossip |
| A candidate block requires an unsupported version | Verification fails before transaction execution |
| A state-sync snapshot requires an unsupported version or has a mismatched activated-prefix commitment | The summary is rejected before download or local-state replacement |
| A staged snapshot's arena revision or activation records disagree with its summary | Installation is rejected while the live database remains unchanged |
| Persistence fails after state sync or block acceptance has started publishing consensus state | The VM fail-stops without returning control to MetalGo; it must be recovered or resynced instead of continuing on a potentially split arena/log view |
| Nodes load different future schedules that currently select the same version | Their schedule hashes, and usually their next-upgrade fields, differ before the boundary |

Build, verify, block execution/replay, transaction admission, state sync, and
acceptance all require a support-checked context. Candidate height and version
are carried through transaction, action, and WASM execution instead of being
re-derived from the accepted head.

## 7. Observability with `getInfo`

Query a running node with the repository CLI:

```bash
export METALGO_URI="http://127.0.0.1:9650"
export PULSEVM_BLOCKCHAIN_ID="<blockchain-id>"
export PULSEVM_RPC_URL="${METALGO_URI}/ext/bc/${PULSEVM_BLOCKCHAIN_ID}/rpc"
cargo run -p pulse -- --url "$PULSEVM_RPC_URL" get info
```

The response includes these fields:

```json
{
  "protocol_version": 1,
  "supported_protocol_version": 1,
  "protocol_upgrade_schedule_hash": "e73c3b500964300ce82280695d0608e80d9b50602531b560e9ec33e04e09e914",
  "next_protocol_upgrade": {
    "protocol_version": 2,
    "activation_height": 1000000
  }
}
```

- `protocol_version` is active at the **accepted head**, not necessarily at the
  next block.
- `supported_protocol_version` is the largest version implemented by this
  particular binary. The same source revision can report a different maximum
  when built with the stable or `nightly` Cargo profile.
- `protocol_upgrade_schedule_hash` hashes the validated schedule's canonical
  `(version, height)` representation. Harmless JSON whitespace and key ordering
  do not change it, and future entries are included.
- `next_protocol_upgrade` is the first transition strictly after the accepted
  head; it is `null` when no later transition exists.
- A node must report `supported_protocol_version >= target_version` before it is
  ready for that target's activation. This declared support signal is necessary,
  but it is not proof of complete testing or an identical loaded schedule.

The shared Rust client defaults either version field to `0`, the hash to an
empty string, and the next upgrade to `null` when it talks to an older server.
Those are backward-compatibility sentinels, not proof of readiness.

Compare all four fields across every participating node. The schedule hash
proves what the running PulseVM parsed; retain the original file and artifact
digest in the change record as an independent deployment audit.

The canonical hash is SHA-256 of ASCII `PVMUPG01`, followed by the entry count
as a little-endian `u32`, followed by every validated entry in schedule order as
`protocol_version: u32 LE` and `activation_height: u32 LE`. The example above is
the hash of the two-entry schedule in [section 4](#4-the-upgrade_bytes-schema).

## 8. Operator rollout runbook

For an upgrade targeting protocol version `N` at height `H`:

1. **Release support first.** Build and publish a PulseVM binary whose
   `supported_protocol_version` is at least `N`. Finish replay and architecture
   testing before scheduling activation. Production activation should use the
   normal stable build; never substitute a preview `nightly` artifact unless the
   target network explicitly approved that build profile.
2. **Deploy the binary everywhere with a rolling restart.** Upgrade every
   validator and every node that must verify or state-sync blocks at or after
   `H`. Preserve validator availability, and wait for each restarted node to
   become healthy and catch up before moving to the next one.
3. **Verify binary readiness.** Query each node with `getInfo`. Do not continue
   while any node reports a maximum below `N` or reports `0` because it is too
   old to expose the field.
4. **Publish one schedule artifact.** Record the exact JSON bytes, a SHA-256
   digest, the target network, version `N`, height `H`, binary digest, and Cargo
   build profile/features in the change record.
5. **Install it everywhere with a rolling restart.** For a normal MetalGo
   deployment, put the file at
   `{chain-config-dir}/{blockchainID}/upgrade.json`. For network-runner, set the
   blockchain specification's `network_upgrade` field. Restart nodes in a
   sequence that preserves validator availability; never stop every validator
   at once.
6. **Verify the running schedule.** Query every node again. Require identical
   `protocol_upgrade_schedule_hash` values and require
   `next_protocol_upgrade == {protocol_version: N, activation_height: H}`.
   Retain the installed file digest in the change record as well.
7. **Watch both sides of the boundary.** Confirm block `H - 1` under the old
   rules, then confirm block `H` is built, verified, accepted, and reported as
   version `N`.
8. **Freeze the activated prefix.** Never downgrade to a binary that cannot
   execute `N`, and never remove or rewrite the entry for height `H`.

Because the schedule is only read during initialization, a strict binary-first
rollout normally means two rolling restarts: one to deploy supporting code, then
one to load the canonical schedule. Leave enough time between those phases to
verify every node before activation.

With the code currently in this branch, no post-genesis upgrade can safely
activate: a target must be greater than genesis version `1`, while this binary's
maximum is still `1`. The parser accepts a future entry before activation, but
the supporting binary must be deployed before that height. There is no released
version-2 behavior yet.

## 9. Adding a protocol feature

### 9.1 Add the temporary build gate and permanent mapping

While a feature is unfinished, declare a dedicated Cargo feature in
`pulsevm_core/Cargo.toml` and include it in the complete `nightly` aggregate:

```toml
[features]
nightly = ["protocol_feature_canonical_transaction_ordering"]
protocol_feature_canonical_transaction_ordering = []
```

Hide the unfinished implementation—not the legacy path—behind that feature:

```rust
#[cfg(feature = "protocol_feature_canonical_transaction_ordering")]
fn apply_canonical_ordering() {
    // Version-2 implementation.
}
```

Use `#[cfg(...)]`, not `if cfg!(...)`, when the implementation must be absent
from the compiled artifact. An ordinary `if` still type-checks and compiles both
branches.

Add a descriptive `ProtocolFeature` variant and map it to the first version that
enables it in `ProtocolFeature::protocol_version`:

```rust
pub enum ProtocolFeature {
    Baseline,
    CanonicalTransactionOrdering,
}

impl ProtocolFeature {
    const fn protocol_version(self) -> ProtocolVersion {
        match self {
            Self::Baseline => 1,
            Self::CanonicalTransactionOrdering => 2,
        }
    }
}
```

Several features may deliberately map to the same release version. Once a
mapping ships, never reuse its number or move it to a different version. Retain
the old behavior while the supported-version and history policy requires replay
of pre-activation blocks; removing it requires an explicit minimum-version,
replay, and state-sync migration.

PulseVM assigns preview work its intended eventual protocol version; it does not
use a separate disposable version range. Never put a preview-only version in a
persistent production schedule.

### 9.2 Gate the exact consensus boundary

Select the version from the candidate block height, verify that the binary
supports it, and pass that version down to the code where behavior changes. A
dual-gated boundary follows this schematic pattern:

```rust
let protocol_context = self.ensure_protocol_version_supported(block_height)?;

if protocol_context.feature_enabled(ProtocolFeature::CanonicalTransactionOrdering) {
    #[cfg(feature = "protocol_feature_canonical_transaction_ordering")]
    return apply_canonical_ordering();

    #[cfg(not(feature = "protocol_feature_canonical_transaction_ordering"))]
    return Err(ChainError::BlockError(
        "canonical transaction ordering was not compiled".into(),
    ));
}

apply_legacy_ordering()
```

The support check should make the `not(feature)` error unreachable in normal
operation: a stable build advertises a maximum below the preview feature's
version. Keeping an explicit error makes accidental new call paths fail closed
instead of silently executing legacy behavior at a new-version height.

The old path is not temporary compatibility code. Feature-enabled and later
stable binaries need it whenever they replay or verify a block before
activation.

Avoid these common mistakes:

- Do not check `ProtocolFeature::enabled(PROTOCOL_VERSION)`. That activates a
  rule when the binary is installed instead of at the scheduled height.
- Do not use `cfg!(feature = "protocol_feature_...")` as the runtime decision.
  It describes binary contents, not the rules active for a block.
- Do not branch on the accepted-head version while evaluating a candidate. At a
  boundary, the candidate may already use the next version.
- Do not query a raw schedule version and branch on it. Obtain the
  support-checked `ProtocolExecutionContext` at the entry point and query the
  feature through the transaction, apply, or WASM context carrying that exact
  candidate block.
- When adding a real feature, do not gate only the producer path. Verifiers,
  standalone execution, replay, and state sync must reach the same rule
  selection.
- Do not derive activation from wall-clock time, environment variables, node
  configuration other than the canonical schedule, or contract state.

### 9.3 Promote nightly code to stable support

Only the complete `nightly` aggregate may raise the nightly maximum. Enabling a
single `protocol_feature_*` flag is useful for isolated development, but it must
not raise `PROTOCOL_VERSION`: one protocol version may contain several features,
and a partial build cannot safely claim support for the whole version.

Advance `NIGHTLY_PROTOCOL_VERSION` only after every implementation assigned to
the new version is present in all relevant paths, included by `nightly`, and
covered by semantic boundary tests. A `--features nightly` binary then declares
that it can execute the preview version for testing. This is still not runtime
activation.

Before production activation:

1. make every implementation assigned to the version part of the normal stable
   build, removing its temporary `#[cfg]` gate or otherwise making support
   impossible to disable;
2. delete the stabilized Cargo flag and any manifest forwarders, including its
   entry in the unfinished `nightly` aggregate;
3. advance `STABLE_PROTOCOL_VERSION` and keep
   `NIGHTLY_PROTOCOL_VERSION >= STABLE_PROTOCOL_VERSION`; and
4. build and test both normal and nightly configurations.

Do not rely on a default Cargo feature for stable consensus support:
`--no-default-features` could remove it. Once stable maximum `N` is advertised,
every normal build must contain every rule required through `N`.

Advancing either maximum is a capability declaration. `PROTOCOL_VERSION`
selects the appropriate maximum for the compiled build, while the height
schedule remains the only runtime switch. Protocol versions are cumulative: a
binary advertising version `3` must contain all version-2 and version-3 rules.

Do not change `GENESIS_PROTOCOL_VERSION` for an existing chain. Raise
`MIN_SUPPORTED_PROTOCOL_VERSION` only with an explicit history, replay, and
state-sync compatibility plan; old heights can still require the old rules even
after the live network has advanced.

### 9.4 Deprecate behavior without rewriting history

Protocol features are permanent, cumulative version mappings. There is no
schedule entry that disables an activated feature, and an activated version is
never rolled back by changing the schedule. A feature is therefore deprecated
by introducing a replacement rule in a later protocol version, not by removing
or reinterpreting its original rule.

For a behavior introduced in version `N` and replaced in version `M > N`:

1. retain the version-`N` implementation and its mapping so nodes can replay,
   verify, and state-sync any supported history before `M`;
2. add the replacement as a new `ProtocolFeature` mapped to `M`, with an exact
   candidate-height gate that selects the old behavior below `M` and the new
   behavior at and after `M`;
3. document the old behavior as deprecated, including its final active range
   (`N` through `M - 1`), migration guidance for contracts and operators, and
   whether state created under the old rule needs conversion; and
4. test replay on both sides of `M`, plus state sync and restart from snapshots
   taken before and after `M`.

Removing old code is a separate compatibility migration, not normal feature
deprecation. It is allowed only when the project deliberately raises
`MIN_SUPPORTED_PROTOCOL_VERSION` and documents the retained-history boundary,
archive/replay policy, state-sync compatibility, and recovery path for nodes
below that boundary. Until such a migration lands, every supported binary keeps
the legacy behavior for historical blocks even when no new block can select it.

## 10. Test and release checklist

A real feature is incomplete until its activation boundary and historical
behavior are tested. Cover at least:

- a permanent feature-to-version mapping test, so released mappings cannot be
  renumbered accidentally;
- normal and `nightly` builds reporting the intended maximum version;
- a normal build excluding each unfinished implementation and rejecting its
  activation version;
- a nightly build containing the implementation while retaining legacy behavior
  before activation;
- cross-build replay proving that normal and nightly binaries produce identical
  block IDs, receipts, and state roots before activation, then that the normal
  binary fails closed while the nightly binary applies the new rule at the
  activation height;
- for a replacement/deprecation, replay, restart, and state-sync coverage on
  both sides of the replacement version;
- empty, whitespace-only, and multi-entry schedules;
- unknown fields at both the root and entry level;
- zero, duplicate, decreasing, missing, and out-of-range values;
- the 1,024-entry limit and a valid schedule at the limit;
- version selection at `H - 1`, `H`, and `H + 1`;
- build and verify behavior before and at activation;
- initialization through serialized `upgrade_bytes`, not only a schedule placed
  directly into a controller test;
- restart with the same schedule before and after activation;
- activated-prefix persistence across restart, plus rejection of removed,
  moved, or retroactively inserted entries;
- startup and state-sync rejection when the target height is unsupported;
- state-summary version/hash mismatch rejection before mutation and exclusion
  of verified-but-unaccepted state from produced snapshots;
- `getInfo` values before and after the activation block is accepted;
- byte-for-byte replay of consensus artifacts from all pre-activation history,
  including block IDs, receipts, and state roots; compare diagnostic traces only
  after excluding or normalizing nondeterministic fields such as elapsed
  wall-clock timing; and
- the supported architecture matrix for changes involving WASM, arithmetic,
  serialization, or database ordering.

Useful focused checks for the current implementation are:

```bash
cargo test -p pulsevm_core --lib --no-default-features protocol_features
cargo test -p pulsevm_core --lib --features nightly protocol_features
cargo test -p pulsevm_core --lib \
  unsupported_protocol_version_stops_build_and_verify_at_activation
cargo check -p pulsevm --release --no-default-features
cargo check -p pulsevm --release --features nightly
cargo test --workspace --locked
```

Keep the normal and nightly checks explicit. Do not use `--all-features` as the
only preview check: Cargo features unify across the dependency graph, and in
this workspace that command also enables unrelated instrumentation such as
`arena-shadow`.

## 11. Incident and rollback rules

- **Invalid schedule before startup:** replace it with the agreed canonical
  artifact on every affected node and restart.
- **Schedule mismatch before activation:** stop the rollout, reconcile every
  node to one artifact, and reverify the digests before producing the affected
  height.
- **Unsupported version reached:** deploy a binary that implements the active
  version. Do not make a local node "recover" by deleting or moving the
  activation entry.
- **Fault discovered after activation:** do not downgrade or reinterpret
  accepted blocks under the old rules. If the chain can advance safely, ship a
  corrective feature in a later version. If it has halted, use a coordinated
  network recovery for the next unaccepted height; do not make unilateral
  binary or schedule edits.
- **Fatal consistency error while publishing state:** the VM deliberately aborts
  before MetalGo can resume consensus. An interrupted state-sync publication
  leaves a durable marker that also rejects restart. Preserve the data directory
  and logs for diagnosis, then rebuild that node from known-good state or run a
  fresh state sync; do not delete the marker and repeatedly restart partially
  published state.

Editing an already-active schedule entry is rejected against the chainbase
activation ledger. Treat any such attempt as a chain incident, not a normal
rollback.

## 12. Implementation map

- Protocol constants, feature mappings, schedule parsing, selection, and unit
  tests: [`protocol_features.rs`](../crates/pulsevm_core/src/chain/protocol_features.rs)
- Core stable/nightly Cargo profiles:
  [`pulsevm_core/Cargo.toml`](../crates/pulsevm_core/Cargo.toml)
- VM binary forwarding for the nightly profile:
  [`pulsevm/Cargo.toml`](../crates/pulsevm/Cargo.toml)
- Stable/nightly CI coverage:
  [`test.yml`](../.github/workflows/test.yml)
- Initialization, build/verify gates, state-sync gate, and boundary test:
  [`controller.rs`](../crates/pulsevm_core/src/chain/controller.rs)
- Transactional activation ledger in chainbase:
  [`database.rs`](../crates/pulsevm_ffi/src/database.rs) and
  [`database.cpp`](../crates/pulsevm_ffi/database.cpp)
- State-summary protocol commitment and legacy/versioned wire barrier:
  [`state_sync.rs`](../crates/pulsevm_core/src/chain/state_sync.rs)
- State-sync staged validation, publication marker, re-based logs, and
  checksummed producer-schedule sidecar:
  [`controller.rs`](../crates/pulsevm_core/src/chain/controller.rs)
- Candidate context propagation through transaction, action, and WASM:
  [`transaction_context.rs`](../crates/pulsevm_core/src/chain/transaction_context.rs),
  [`apply_context.rs`](../crates/pulsevm_core/src/chain/apply_context.rs), and
  [`wasm_runtime.rs`](../crates/pulsevm_core/src/chain/wasm_runtime.rs)
- rpcchainvm `upgrade_bytes` handoff:
  [`main.rs`](../crates/pulsevm/src/main.rs)
- `pulsevm.getInfo` population:
  [`service.rs`](../crates/pulsevm/src/chain/service.rs)
- Server response shape:
  [`responses.rs`](../crates/pulsevm/src/api/responses.rs)
- Backward-compatible client response shape:
  [`pulsevm_api_types/src/lib.rs`](../crates/pulsevm_api_types/src/lib.rs)
- Real MetalGo `upgrade_bytes` transport and unsupported `H - 1`/`H`
  boundary regression:
  [`protocol_upgrade_test.go`](../tests/e2e/protocol_upgrade_test.go)
- Multi-node MetalGo E2E build and execution:
  [`e2e.yml`](../.github/workflows/e2e.yml)

The feature-to-version pattern is inspired by
[nearcore's protocol feature model](https://github.com/near/nearcore/blob/53f338792c7eeb0df43a6f37bb55578371bebcba/core/primitives-core/src/version.rs),
but PulseVM's implementation and this repository's tests define PulseVM's
behavior.
