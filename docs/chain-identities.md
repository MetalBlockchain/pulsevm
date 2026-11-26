# Chain identities

PulseVM runs inside MetalGo, so it handles two IDs with different owners and
uses:

| ID | Source | Use |
|---|---|---|
| Platform blockchain ID | `InitializeRequest.chain_id` from MetalGo | Names the blockchain to the host and is exposed as `get_info.platform_chain_id`. |
| Transaction-signing ID | The host-provided ID in current releases | Used for transaction signature recovery and exposed as `get_info.chain_id`. |
| Genesis-derived Antelope ID | `sha256(fc::raw::pack(genesis_state))` | Written into the Antelope `global_property` state-history record. |

The transaction-signing and platform IDs are the same in the current release.
The genesis-derived ID is computed independently and can differ from them. A
difference is not proof that the genesis is corrupt and must not prevent node
startup. The initializer logs both values at info level when they differ.

The warning historically used the generic phrase “configured chain id,” which
made the comparison look like a failed consistency check. Do not change it to a
fatal error without first changing the identity model and transaction-signing
compatibility for deployed chains. When diagnosing a deployment, compare the
MetalGo blockchain ID with the Antelope genesis hash as separate values.

This behavior is consensus-relevant: transaction signatures are recovered
against the transaction-signing ID, while state history records the
genesis-derived ID. If either value's role or source changes, test replay and
signature validation across nodes running the supported release mix.
