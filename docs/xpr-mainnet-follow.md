# XPR Mainnet follow deployment

This runbook describes the EC2 explorer’s local XPR Mainnet data path. PulseVM
validates and applies canonical signed blocks continuously. Leap supplies the
mainnet P2P connection and appends blocks to its local block log; Hyperion
indexes PulseVM’s local SHiP stream. This is an operational adapter, not native
PulseVM P2P peering.

## Recovery status (2026-10-09)

The explorer frontend is back on PulseVM. The nodeos-compatible Leap service is
stopped because the available chainbase state has no fork database and the
archive state is x86_64, while this host's Leap build is ARM. A temporary public
API frontend fallback was reverted.

`pulsevm-xpr-api-block-feed.service` now fetches signed blocks from public XPR
chain APIs and appends canonical block-log records to
`/data/xpr-mainnet-follow-recovery/node/blocks`. It checks continuity and
reconstructed block IDs before append. PulseVM independently validates and
applies those blocks. On Oct 9, the replay reader also needed a race fix: a
newly appended log record can become visible just before its index entry. The
reader now parses the last indexed block's own boundary, so an unindexed record
cannot be mistaken for its trailer. PulseVM resumed from durable block
402,150,000 and is replaying forward; the feed is enabled and follows the
irreversible height. Monitor `pulsevm.getInfo` and the replay log for progress.

## Data path

```text
Public XPR chain APIs
       │ signed block responses; ID/continuity checked
       ▼
PulseVM block-log feeder (local Leap v3 log format)
       │ PulseVM independently validates blocks
       ▼
PulseVM replay (signature authentication, block verification, apply)
       ├── JSON-RPC :9660 ──► Bloks frontend
       └── SHiP :9091 ──► Hyperion ──► Elasticsearch
                                  └──► explorer API :7000
```

The explorer’s static files are served from `/var/www/bloks-frontend/current`.
The compiled frontend uses PulseVM JSON-RPC for chain status and block headers,
and Hyperion for transaction traces and history. Caddy routes `/pulsevm-rpc`
and `/rpc/*` to PulseVM, while `/v1/chain/*` still targets the stopped Leap
compatibility service. The PulseVM frontend adapter falls back to PulseVM block
headers and receipts when Leap is unavailable; full transaction payloads
require the Leap compatibility API. Caddy sets `Content-Type:
application/json` on the PulseVM RPC and Hyperion proxies because the compiled
frontend omits it on POSTs. The local frontend adapter unwraps JSON-RPC
`result` values and maps the PulseVM producer response to the array shape the
producer table expects. The producer table also needs display fields
(`num_votes`, vote percentage, rewards, and producer metadata) that are absent
from raw chain table rows, so the frontend routes that presentation-only
request through Bloks' existing Proton Feathers service. The same adapter uses
that service for XPR price, market cap, and forex data. Use
[`enable-local-pulsevm-frontend.sh`](../scripts/enable-local-pulsevm-frontend.sh)
to publish the adapter. Do not use the custom MetalGo network (network ID
1337) as the XPR data source.

PulseVM's `SignedBlock` stores transaction receipts, not the full `trx`
objects, so its `getBlock` result alone cannot populate the Bloks block and
transaction views. Leap's matching block log retains the complete transaction
payloads. [`fix-pulsevm-block-ui.sh`](../scripts/fix-pulsevm-block-ui.sh)
prefers the local Leap API, enables Hyperion history lookup, and falls back to
PulseVM block headers and receipts if Leap is unavailable. In fallback mode
the block page shows CPU and NET usage with “Receipt only” rows; transaction
IDs and action details require Leap's full block data. The transaction page
uses Hyperion traces when the transaction ID is available.

## EC2 services and paths

- `xpr-mainnet-catchup-amd64` is the persistent Leap 5.0.3 container. It uses
  the clean provider state and block log under
  `/data/xpr-mainnet-follow-recovery/node`, then follows XPR P2P. It runs with
  `--wasm-runtime=eos-vm-jit --eos-vm-oc-enable=all`: JIT alone still trapped
  on a delayed `xprconf::register` execution, while OC tier-up for all contracts
  passed the canonical block. Its pinned catch-up target is in
  `/data/xpr-mainnet-follow-download/catchup-target.json`.
- The old `/data/xpr-mainnet-current-node/blocks` log is preserved at block
  401,802,825, matching the existing Arena and Hyperion checkpoint. It is a
  historical corpus; the new node root has a copy-on-write clone that Leap is
  appending to. The full provider block archive download was stopped after the
  state/log pair initialized successfully. Its partial file remains at
  `/data/xpr-mainnet-follow-download/blocks.tar.gz` as a fallback. The
  `pulsevm-xpr-mainnet-catchup-resume.service` unit is installed but disabled.
- `pulsevm-xpr-replay.service` follows
  `/data/xpr-mainnet-follow-recovery/node/blocks` and resumes from
  `/data/xpr-hyperion/arena`. It is configured with `XPR_REPLAY_FOLLOW=1`, a
  10,000-block durability checkpoint, local JSON-RPC/SHiP listeners, and a
  300,000-block Hyperion lag ceiling. Logs are in
  `/data/xpr-hyperion/replay.log`.
- `pulsevm-xpr-api-block-feed.service` appends blocks from public XPR chain
  APIs to the same Leap v3 block log. It is an input adapter only: PulseVM does
  signature, transaction, and state validation before advancing its head.
  Logs are in `/data/xpr-hyperion/api-block-feed.log`.
- Hyperion reads `/data/xpr-hyperion/hyperion/config.toml`, resumes from its
  Elasticsearch checkpoint, and uses the existing `xpr-full-replay` indexes.
  Delta reads and writes go through the `xpr-full-replay-delta-rw` rollover
  alias; the old single-shard delta index is at Elasticsearch’s document cap.
- `pulsevm-xpr-replay-monitor.service` writes the durable index watermark to
  `/data/xpr-hyperion/indexed-height`. PulseVM throttles its SHiP history
  pruning and follow rate against this watermark.

The reusable append-only block-log follow mode is in
[`xpr_blocklog_replay.rs`](../crates/pulsevm_core/examples/xpr_blocklog_replay.rs)
and can be launched with `XPR_REPLAY_FOLLOW=1` through
[`run-xpr-full-replay.sh`](../scripts/run-xpr-full-replay.sh). Set
`XPR_REPLAY_PRODUCER_KEY` to a local key because NodeConfig requires a producer
key; replay never uses it to sign or produce blocks.

## Operational checks

```sh
sudo docker inspect -f '{{.State.Status}}' xpr-mainnet-catchup-amd64
sudo systemctl status pulsevm-xpr-replay.service --no-pager
sudo systemctl status pulsevm-xpr-replay-monitor.service --no-pager
sudo docker ps --format '{{.Names}} {{.Status}}'
curl -s http://127.0.0.1:9660 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}'
cat /data/xpr-hyperion/indexed-height
```

Check `chain_id` in the PulseVM response against the canonical XPR Mainnet ID
`384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0`. Confirm
PulseVM’s `head_block_num` advances, Hyperion’s indexed watermark follows it,
and their lag remains below 300,000 blocks.

The current setup reuses the matching existing block log with a reflink clone,
so Leap can immediately validate the restored state and follow peers without
extracting the full archive. The original block log and existing Arena remain
untouched. To rebuild through the slower full-archive path, re-enable the
resume unit and let its download/extraction and pinned-block check finish.
Then start the follower and Hyperion indexer:

```sh
XPR_CORPUS_NODE_ROOT=/data/xpr-mainnet-follow-recovery/node \
XPR_CONFIG_DIR=/data/xpr-mainnet-follow-config \
XPR_WASM_RUNTIME=eos-vm-jit \
XPR_EOS_VM_OC_ENABLE=all \
  scripts/run-xpr-mainnet-catchup-amd64.sh start
sudo systemctl start pulsevm-xpr-replay.service
sudo docker start pulsevm-xpr-full-history-indexer-1
```

The EC2 frontend is currently configured for PulseVM. The public tunnel and
`/pulsevm-rpc` route have been verified against PulseVM's canonical chain ID.
The follower must continue replaying toward the current irreversible height;
if block validation fails, stop the feed and follower and inspect the reported
block before changing the Arena or Elasticsearch state.
