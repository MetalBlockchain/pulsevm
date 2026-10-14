# Docker local cluster and explorer

The root [`compose.yaml`](../compose.yaml) runs a Metal Network Runner server,
five MetalGo validators with the current PulseVM source, Elasticsearch, the
Hyperion Rust indexer/API, and the Bloks Vue explorer. MetalGo is pinned to
`v1.14.2-tahoe` (rpcchainvm protocol 45), matching CI. Network Runner is pinned
to `869d8a0cd62dac3a0fd1c503a36bdd6dfabda025`.

## Prerequisites

- Docker Engine with BuildKit and Docker Compose **2.17 or newer** (named
  additional build contexts are required).
- Linux AMD64 or ARM64, or a Linux Docker VM on macOS/Windows. Allocate enough
  resources for five validators and LLVM compilation: 16 GiB RAM is a useful
  starting point, with at least 20 GiB free disk for images and local data.
- A `hyperion-rs` source checkout with PulseVM support and a `bloks-frontend`
  source checkout with `apps/frontend` and `JsonRpcPulseVM` support. The default
  layout is:

  ```text
  workspace/
    pulsevm/          # this repository
    hyperion-rs/      # https://github.com/MetalBlockchain/hyperion-rs
    bloks-frontend/   # your XPRNetwork/bloks-frontend checkout
  ```

Hyperion revision `c88028187fa9926f400d419fb9d5d46bc71f624b` and Bloks revision
`875b6f18bf0fbcad9c638e12ebcecd7db49ce233` are the source interfaces used by this
stack. Builds respect Cargo and pnpm lockfiles. Set `HYPERION_SOURCE_DIR` and
`BLOKS_SOURCE_DIR` for another layout; paths can be absolute. You must have
access to the Bloks sources. The stack does not download a private checkout.
The source checkouts are read-only build inputs; their configs are not edited.

Elasticsearch may require a higher Linux host/VM `vm.max_map_count`. If its
bootstrap logs report that the value is too low, set it on the Docker host:

```sh
sudo sysctl -w vm.max_map_count=262144
```

## Start with a supplied genesis

From the PulseVM repository root:

```sh
GENESIS_FILE=/absolute/path/to/genesis.json docker compose up --build -d
docker compose ps
docker compose logs -f network-runner hyperion-indexer
```

Without `GENESIS_FILE`, the stack uses the repository's `genesis.json` and its
existing public development producer key. For a different initial key or
system account, copy the example settings file, edit it, and use it explicitly:

```sh
cp .env.localnet.example .env.localnet
# Set GENESIS_FILE and PULSEVM_PRODUCER_KEY (matching genesis.initial_key).
docker compose --env-file .env.localnet up --build -d
```

Use the same `--env-file` on subsequent Compose commands. `NODE_COUNT` supports
2 through 10 nodes; default 5. `PULSEVM_DB_SIZE` is a per-node database capacity
and defaults to 512 MiB for a small local chain. Increase it before creating a
larger chain. All validators use one development producer identity, matching
the existing local harness. These keys and settings are for local testing.

The first build compiles PulseVM, Network Runner, Hyperion, and Bloks and can
take several minutes. Build caches accelerate subsequent runs. BuildKit also
needs network access to package registries and the pinned MetalGo release.

## Endpoints

All published ports bind to `127.0.0.1` by default. Elasticsearch is available
only inside the Compose network.

| Service | Default URL |
| --- | --- |
| Bloks explorer | `http://localhost:8000` |
| PulseVM JSON-RPC through the explorer | `http://localhost:8000/rpc` |
| Hyperion API through the explorer | `http://localhost:8000/v2/health` |
| Hyperion API directly | `http://localhost:7000/v2/health` |
| MetalGo node 1 PulseVM JSON-RPC | `http://localhost:9650/ext/bc/pulse/rpc` |
| SHiP directly / through explorer | `ws://localhost:9090` / `ws://localhost:8000/ship` |
| Runner HTTP control API | `http://localhost:8081` |
| Runner gRPC control API | `localhost:8080` |

Change host ports using `.env.localnet.example`; internal URLs remain fixed.
The runner assigns deterministic node HTTP ports (9650, 9652, ...). Its
`pulse` blockchain alias avoids manually copying a newly generated MetalGo
blockchain ID into Hyperion or Nginx. The explorer receives the actual
Antelope chain ID from `pulsevm.getInfo` at startup, uses PulseVM JSON-RPC,
and sends history requests to the local Hyperion instance. Browser API
requests share the explorer's origin, avoiding CORS and Docker hostname issues.

The first VM process to bind port 9090 supplies SHiP. Other validators use
PulseVM's supported ephemeral-port fallback; `WS_BIND` is deliberately unset.
Hyperion indexes block headers, traces, and deltas from this local chain.

```sh
curl -fsS http://localhost:8000/rpc \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}'
curl -fsS http://localhost:8000/v2/health
curl -fsS http://localhost:8081/v1/control/status \
  -H 'Content-Type: application/json' --data '{}'
```

PulseVM requests blocks when transactions are available; an idle local network
need not advance continuously. A fresh genesis does not deploy token contracts
or populate XPR tables. `CORE_SYMBOL`/`CORE_PRECISION` change explorer labels
only. Bloks features requiring third-party price, NFT, voting, or identity
services are not supplied by this stack. PulseVM block responses contain
receipts rather than full transaction objects; use Hyperion for indexed action
and transaction details.

## Stop, restart, and reset

```sh
docker compose down
docker compose up -d
```

On a clean stop, the runner stops its nodes and saves a named snapshot in the
`network-data` volume. The next start restores that snapshot, preserving the
MetalGo blockchain ID and chain state; Elasticsearch also keeps its indexes.
Allow the three-minute shutdown grace period to finish. A settings fingerprint
prevents reusing the existing data with a changed genesis, node count, producer
configuration, or database capacity.

If shutdown was interrupted or snapshot creation failed, startup refuses to
silently roll back to an older snapshot. The `session-active` recovery marker
and node data remain in the network volume. Inspect the logs and recover that
data before clearing the marker; do not clear it merely to bypass the check.

To deliberately discard the local chain, generated configuration, and indexed
history together:

```sh
# Destructive: deletes this Compose project's localnet volumes.
docker compose down --volumes
GENESIS_FILE=/absolute/path/to/new-genesis.json docker compose up --build -d
```

For independent clusters, use separate Compose project names (`-p`) and host
ports so each cluster has its own data volumes. Keep the chain and Hyperion
volumes paired; replacing one without the other can leave stale indexed history.

This deployment adds no protocol behavior or activation changes. Every
validator runs the same built PulseVM binary and the supplied genesis.
