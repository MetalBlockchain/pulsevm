# Metal Dollar on a local PulseVM chain

This guide runs the Metal Dollar treasury UI and signed mint/redeem flow against
a disposable PulseVM localnet. It uses the repository's Docker Compose stack,
deploys pinned contract artifacts onto that local chain, and keeps transactions
on loopback. Artifact downloads are read-only requests to the public Proton RPC.

## Requirements

- Docker Engine and Docker Compose 2.17 or newer.
- The localnet source checkouts described in [the Docker localnet guide](./docker-localnet.md).
- Node.js 18 or newer.
- A checked-out Metal Dollar frontend with `@proton/js` installed.
- A local test WebAuth signing key and the producer key matching the configured
  local genesis.

## Start the local chain and provision the fixture

From the PulseVM repository root, create a private local settings file and add
the two test keys. Keep `.env.localnet` private; Git ignores it.

```sh
cp .env.localnet.example .env.localnet
# Edit .env.localnet and set PULSEVM_PRODUCER_KEY and WEBAUTH_PKEY.
docker compose --env-file .env.localnet up --build -d
```

Then install/provision the fixture and run a signed XUSDC-to-XMD mint followed
by an XMD-to-XUSDC redeem:

```sh
bash scripts/e2e-local-complete.sh
```

The script uses `http://127.0.0.1:9650/ext/bc/pulse` by default. Set
`PULSEVM_RPC_URL` if you changed the localnet HTTP port. It refuses non-loopback
URLs. The setup checks pinned contract hashes before deployment and uses the
keys from the environment or `.env.localnet`.

For provisioning without the round trip, run:

```sh
node scripts/setup-webauth-e2e.mjs
```

For a collateral-transfer check that skips XMD minting, run:

```sh
node scripts/e2e-test-collateral-only.mjs
```

## Run the frontend

The setup output includes the local chain ID and contract account names. From
the Metal Dollar frontend checkout, run:

```sh
VITE_CHAIN=pulsevm-test \
VITE_PULSEVM_TEST_RPC_URL=http://127.0.0.1:9650/ext/bc/pulse \
VITE_PULSEVM_TEST_CHAIN_ID=<chain-id-from-setup> \
VITE_PULSEVM_TREASURY_ADDRESS=xmd.treasury \
VITE_PULSEVM_TOKEN_ADDRESS=xmd.token \
npm run dev:pulsevm -- --host 127.0.0.1
```

Open the local frontend, connect the `sitoula` test account, and visit
`/mint-n-redeem`. PulseVM serves the Antelope-compatible RPC paths and local
browser CORS headers used by the UI. The programmatic round trip verifies local
contract and balance changes; it does not establish that the official WebAuth
app accepts a custom local chain ID for mobile signing.

## Reset or stop

Stop the stack while retaining its saved local state with
`docker compose down`. To discard the local chain and its indexed history, use
`docker compose down --volumes`; this deletes the Compose project's localnet
volumes. See [the localnet guide](./docker-localnet.md) for restart and recovery
details.
