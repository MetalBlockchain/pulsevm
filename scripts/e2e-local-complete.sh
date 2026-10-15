#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RPC_URL="${PULSEVM_RPC_URL:-http://127.0.0.1:9650/ext/bc/pulse}"

node --input-type=module - "$RPC_URL" <<'NODE'
const rpcUrl = process.argv.at(-1)
const endpoint = new URL(rpcUrl)
if (!['127.0.0.1', 'localhost', '::1'].includes(endpoint.hostname)) {
  throw new Error('Refusing to run the local E2E setup against a non-loopback RPC')
}
const response = await fetch(`${rpcUrl.replace(/\/$/, '')}/v1/chain/get_info`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: '{}',
})
if (!response.ok) throw new Error(`Local PulseVM RPC is unavailable: HTTP ${response.status}`)
const info = await response.json()
if (!info.chain_id) throw new Error('RPC returned no chain_id; start the local PulseVM chain first')
console.log(`Connected to local PulseVM chain ${info.chain_id}`)
NODE

PULSEVM_RPC_URL="$RPC_URL" node "$REPO/scripts/setup-webauth-e2e.mjs" --roundtrip
