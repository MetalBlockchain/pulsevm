#!/usr/bin/env bash
# Local UI stack smoke test: chain, XMD state, Hyperion, explorer, frontend.
# Run from the pulsevm repo root after `docker compose --env-file .env.localnet up -d`.
set -uo pipefail

RPC="${PULSEVM_RPC_URL:-http://127.0.0.1:19650/ext/bc/pulse}"
EXPLORER="${EXPLORER_URL:-http://127.0.0.1:18000}"
HYPERION="${HYPERION_URL:-http://127.0.0.1:17000}"
FRONTEND="${FRONTEND_URL:-http://127.0.0.1:5173}"
fail=0

check() { # name, command...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then
    echo "ok   $name"
  else
    echo "FAIL $name: $out" | head -c 300; echo
    fail=1
  fi
}

check "chain get_info" curl -fsS --max-time 10 "$RPC/v1/chain/get_info" -H 'Content-Type: application/json' --data '{}'
check "sitoula XMD balance" curl -fsS --max-time 10 "$RPC/v1/chain/get_currency_balance" -H 'Content-Type: application/json' --data '{"code":"xmd.token","account":"sitoula","symbol":"XMD"}'
check "sitoula XUSDC balance" curl -fsS --max-time 10 "$RPC/v1/chain/get_currency_balance" -H 'Content-Type: application/json' --data '{"code":"xtokens","account":"sitoula","symbol":"XUSDC"}'
check "treasury tokens table" curl -fsS --max-time 10 "$RPC/v1/chain/get_table_rows" -H 'Content-Type: application/json' --data '{"json":true,"code":"xmd.treasury","scope":"xmd.treasury","table":"tokens","limit":10}'
check "hyperion health" curl -fsS --max-time 10 "$HYPERION/v2/health"
check "hyperion sitoula actions" curl -fsS --max-time 10 "$HYPERION/v2/history/get_actions?account=sitoula&limit=1"
check "explorer home" curl -fsS --max-time 15 -o /dev/null "$EXPLORER/"
check "explorer tx page" curl -fsS --max-time 15 -o /dev/null "$EXPLORER/transaction/ace2801b3c9f337d3c35d90c90ecd4809ebf3167aae2053464e06a65d6e0f959"
check "explorer account page" curl -fsS --max-time 15 -o /dev/null "$EXPLORER/account/sitoula"
if curl -fsS --max-time 5 -o /dev/null "$FRONTEND/mint-n-redeem"; then
  echo "ok   frontend mint page"
else
  echo "WARN frontend not reachable at $FRONTEND (start it with: npm run dev:pulsevm -- --host 127.0.0.1)"
fi

if [[ "$fail" == 0 ]]; then echo "ALL CHECKS PASSED"; else echo "CHECKS FAILED"; exit 1; fi
