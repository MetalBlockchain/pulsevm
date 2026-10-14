#!/usr/bin/env bash
set -euo pipefail

[[ -f /localnet/ready ]]
curl --fail --silent --max-time 5 http://127.0.0.1:8081/v1/control/status \
  -H 'Content-Type: application/json' --data '{}' \
  | jq -e '.clusterInfo.healthy and .clusterInfo.customChainsHealthy' >/dev/null
curl --fail --silent --max-time 3 http://127.0.0.1:9650/ext/bc/pulse/rpc \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}' \
  | jq -e '.result.chain_id | type == "string" and length == 64' >/dev/null
