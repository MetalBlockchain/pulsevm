#!/usr/bin/env bash
set -euo pipefail

fail() { echo "localnet: $*" >&2; exit 1; }
api() {
  curl --fail-with-body --silent --show-error --max-time "${3:-30}" \
    "http://127.0.0.1:8081/v1/control/$1" \
    -H 'Content-Type: application/json' -H 'Grpc-Timeout: 600S' --data "$2"
}

: "${NODE_COUNT:=5}"
: "${PULSEVM_PRODUCER_NAME:=pulse}"
: "${PULSEVM_SYSTEM_ACCOUNT:=pulse}"
: "${PULSEVM_NATIVE_SYSTEM_CONTRACT:=true}"
: "${PULSEVM_DB_SIZE:=536870912}"
: "${CORE_SYMBOL:=PULSE}"
: "${CORE_PRECISION:=4}"
export PULSEVM_SYSTEM_ACCOUNT

[[ -f /config/genesis.json ]] || fail "supply a genesis JSON file at /config/genesis.json"
jq -e 'type == "object" and (.initial_key | type == "string") and (.initial_timestamp | type == "string")' \
  /config/genesis.json >/dev/null || fail "invalid PulseVM genesis JSON"
[[ "$NODE_COUNT" =~ ^[0-9]+$ ]] && (( NODE_COUNT >= 2 && NODE_COUNT <= 10 )) \
  || fail "NODE_COUNT must be between 2 and 10"
[[ "$PULSEVM_PRODUCER_NAME" =~ ^[a-z1-5.]{1,12}$ ]] || fail "invalid producer account name"
[[ "$PULSEVM_SYSTEM_ACCOUNT" =~ ^[a-z1-5.]{1,12}$ ]] || fail "invalid system account name"
[[ "$PULSEVM_NATIVE_SYSTEM_CONTRACT" == true || "$PULSEVM_NATIVE_SYSTEM_CONTRACT" == false ]] \
  || fail "PULSEVM_NATIVE_SYSTEM_CONTRACT must be true or false"
[[ "$PULSEVM_DB_SIZE" =~ ^[0-9]{1,12}$ ]] && (( PULSEVM_DB_SIZE >= 67108864 )) \
  || fail "PULSEVM_DB_SIZE must be at least 67108864 bytes"
[[ "$CORE_SYMBOL" =~ ^[A-Z]{1,7}$ ]] || fail "CORE_SYMBOL must contain 1 to 7 uppercase letters"
[[ "$CORE_PRECISION" =~ ^[0-9]$ ]] || fail "CORE_PRECISION must be between 0 and 9"

# Reuse the already-public test key instead of committing another private key.
producer_key="${PULSEVM_PRODUCER_KEY:-$(jq -er '.node1.producer_key' /opt/localnet/default-chain-config.json)}"
chain_config=$(jq -cn \
  --arg producer_name "$PULSEVM_PRODUCER_NAME" --arg producer_key "$producer_key" \
  --arg system_account "$PULSEVM_SYSTEM_ACCOUNT" \
  --argjson native_system_contract "$PULSEVM_NATIVE_SYSTEM_CONTRACT" \
  --argjson db_size "$PULSEVM_DB_SIZE" \
  '{producer_name:$producer_name, producer_key:$producer_key, system_account:$system_account,
    native_system_contract:$native_system_contract, db_size:$db_size, state_history_enabled:true}')

mkdir -p /data/snapshots /localnet
rm -f /localnet/ready
input_hash=$(jq -cS --argjson config "$chain_config" --argjson nodes "$NODE_COUNT" \
  '{genesis:., config:$config, nodes:$nodes}' /config/genesis.json | sha256sum | cut -d ' ' -f1)
if [[ -f /data/input.sha256 ]]; then
  [[ "$(< /data/input.sha256)" == "$input_hash" ]] \
    || fail "genesis or node configuration changed; use a new Compose project or reset all localnet volumes"
fi
[[ ! -f /data/session-active ]] \
  || fail "previous shutdown was incomplete; data is preserved in /data. Recover it before restarting, or reset all localnet volumes"

runner_pid=""
network_ready=false
cleanup() {
  local result=$?
  trap - EXIT TERM INT
  rm -f /localnet/ready
  if [[ -n "$runner_pid" ]]; then
    if [[ "$network_ready" == true ]]; then
      echo "localnet: stopping nodes and saving the localnet snapshot"
      if api savesnapshot '{"snapshotName":"localnet","force":true,"snapshotPath":"/data/snapshots/localnet"}' 150 \
        | jq -e '.snapshotPath | type == "string" and length > 0' >/dev/null; then
        rm -f /data/session-active
      else
        echo "localnet: snapshot failed; leaving the recovery marker and node data intact" >&2
        result=1
      fi
    else
      api stop '{}' 20 >/dev/null 2>&1 || true
    fi
    kill "$runner_pid" 2>/dev/null || true
    wait "$runner_pid" 2>/dev/null || true
  fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

# Leave WS_BIND unset. The first VM binds :9090; the remaining co-located VMs
# use the VM's supported ephemeral-port fallback. All serve the same chain.
unset WS_BIND
metal-network-runner server --log-level info --port=:8080 \
  --grpc-gateway-port=:8081 --snapshots-dir=/data/snapshots --disable-nodes-output &
runner_pid=$!
for (( attempt=0; attempt<60; attempt++ )); do
  if curl --fail --silent --max-time 1 http://127.0.0.1:8081/v1/ping \
    -H 'Content-Type: application/json' --data '{}' >/dev/null; then
    break
  fi
  kill -0 "$runner_pid" 2>/dev/null || fail "network runner exited before its API became ready"
  sleep 1
done
curl --fail --silent --max-time 2 http://127.0.0.1:8081/v1/ping \
  -H 'Content-Type: application/json' --data '{}' >/dev/null || fail "runner API startup timed out"

printf '%s\n' "$input_hash" > /data/input.sha256
touch /data/session-active
if [[ -f /data/snapshots/localnet/network.json ]]; then
  echo "localnet: restoring the saved cluster"
  api loadsnapshot '{"snapshotName":"localnet","snapshotPath":"/data/snapshots/localnet",
    "execPath":"/usr/local/bin/metalgo","pluginDir":"/opt/plugins",
    "rootDataDir":"/data/network","reassignPortsIfUsed":false,
    "globalNodeConfig":"{\"http-host\":\"0.0.0.0\",\"http-allowed-hosts\":\"*\"}"}' 600 >/dev/null
else
  node_configs=$(jq -cn --argjson count "$NODE_COUNT" \
    'reduce range(0;$count) as $i ({}; .["node\($i+1)"] =
      ({"http-port":(9650+$i*2),"staking-port":(9651+$i*2)} | tojson))')
  # Runner node flags need the string "*" for the host filter. A JSON array
  # becomes the literal host "[*]" and rejects the other Compose services.
  start_request=$(jq -cn --argjson nodes "$NODE_COUNT" --argjson node_configs "$node_configs" \
    --arg config "$chain_config" \
    '{execPath:"/usr/local/bin/metalgo",pluginDir:"/opt/plugins",numNodes:$nodes,
      rootDataDir:"/data/network",reassignPortsIfUsed:false,dynamicPorts:false,
      globalNodeConfig:({"http-host":"0.0.0.0","http-allowed-hosts":"*"} | tojson),
      customNodeConfigs:$node_configs,
      blockchainSpecs:[{vm_name:"pulsevm",genesis:"/config/genesis.json",
        blockchain_alias:"pulse",chain_config:$config}]}')
  echo "localnet: starting $NODE_COUNT MetalGo validators with PulseVM"
  api start "$start_request" 600 >/dev/null
fi
api waitforhealthy '{}' 600 | jq -e '.clusterInfo.customChainsHealthy' >/dev/null

info=$(curl --fail --silent --show-error --max-time 10 http://127.0.0.1:9650/ext/bc/pulse/rpc \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"pulsevm.getInfo","params":{}}')
jq -e '.result.chain_id | type == "string" and length == 64' <<<"$info" >/dev/null \
  || fail "PulseVM did not expose a valid chain ID through the pulse alias"
network_ready=true

envsubst '$PULSEVM_SYSTEM_ACCOUNT' < /opt/localnet/hyperion.toml > /localnet/hyperion.toml
jq -cn --argjson info "$info" \
  --arg timestamp "$(jq -r '.initial_timestamp' /config/genesis.json)" \
  --arg system "$PULSEVM_SYSTEM_ACCOUNT" --arg symbol "$CORE_SYMBOL" --argjson precision "$CORE_PRECISION" \
  '{chain_id:$info.result.chain_id, initial_timestamp:$timestamp, system_account:$system,
    core_symbol:$symbol, core_precision:$precision}' > /localnet/chain.json
printf 'window.PULSEVM_LOCALNET = %s;\n' "$(< /localnet/chain.json)" > /localnet/localnet-config.js
touch /localnet/ready
echo "localnet: ready; RPC alias /ext/bc/pulse/rpc; Antelope chain ID $(jq -r '.chain_id' /localnet/chain.json)"
wait "$runner_pid"
