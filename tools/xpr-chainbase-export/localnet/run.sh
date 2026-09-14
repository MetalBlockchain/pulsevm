#!/usr/bin/env bash
# Start a disposable single-producer XPR/Leap chain and make a snapshot that
# export.sh can consume. This is a fixture for exercising the converter, not a
# copy of XPR Mainnet state.
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly image="pulsevm-xpr-nodeos:leap-5.0.3"
readonly network="pulsevm-xpr-localnet"
readonly container="pulsevm-xpr-producer"
readonly default_work_dir="/tmp/pulsevm-xpr-localnet"

usage() {
    cat <<'EOF'
Usage: run.sh start [--work-dir DIR]
       run.sh snapshot [--work-dir DIR]
       run.sh stop

`start` builds the Leap image if needed and launches one local XPR producer.
`snapshot` asks that producer for a state snapshot and prints its host path.
All generated data is under /tmp by default; no XPR Mainnet data is used.
EOF
}

command="${1:-}"
[[ -n "$command" ]] || { usage >&2; exit 2; }
shift || true
work_dir="$default_work_dir"
while (($#)); do
    case "$1" in
        --work-dir) work_dir="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$command" in
    start)
        [[ ! -e "$work_dir" ]] || { echo "work directory already exists: $work_dir" >&2; exit 2; }
        [[ -z "$(docker ps -aq --filter "name=^/${container}$")" ]] || {
            echo "container already exists: $container" >&2; exit 2;
        }
        docker image inspect "$image" >/dev/null 2>&1 || \
            docker build --platform linux/amd64 -t "$image" "$script_dir"
        docker network inspect "$network" >/dev/null 2>&1 || docker network create "$network" >/dev/null
        mkdir -p "$work_dir"/{config,data}
        cp "$script_dir/genesis.json" "$work_dir/genesis.json"
        cp "$script_dir/producer-config.ini" "$work_dir/config/config.ini"
        docker run --detach --platform linux/amd64 \
            --name "$container" --network "$network" --network-alias xpr-producer \
            --mount "type=bind,src=$work_dir,dst=$work_dir" \
            "$image" nodeos --data-dir "$work_dir/data" --config-dir "$work_dir/config" \
            --genesis-json "$work_dir/genesis.json" >/dev/null
        for _ in $(seq 1 60); do
            if docker exec "$container" curl --fail --silent http://127.0.0.1:8888/v1/chain/get_info >/dev/null; then
                echo "XPR local producer is running: $container"
                echo "work directory: $work_dir"
                exit 0
            fi
            sleep 1
        done
        docker logs "$container" >&2 || true
        echo "XPR producer did not become ready" >&2
        exit 1
        ;;
    snapshot)
        [[ -d "$work_dir" ]] || { echo "work directory does not exist: $work_dir" >&2; exit 2; }
        docker inspect "$container" >/dev/null 2>&1 || { echo "producer is not running" >&2; exit 2; }
        snapshot_json="$(docker exec "$container" curl --fail --silent --request POST http://127.0.0.1:8888/v1/producer/create_snapshot)"
        snapshot_path="$(printf '%s' "$snapshot_json" | sed -n 's/.*"snapshot_name":"\([^"]*\)".*/\1/p')"
        [[ -n "$snapshot_path" ]] || { echo "could not parse snapshot response: $snapshot_json" >&2; exit 1; }
        if [[ "$snapshot_path" = /* ]]; then
            echo "$snapshot_path"
        else
            echo "$work_dir/data/$snapshot_path"
        fi
        ;;
    stop)
        docker rm --force "$container" >/dev/null 2>&1 || true
        ;;
    *)
        echo "unknown command: $command" >&2
        usage >&2
        exit 2
        ;;
esac
