#!/usr/bin/env bash
# Build the cutover ceremony contracts with the pinned CDT (eosio.cdt 1.8.1,
# whose wasm output is proven on Leap 5 by the XPR system contracts).
# Usage: ./build.sh   (writes *.wasm / *.abi in this directory)
set -euo pipefail
cd "$(dirname "$0")"
for contract in cutover seed; do
    docker run --rm --platform linux/amd64 \
        -v "$PWD:/contracts" \
        -v "$PWD:/out" \
        eosio/eosio.cdt:v1.8.1 \
        sh -c "cd /tmp && eosio-cpp -abigen -o /out/${contract}.wasm /contracts/${contract}.cpp"
    python3 finalize_abi.py "${contract}.abi"
done
