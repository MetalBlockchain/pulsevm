#!/usr/bin/env bash
set -e

if ! [[ "$0" =~ scripts/tests.integration.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

PULSEVM_PATH=$(
  cd "$(dirname "${BASH_SOURCE[0]}")"
  cd .. && pwd
)
source "$PULSEVM_PATH"/scripts/constants.sh

# to install the ginkgo binary (required for test build and run)
go install -v github.com/onsi/ginkgo/v2/ginkgo@v2.0.0-rc2

echo "building pulsevm"
./scripts/build.sh

rm -Rf "$PULSEVM_PATH/tests/integration/tmpnet"

# run with 3 embedded VMs
ACK_GINKGO_RC=true ginkgo \
run \
-v \
./tests/integration \
-- \
--vms 5 \
--metalgo-path /Users/glennmarien/Documents/MetalBlockchain/metalgo/build/metalgo \
--plugin-path "$PULSEVM_PATH/build"

echo "ALL SUCCESS!"