#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

if ! [[ "$0" =~ scripts/build.sh ]]; then
  echo "must be run from repository root"
  exit 255
fi

# Set default binary directory location
name="rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs"

# Build blobvm, which is run as a subprocess
mkdir -p ./build

echo "Building pulsevm in ./build/$name"
go build -o ./build/$name ./main