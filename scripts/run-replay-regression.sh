#!/usr/bin/env bash
# Run the consensus replay against the frozen C++ state-root and SHiP outputs.
#
# Usage:
#   scripts/run-replay-regression.sh [fixture-directory-or-archive]
#
# The directory form must contain rpcblocks/, golden_roots.txt and
# ship_golden.txt. The archive form must be the exact frozen corpus identified
# below; this prevents a changed download from silently redefining the oracle.
set -euo pipefail

readonly EXPECTED_ARCHIVE_SHA256="68bff604d1471d63aacc6bea7c997f5c97e53eddd6c9864238061083836d7572"
readonly EXPECTED_BLOCKS=1697
readonly EXPECTED_ROOTS=23744
readonly EXPECTED_SHIP_DELTAS=1696

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${1:-${REPO_ROOT}/target/replay}"
FIXTURES="${SOURCE}"
TEMP_DIR=""

cleanup() {
  if [[ -n "${TEMP_DIR}" ]]; then
    rm -rf "${TEMP_DIR}"
  fi
}
trap cleanup EXIT

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [[ -f "${SOURCE}" ]]; then
  actual_sha="$(sha256_file "${SOURCE}")"
  if [[ "${actual_sha}" != "${EXPECTED_ARCHIVE_SHA256}" ]]; then
    echo "replay fixture digest mismatch: got ${actual_sha}, expected ${EXPECTED_ARCHIVE_SHA256}" >&2
    exit 1
  fi

  # Reject absolute paths and parent traversal before extracting an externally
  # downloaded archive.
  if tar -tzf "${SOURCE}" | awk '
    substr($0, 1, 1) == "/" ||
    $0 == ".." ||
    index($0, "../") == 1 ||
    index($0, "/../") > 0 ||
    substr($0, length($0) - 2) == "/.." { bad=1 }
    END { exit !bad }
  '; then
    echo "replay fixture archive contains an unsafe path" >&2
    exit 1
  fi

  TEMP_DIR="$(mktemp -d)"
  tar -xzf "${SOURCE}" -C "${TEMP_DIR}"
  FIXTURES="${TEMP_DIR}"
elif [[ ! -d "${SOURCE}" ]]; then
  echo "replay fixtures not found: ${SOURCE}" >&2
  exit 1
fi

BLOCK_DIR="${FIXTURES}/rpcblocks"
ROOTS_FILE="${FIXTURES}/golden_roots.txt"
SHIP_FILE="${FIXTURES}/ship_golden.txt"

for required in "${BLOCK_DIR}" "${ROOTS_FILE}" "${SHIP_FILE}"; do
  if [[ ! -e "${required}" ]]; then
    echo "incomplete replay corpus: missing ${required}" >&2
    exit 1
  fi
done

block_count="$(find "${BLOCK_DIR}" -type f -name '*.json' | wc -l | tr -d ' ')"
root_count="$(wc -l < "${ROOTS_FILE}" | tr -d ' ')"
ship_count="$(wc -l < "${SHIP_FILE}" | tr -d ' ')"
if [[ "${block_count}" != "${EXPECTED_BLOCKS}" || "${root_count}" != "${EXPECTED_ROOTS}" || "${ship_count}" != "${EXPECTED_SHIP_DELTAS}" ]]; then
  echo "incomplete replay corpus: blocks=${block_count}/${EXPECTED_BLOCKS}, roots=${root_count}/${EXPECTED_ROOTS}, SHiP=${ship_count}/${EXPECTED_SHIP_DELTAS}" >&2
  exit 1
fi

cd "${REPO_ROOT}"
PULSEVM_RPC_BLOCKS_DIR="${BLOCK_DIR}" \
PULSEVM_GOLDEN_ROOTS="${ROOTS_FILE}" \
PULSEVM_SHIP_VERIFY="${SHIP_FILE}" \
cargo test -p pulsevm_core --locked --lib replay_testnet_blocks -- \
  --ignored --nocapture --test-threads=1
