#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <maximum-glibc-version> <binary> [binary ...]" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 2
fi

maximum_version=$1
shift

if [[ ! $maximum_version =~ ^[0-9]+(\.[0-9]+)+$ ]]; then
  echo "Invalid glibc version: $maximum_version" >&2
  usage
  exit 2
fi

readelf_command=${READELF:-readelf}
if ! command -v "$readelf_command" >/dev/null 2>&1; then
  echo "$readelf_command is required to inspect glibc symbol versions" >&2
  exit 2
fi

failed=0

for binary in "$@"; do
  if [[ ! -f $binary ]]; then
    echo "$binary: file not found" >&2
    failed=1
    continue
  fi

  if ! version_info=$("$readelf_command" --version-info --wide "$binary" 2>&1); then
    echo "$binary: readelf could not inspect the file" >&2
    echo "$version_info" >&2
    failed=1
    continue
  fi

  versions=$(grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' <<<"$version_info" \
    | sed 's/^GLIBC_//' \
    | sort -Vu || true)

  if [[ -z $versions ]]; then
    echo "$binary: no versioned glibc imports"
    continue
  fi

  required_version=$(tail -n 1 <<<"$versions")
  newest_version=$(printf '%s\n%s\n' "$maximum_version" "$required_version" \
    | sort -V \
    | tail -n 1)

  if [[ $newest_version != "$maximum_version" ]]; then
    echo "$binary: requires glibc $required_version (maximum supported: $maximum_version)" >&2
    failed=1
  else
    echo "$binary: requires glibc $required_version or older (maximum supported: $maximum_version)"
  fi
done

exit "$failed"
