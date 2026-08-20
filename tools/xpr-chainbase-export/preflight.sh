#!/usr/bin/env bash
# Validate the immutable inputs to an XPR chainbase export before nodeos is
# started. This is deliberately read-only: it never changes the snapshot, the
# XPR checkout, or the destination directory.

set -euo pipefail

readonly pinned_core_revision="cbb24506280275f4fb51fb9d77758ff8249fa655"

usage() {
    cat <<'EOF'
Usage:
  preflight.sh --nodeos PATH --snapshot PATH --xpr-core PATH --p2p-peer HOST:PORT [options]

Required:
  --nodeos PATH            XPR nodeos binary to use for export
  --snapshot PATH          Read-only XPR nodeos snapshot (.bin)
  --xpr-core PATH          Git checkout used to build nodeos
  --p2p-peer HOST:PORT     Source-network peer; repeatable

Options:
  --source-revision SHA    Required checkout revision
                          (default: cbb24506280275f4fb51fb9d77758ff8249fa655)
  --minimum-free-gib N     Require at least N GiB free beside the snapshot
  --require-sidecar-plugin Require the deferred-transaction sidecar source
                          plugin to be installed and linked into nodeos
  --help                   Show this help

The checkout revision is an operator attestation that must match the snapshot
provenance. This script can verify the checkout, but only a trusted snapshot
publisher can establish which revision created a given Mainnet snapshot.
EOF
}

nodeos=""
snapshot=""
xpr_core=""
source_revision="$pinned_core_revision"
minimum_free_gib=0
require_sidecar_plugin=false
peers=()

while (($#)); do
    case "$1" in
        --nodeos) nodeos="$2"; shift 2 ;;
        --snapshot) snapshot="$2"; shift 2 ;;
        --xpr-core) xpr_core="$2"; shift 2 ;;
        --p2p-peer) peers+=("$2"); shift 2 ;;
        --source-revision) source_revision="$2"; shift 2 ;;
        --minimum-free-gib) minimum_free_gib="$2"; shift 2 ;;
        --require-sidecar-plugin) require_sidecar_plugin=true; shift ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -x "$nodeos" ]] || { echo "nodeos is not executable: $nodeos" >&2; exit 2; }
[[ -s "$snapshot" ]] || { echo "snapshot does not exist or is empty: $snapshot" >&2; exit 2; }
[[ -d "$xpr_core/.git" ]] || { echo "not a Git XPR core checkout: $xpr_core" >&2; exit 2; }
[[ -f "$xpr_core/plugins/CMakeLists.txt" ]] || { echo "not an XPR core checkout: $xpr_core" >&2; exit 2; }
[[ -f "$xpr_core/programs/nodeos/CMakeLists.txt" ]] || { echo "not an XPR nodeos source tree: $xpr_core" >&2; exit 2; }
[[ "$source_revision" =~ ^[[:xdigit:]]{7,64}$ ]] || {
    echo "--source-revision must be a Git SHA" >&2
    exit 2
}
[[ "$minimum_free_gib" =~ ^[0-9]+$ ]] || {
    echo "--minimum-free-gib must be a non-negative integer" >&2
    exit 2
}
((${#peers[@]})) || { echo "at least one --p2p-peer is required" >&2; exit 2; }

for peer in "${peers[@]}"; do
    host="${peer%:*}"
    port="${peer##*:}"
    [[ -n "$host" && "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] || {
        echo "invalid --p2p-peer (expected HOST:PORT): $peer" >&2
        exit 2
    }
done

checkout_revision="$(git -C "$xpr_core" rev-parse HEAD)"
[[ "$checkout_revision" == "$source_revision" ]] || {
    echo "XPR core checkout is $checkout_revision, expected $source_revision" >&2
    exit 2
}

if "$require_sidecar_plugin"; then
    plugin_dir="$xpr_core/plugins/deferred_transaction_sidecar_plugin"
    [[ -f "$plugin_dir/deferred_transaction_sidecar_plugin.cpp" ]] || {
        echo "deferred-transaction sidecar plugin is not installed in $plugin_dir" >&2
        exit 2
    }
    rg -q 'add_subdirectory\(deferred_transaction_sidecar_plugin\)' "$xpr_core/plugins/CMakeLists.txt" || {
        echo "XPR core plugins CMake does not include the deferred sidecar plugin" >&2
        exit 2
    }
    rg -q 'deferred_transaction_sidecar_plugin' "$xpr_core/programs/nodeos/CMakeLists.txt" || {
        echo "XPR nodeos CMake does not link the deferred sidecar plugin" >&2
        exit 2
    }
fi

available_kib="$(df -Pk "$(dirname "$snapshot")" | awk 'NR == 2 { print $4 }')"
required_kib=$((minimum_free_gib * 1024 * 1024))
[[ "$available_kib" =~ ^[0-9]+$ && "$available_kib" -ge "$required_kib" ]] || {
    echo "insufficient free space beside snapshot: need ${minimum_free_gib} GiB" >&2
    exit 2
}

sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

printf 'preflight passed\n'
printf 'source_revision=%s\n' "$checkout_revision"
printf 'snapshot_sha256=%s\n' "$(sha256 "$snapshot")"
printf 'snapshot_free_gib=%s\n' "$((available_kib / 1024 / 1024))"
printf 'deferred_sidecar_plugin=%s\n' "$require_sidecar_plugin"
