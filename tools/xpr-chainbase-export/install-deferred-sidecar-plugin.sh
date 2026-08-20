#!/usr/bin/env bash
# Install the companion source plugin into an exact XPR Leap checkout before
# rebuilding nodeos. It deliberately refuses to replace an existing plugin.

set -euo pipefail

readonly pinned_core_revision="d133c6413ce8ce2e96096a0513ec25b4a8dbe837"
readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 --xpr-core PATH" >&2
}

xpr_core=""
while (($#)); do
    case "$1" in
        --xpr-core) xpr_core="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

[[ -n "$xpr_core" ]] || { usage; exit 2; }
[[ -f "$xpr_core/plugins/CMakeLists.txt" ]] || { echo "not an XPR Leap checkout: $xpr_core" >&2; exit 2; }
[[ -f "$xpr_core/programs/nodeos/CMakeLists.txt" ]] || { echo "not an XPR nodeos source tree: $xpr_core" >&2; exit 2; }

if [[ -d "$xpr_core/.git" ]]; then
    revision="$(git -C "$xpr_core" rev-parse HEAD)"
    [[ "$revision" == "$pinned_core_revision" ]] || {
        echo "XPR Leap must be pinned at $pinned_core_revision (found $revision)" >&2
        exit 2
    }
fi

plugin_dir="$xpr_core/plugins/deferred_transaction_sidecar_plugin"
[[ ! -e "$plugin_dir" ]] || { echo "refusing to overwrite $plugin_dir" >&2; exit 2; }

cp -R "$script_dir/deferred-sidecar-plugin" "$plugin_dir"

plugins_cmake="$xpr_core/plugins/CMakeLists.txt"
nodeos_cmake="$xpr_core/programs/nodeos/CMakeLists.txt"
printf '\nadd_subdirectory(deferred_transaction_sidecar_plugin)\n' >>"$plugins_cmake"

perl -0pi -e 's@(PRIVATE -Wl,\$\{whole_archive_flag\} state_history_plugin\s+-Wl,\$\{no_whole_archive_flag\})@PRIVATE -Wl,\${whole_archive_flag} deferred_transaction_sidecar_plugin -Wl,\${no_whole_archive_flag}\n        $1@' "$nodeos_cmake"
rg -q 'deferred_transaction_sidecar_plugin' "$nodeos_cmake" || {
    echo "could not add the source plugin to nodeos link libraries; remove $plugin_dir and inspect $nodeos_cmake" >&2
    exit 1
}

echo "installed deferred_transaction_sidecar_plugin; rebuild nodeos from $xpr_core"
