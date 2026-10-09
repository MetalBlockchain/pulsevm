#!/usr/bin/env bash
# Create a new static Bloks release configured for PulseVM RPC and Proton data.
set -euo pipefail

readonly ROOT="${BLOKS_FRONTEND_ROOT:-/var/www/bloks-frontend}"
readonly CURRENT="$ROOT/current"

fail() {
  echo "error: $*" >&2
  exit 1
}

[[ "$EUID" == 0 ]] || fail "run this script as root"
[[ -L "$CURRENT" ]] || fail "missing current release symlink: $CURRENT"
readonly CURRENT_RELEASE="$(readlink -f "$CURRENT")"
[[ -d "$CURRENT_RELEASE/js" ]] || fail "missing frontend js directory in $CURRENT_RELEASE"

shopt -s nullglob
readonly BUNDLES=("$CURRENT_RELEASE"/js/app.*.js)
[[ "${#BUNDLES[@]}" == 1 ]] || fail "expected one compiled app bundle in $CURRENT_RELEASE/js"
readonly BUNDLE="${BUNDLES[0]}"
readonly DISABLED_TOGGLE='da=!0,ha=!1,pa='
readonly ENABLED_TOGGLE='da=!0,ha=!0,pa='
grep -Fq "$DISABLED_TOGGLE" "$BUNDLE" || grep -Fq "$ENABLED_TOGGLE" "$BUNDLE" || \
  fail "the current bundle does not have the expected PulseVM toggle"
grep -Fq 'USE_PULSE_VM:ha' "$BUNDLE" || fail "the bundle does not map USE_PULSE_VM to the expected flag"

readonly RELEASE_NAME="$(date -u +%Y%m%d%H%M%S)-local-pulsevm"
readonly NEW_RELEASE="$ROOT/releases/$RELEASE_NAME"
readonly NEXT_LINK="$ROOT/.current-$RELEASE_NAME"
[[ ! -e "$NEW_RELEASE" && ! -e "$NEXT_LINK" ]] || fail "release path already exists"
mkdir -p "$ROOT/releases"
cp -a "$CURRENT_RELEASE" "$NEW_RELEASE"
readonly RELEASE_BUNDLE="$NEW_RELEASE/js/$(basename "$BUNDLE")"
sed -i 's/da=!0,ha=!1,pa=/da=!0,ha=!0,pa=/' "$RELEASE_BUNDLE"
grep -Fq "$ENABLED_TOGGLE" "$RELEASE_BUNDLE" || {
  rm -rf "$NEW_RELEASE"
  fail "failed to enable the PulseVM frontend adapter"
}
python3 - "$RELEASE_BUNDLE" <<'PY' || {
from pathlib import Path
import sys

bundle_path = Path(sys.argv[1])
source = bundle_path.read_text()

old_fetch = 'r=l?u().call(o,p):this.processResult(p)'
new_fetch = 'r=l?u().call(o,p):this.processResult(p&&void 0!==p.result?p.result:p)'
if source.count(new_fetch) == 1:
    pass
elif source.count(old_fetch) == 1:
    source = source.replace(old_fetch, new_fetch, 1)
else:
    raise SystemExit("expected one PulseVM JSON-RPC result adapter in the app bundle")

old_producers = (
    'key:"get_producers",value:function(){return y(function(){return K(this,function(e){'
    'switch(e.label){case 0:return[4,this.fetch("pulsevm.getProducers",{})];'
    'case 1:return[2,e.sent()]}})}).call(this)}'
)
previous_producers = (
    'key:"get_producers",value:function(){return y(function(){return K(this,function(e){'
    'switch(e.label){case 0:return[4,this.fetch("pulsevm.getProducers",{})];'
    'case 1:return[2,function(t){return Array.isArray(t)?t:t&&Array.isArray(t.producers)?'
    't.producers:t&&Array.isArray(t.rows)?t.rows:[]}(e.sent())]}})}).call(this)}'
)
new_producers = (
    'key:"get_producers",value:function(){return y(function(){return K(this,function(e){'
    'switch(e.label){case 0:return[4,this.fetch("pulsevm.getProducers",{})];'
    'case 1:return[2,function(t){var p=Array.isArray(t)?t:t&&Array.isArray(t.producers)?'
    't.producers:t&&Array.isArray(t.rows)?t.rows:[];return p.producers=p,p.count=t&&'
    '"number"===typeof t.count?t.count:p.length,p}(e.sent())]}})}).call(this)}'
)
if source.count(new_producers) == 1:
    pass
elif source.count(previous_producers) == 1:
    source = source.replace(previous_producers, new_producers, 1)
elif source.count(old_producers) == 1:
    source = source.replace(old_producers, new_producers, 1)
else:
    raise SystemExit("expected one PulseVM producer array adapter in the app bundle")

old_api_url = 'Qi="",Ji="pulsevm-ec2"'
new_api_url = 'Qi="https://www.api.bloks.io/proton",Ji="pulsevm-ec2"'
if source.count(new_api_url) == 1:
    pass
elif source.count(old_api_url) == 1:
    source = source.replace(old_api_url, new_api_url, 1)
else:
    raise SystemExit("expected one PulseVM external price-service setting in the app bundle")

# The explorer's producer table expects the enriched Bloks producer service
# fields (num_votes, percentage_votes, reward, etc.). PulseVM's RPC returns
# consensus table rows, which use total_votes and omit those display fields.
# Reuse the configured Proton producer service for this presentation-only
# view, while keeping PulseVM as the source for chain state and RPC data.
old_producers_route = (
    'this.constants.USE_PULSE_VM?[4,this.rpc.get_producers()]:'
    '""===this.constants.API_URL||n?[3,2]:[4,this.get((0,s.Y4)(this.constants.API_URL,'
    '"producers",{pageNum:e,perPage:t}))]'
)
new_producers_route = (
    'this.constants.USE_PULSE_VM&&""===this.constants.API_URL?'
    '[4,this.rpc.get_producers()]:""===this.constants.API_URL||n?[3,2]:[4,this.get('
    '(0,s.Y4)(this.constants.API_URL,"producers",{pageNum:e,perPage:t}))]'
)
if source.count(new_producers_route) == 1:
    pass
elif source.count(old_producers_route) == 1:
    source = source.replace(old_producers_route, new_producers_route, 1)
else:
    raise SystemExit("expected one producer route to adapt PulseVM display data")

bundle_path.write_text(source)
PY
  rm -rf "$NEW_RELEASE"
  fail "failed to adapt PulseVM JSON-RPC responses in the compiled app bundle"
}
readonly VERSIONED_BUNDLE="app.local-pulsevm-${RELEASE_NAME}.js"
mv "$RELEASE_BUNDLE" "$NEW_RELEASE/js/$VERSIONED_BUNDLE"
sed -i "s#js/$(basename "$BUNDLE")#js/$VERSIONED_BUNDLE#" "$NEW_RELEASE/index.html"
grep -Fq "js/$VERSIONED_BUNDLE" "$NEW_RELEASE/index.html" || {
  rm -rf "$NEW_RELEASE"
  fail "failed to point index.html at the updated PulseVM app bundle"
}
ln -s "$NEW_RELEASE" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT"
echo "active_release=$NEW_RELEASE"
echo "rollback: ln -sfn '$CURRENT_RELEASE' '$CURRENT'"
