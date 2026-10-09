#!/usr/bin/env bash
# Publish a Bloks release that reads complete block data from the local Leap API.
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
readonly APP_BUNDLE="${BUNDLES[0]}"
readonly COMPONENT_BUNDLES=("$CURRENT_RELEASE"/js/account.*.js)
[[ "${#COMPONENT_BUNDLES[@]}" == 1 ]] || fail "expected one compiled account bundle in $CURRENT_RELEASE/js"
readonly COMPONENT_BUNDLE="${COMPONENT_BUNDLES[0]}"

readonly RELEASE_NAME="$(date -u +%Y%m%d%H%M%S)-pulsevm-block-ui"
readonly NEW_RELEASE="$ROOT/releases/$RELEASE_NAME"
readonly NEXT_LINK="$ROOT/.current-$RELEASE_NAME"
[[ ! -e "$NEW_RELEASE" && ! -e "$NEXT_LINK" ]] || fail "release path already exists"

mkdir -p "$ROOT/releases"
cp -a "$CURRENT_RELEASE" "$NEW_RELEASE"
if ! python3 - "$NEW_RELEASE/js/$(basename "$APP_BUNDLE")" \
  "$NEW_RELEASE/js/$(basename "$COMPONENT_BUNDLE")" <<'PY'
from pathlib import Path
import sys

app_path = Path(sys.argv[1])
app_source = app_path.read_text()
rpc_get_block = (
    'key:"get_block",value:function(e){return y(function(){return K(this,function(t){'
    'switch(t.label){case 0:return[4,this.fetch("pulsevm.getBlock",'
    '{block_num_or_id:String(e)})];case 1:return[2,t.sent()]}})}).call(this)}}'
)
leap_get_block = (
    'key:"get_block",value:function(e){return y(function(){return K(this,function(t){'
    'switch(t.label){case 0:return[4,this.fetch("/v1/chain/get_block",'
    '{block_num_or_id:String(e)})];case 1:return[2,t.sent()]}})}).call(this)}}'
)
leap_with_pulsevm_fallback = (
    'key:"get_block",value:function(e){var r=this;return this.fetch("/v1/chain/get_block",'
    '{block_num_or_id:String(e)}).catch(function(){return r.fetch("pulsevm.getBlock",'
    '{block_num_or_id:String(e)}).then(function(b){if(b&&Array.isArray(b.transactions)&&'
    'b.transactions.some(function(x){return !x.trx}))b.pulsevm_transaction_receipts=b.transactions;'
    'return b})})}}'
)
leap_with_pulsevm_fallback_clear_receipts = (
    'key:"get_block",value:function(e){var r=this;return this.fetch("/v1/chain/get_block",'
    '{block_num_or_id:String(e)}).catch(function(){return r.fetch("pulsevm.getBlock",'
    '{block_num_or_id:String(e)}).then(function(b){if(b&&Array.isArray(b.transactions)&&'
    'b.transactions.some(function(x){return !x.trx})){b.pulsevm_transaction_receipts=b.transactions;'
    'b.transactions=[]}return b})})}}'
)
receipt_only_workaround = (
    'key:"get_block",value:function(e){return y(function(){return K(this,function(t){'
    'switch(t.label){case 0:return[4,this.fetch("pulsevm.getBlock",'
    '{block_num_or_id:String(e)})];case 1:return[2,function(b){'
    'if(b&&Array.isArray(b.transactions)&&b.transactions.some(function(x){return !x.trx})){'
    'b.pulsevm_transaction_receipts=b.transactions;b.transactions=[]}return b}(t.sent())]'
    '}})}).call(this)}}'
)
if app_source.count(leap_with_pulsevm_fallback) == 1:
    pass
elif app_source.count(leap_with_pulsevm_fallback_clear_receipts) == 1:
    app_source = app_source.replace(leap_with_pulsevm_fallback_clear_receipts, leap_with_pulsevm_fallback, 1)
elif app_source.count(leap_get_block) == 1:
    app_source = app_source.replace(leap_get_block, leap_with_pulsevm_fallback, 1)
elif app_source.count(rpc_get_block) == 1:
    app_source = app_source.replace(rpc_get_block, leap_with_pulsevm_fallback, 1)
elif app_source.count(receipt_only_workaround) == 1:
    app_source = app_source.replace(receipt_only_workaround, leap_with_pulsevm_fallback, 1)
else:
    raise SystemExit("expected one block adapter in the compiled app bundle")

native_history = 'oa=["native"]'
mixed_history = 'oa=["native","hyperion"]'
hyperion_history = 'oa=["hyperion"]'
if app_source.count(native_history) == 1:
    app_source = app_source.replace(native_history, hyperion_history, 1)
elif app_source.count(mixed_history) == 1:
    app_source = app_source.replace(mixed_history, hyperion_history, 1)
elif app_source.count(hyperion_history) != 1:
    raise SystemExit("expected the PulseVM EC2 history type list in the compiled app bundle")

without_hyperion_url = 'DOMAIN_TITLE:aa,HISTORY_TYPES:oa,KEY_PREFIX:sa'
with_hyperion_url = 'DOMAIN_TITLE:aa,HISTORY_TYPES:oa,HYPERION_URL:window.location.origin,KEY_PREFIX:sa'
if app_source.count(without_hyperion_url) == 1:
    app_source = app_source.replace(without_hyperion_url, with_hyperion_url, 1)
elif app_source.count(with_hyperion_url) != 1:
    raise SystemExit("expected the PulseVM EC2 history endpoint setting in the compiled app bundle")
app_path.write_text(app_source)

component_path = Path(sys.argv[2])
component_source = component_path.read_text()
old_key = "key:n.trx.id"
new_key = "key:n.trx&&n.trx.id||n.cpu_usage_us"
old_transaction_cell = (
    'e("td",[t.isString(n.trx)?e("router-link",{attrs:{to:{name:"Transaction",'
    'params:{id:n.trx,blockHint:t.block.block_num}}}},[t._v(" "+t._s(n.trx)+" ")]'
    '):e("router-link",{attrs:{to:{name:"Transaction",params:{id:n.trx.id,'
    'blockHint:t.block.block_num}}}},[t._v(" "+t._s(n.trx.id)+" ")])],1)'
)
new_transaction_cell = (
    'e("td",[n.trx?(t.isString(n.trx)?e("router-link",{attrs:{to:{name:"Transaction",'
    'params:{id:n.trx,blockHint:t.block.block_num}}}},[t._v(" "+t._s(n.trx)+" ")]'
    '):e("router-link",{attrs:{to:{name:"Transaction",params:{id:n.trx.id,'
    'blockHint:t.block.block_num}}}},[t._v(" "+t._s(n.trx.id)+" ")])):t._v("Receipt only")],1)'
)
if component_source.count(new_key) == 1 and component_source.count(new_transaction_cell) == 1:
    pass
elif component_source.count(old_key) == 1 and component_source.count(old_transaction_cell) == 1:
    component_path.write_text(
        component_source.replace(old_key, new_key, 1).replace(old_transaction_cell, new_transaction_cell, 1)
    )
else:
    raise SystemExit("expected one transaction ID row in the compiled block component")
PY
then
  rm -rf "$NEW_RELEASE"
  fail "failed to patch the PulseVM block response adapter"
fi

ln -s "$NEW_RELEASE" "$NEXT_LINK"
mv -Tf "$NEXT_LINK" "$CURRENT"
echo "active_release=$NEW_RELEASE"
echo "rollback: ln -sfn '$CURRENT_RELEASE' '$CURRENT'"
