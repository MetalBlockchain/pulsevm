#!/bin/bash
# EXAMPLE recording run (adapt the four commands at the top to your network). Puts one node's directory on a dm-log-writes
# device, runs load and a set of restarts while every write is recorded, with named marks around each event, then
# tears down. Afterwards: plw-replay.py index/run/subset on $PLW_WORK/<name>/log.img, plw-select.py, plw-start.py.
#
# What it models: the node directory losing power at an arbitrary point of the recording (see README: prefix and
# volatile-cache models). Restarts inside the recording put cut points inside start-up, WAL recovery, catch-up and - if
# the node is far enough behind to state-sync (state_sync_min_blocks_behind, default 1024) - inside the install.
set -euo pipefail
NAME=${NAME:-node5}                           # a label; also the dm device name suffix
NODE_DIR=${NODE_DIR:?the node directory}      # must hold chainData/, db/, logs/
STOP=${STOP:?command that stops the node}     # e.g. systemctl stop my-node5
START=${START:?command that starts the node}
KILL=${KILL:?command that SIGKILLs the node MetalGo + plugin in one call}
LOAD=${LOAD:?command that runs transaction load for SECONDS seconds}   # background-able
SECS=${SECS:-640}; D="$(dirname "$0")/plw-dev.sh"
mk() { "$D" mark "$NAME" "$1"; }
$STOP; "$D" setup "$NAME" "$NODE_DIR"; $START; sleep 30; mk started; T0=$(date +%s)
SECONDS_=$SECS bash -c "$LOAD" & LP=$!
at() { while (( $(date +%s) < T0 + $1 )); do sleep 0.5; done; }
at 100; mk pre-clean-stop; $STOP; mk clean-stopped; $START; mk restarted; sleep 20
at 200; mk pre-kill; $KILL; mk killed; sleep 3; $START; mk restarted-after-kill; sleep 20
# a state-sync window: stop long enough to be more than state_sync_min_blocks_behind behind, then:
at 300; mk pre-kill-sync; $KILL; sleep ${SYNC_PAUSE:-60}; $START; mk restarted-for-sync; sleep 60; mk joined-after-sync
wait $LP; mk end; $KILL || true; sleep 2; $STOP || true
"$D" teardown "$NAME" "$NODE_DIR"; $START
