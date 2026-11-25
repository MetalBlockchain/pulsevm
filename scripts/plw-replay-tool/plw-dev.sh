#!/bin/bash
# Put one node's data directory on ext4 over a dm-log-writes device so that every write the node makes (data, metadata,
# FLUSH and FUA) is recorded in order and can later be replayed to any cut point.
#
#   plw-dev.sh setup    <name> <node-dir> [dev-size, default 2G] [log-size, default 24G]
#   plw-dev.sh mark     <name> <text>         write a named mark into the log (e.g. before/after an event you inject)
#   plw-dev.sh teardown <name> <node-dir>
#
# setup: <node-dir> must not be in use. It is renamed to <node-dir>.host, a sparse loop file of dev-size is made into a
# dm-log-writes device (log on a second sparse loop file), mkfs.ext4 (defaults: data=ordered, journal), mark "mkfs", the
# old contents are copied in (except logs/, which is bind-mounted from the host copy so the node's own log output is NOT
# in the recording), sync, mark "copied". Replay cut points start at "copied".
# teardown: unmounts, removes the dm device and loops, puts <node-dir>.host back. The two image files stay in
# $PLW_WORK/<name>/ (dev.img, log.img); only log.img is needed afterwards.
# Requires: root, dm-log-writes (kernel CONFIG_DM_LOG_WRITES), losetup, dmsetup, mkfs.ext4, tar.
set -euo pipefail
cmd=$1 name=$2; W=${PLW_WORK:-$PWD/plw-work}/$name; DM=plw-$name
case $cmd in
setup)
  ND=$3; DS=${4:-2G}; LS=${5:-24G}; mkdir -p $W
  [ -e $ND.host ] && { echo "$ND.host exists"; exit 1; }
  mv $ND $ND.host
  truncate -s $DS $W/dev.img; truncate -s $LS $W/log.img
  DEV=$(losetup -f --show $W/dev.img); LOGD=$(losetup -f --show $W/log.img); echo "$DEV $LOGD" > $W/loops
  dmsetup create $DM --table "0 $(blockdev --getsz $DEV) log-writes $DEV $LOGD"
  mkfs.ext4 -q /dev/mapper/$DM; dmsetup message $DM 0 mark mkfs
  mkdir $ND; mount /dev/mapper/$DM $ND
  (cd $ND.host && tar --exclude=./logs -cf - .) | (cd $ND && tar -xpf -)
  mkdir -p $ND.host/logs $ND/logs; mount --bind $ND.host/logs $ND/logs
  sync; dmsetup message $DM 0 mark copied
  echo "$ND on /dev/mapper/$DM (dev $DEV, log $LOGD)";;
mark) dmsetup message $DM 0 mark "$3";;
teardown)
  ND=$3; umount $ND/logs 2>/dev/null || true; umount $ND
  dmsetup remove $DM; read -r DEV LOGD < $W/loops; losetup -d $DEV $LOGD
  rmdir $ND; mv $ND.host $ND
  echo "$ND back; images in $W (allocated $(du -sh $W | cut -f1))";;
*) echo "usage: see the header" >&2; exit 2;;
esac
