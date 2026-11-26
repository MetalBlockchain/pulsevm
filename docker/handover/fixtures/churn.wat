;; Rewrites one table row with as many bytes as the action carries.
;;
;; The post-cut restart check needs a workload that frees and reuses blob slots:
;; a contract row's value is rewritten in place (same size) or moved (different
;; size) on every update, and a node that restarted used to lose track of which
;; slots were free and so laid its state out differently from one that had not.
;; Account creation only appends and cannot show that; this can.
(module
  (import "env" "action_data_size" (func $size (result i32)))
  (import "env" "read_action_data" (func $read (param i32 i32) (result i32)))
  (import "env" "db_find_i64" (func $find (param i64 i64 i64 i64) (result i32)))
  (import "env" "db_store_i64"
    (func $store (param i64 i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_update_i64" (func $update (param i32 i64 i32 i32)))
  (memory (export "memory") 1)
  (func (export "apply") (param $receiver i64) (param $code i64) (param $action i64)
    (local $n i32) (local $itr i32)
    (local.set $n (call $size))
    (drop (call $read (i32.const 0) (local.get $n)))
    (local.set $itr (call $find (local.get $receiver) (i64.const 1) (i64.const 2) (i64.const 1)))
    (if (i32.lt_s (local.get $itr) (i32.const 0))
      (then
        (drop (call $store (i64.const 1) (i64.const 2) (local.get $receiver)
          (i64.const 1) (i32.const 0) (local.get $n))))
      (else
        (call $update (local.get $itr) (local.get $receiver) (i32.const 0) (local.get $n))))))
