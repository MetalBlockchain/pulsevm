pub static ALIGNED_REF_WAST: &str = r#"(module
 (import "env" "sha256" (func $sha256 (param i32 i32 i32)))
 (table 0 funcref)
 (memory $0 32)
 (export "memory" (memory $0))
 (data (i32.const 4) "hello")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $sha256
   (i32.const 4)
   (i32.const 5)
   (i32.const 16)
  )
 )
)"#;

pub static MISALIGNED_REF_WAST: &str = r#"(module
 (import "env" "sha256" (func $sha256 (param i32 i32 i32)))
 (table 0 funcref)
 (memory $0 32)
 (export "memory" (memory $0))
 (data (i32.const 4) "hello")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (call $sha256
   (i32.const 4)
   (i32.const 5)
   (i32.const 5)
  )
 )
)"#;

pub static ALIGNED_CONST_REF_WAST: &str = r#"(module
 (import "env" "sha256" (func $sha256 (param i32 i32 i32)))
 (import "env" "assert_sha256" (func $assert_sha256 (param i32 i32 i32)))
 (table 0 funcref)
 (memory $0 32)
 (export "memory" (memory $0))
 (data (i32.const 4) "hello")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (local $3 i32)
  (call $sha256
   (i32.const 4)
   (i32.const 5)
   (i32.const 16)
  )
  (call $assert_sha256
   (i32.const 4)
   (i32.const 5)
   (i32.const 16)
  )
 )
)"#;

pub static MISALIGNED_CONST_REF_WAST: &str = r#"(module
 (import "env" "sha256" (func $sha256 (param i32 i32 i32)))
 (import "env" "assert_sha256" (func $assert_sha256 (param i32 i32 i32)))
 (import "env" "memmove" (func $memmove (param i32 i32 i32) (result i32)))
 (table 0 funcref)
 (memory $0 32)
 (export "memory" (memory $0))
 (data (i32.const 4) "hello")
 (export "apply" (func $apply))
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (local $3 i32)
  (call $sha256
   (i32.const 4)
   (i32.const 5)
   (i32.const 16)
  )
  (local.set $3
   (call $memmove
    (i32.const 17)
    (i32.const 16)
    (i32.const 64)
   )
  )
  (call $assert_sha256
   (i32.const 4)
   (i32.const 5)
   (i32.const 17)
  )
 )
)"#;

pub static ENTRY_WAST: &str = r#"(module
 (import "env" "require_auth" (func $require_auth (param i64)))
 (import "env" "pulse_assert" (func $pulse_assert (param i32 i32 i32)))
 (import "env" "current_time" (func $current_time (result i64)))
 (table 0 funcref)
 (memory $0 1)
 (export "memory" (memory $0))
 (export "entry" (func $entry))
 (export "apply" (func $apply))
 (func $entry
  (block
   (i64.store offset=4
    (i32.const 0)
    (call $current_time)
   )
  )
 )
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (block
   (call $require_auth (i64.const 6121376101093867520))
   (call $pulse_assert
    (i64.eq
     (i64.load offset=4
      (i32.const 0)
     )
     (call $current_time)
    )
    (i32.const 0)
    (i32.const 0)
   )
  )
 )
 (start $entry)
)"#;

pub static ENTRY_WAST_2: &str = r#"(module
 (import "env" "require_auth" (func $require_auth (param i64)))
 (import "env" "pulse_assert" (func $pulse_assert (param i32 i32 i32)))
 (import "env" "current_time" (func $current_time (result i64)))
 (table 0 funcref)
 (memory $0 1)
 (export "memory" (memory $0))
 (export "apply" (func $apply))
 (start $entry)
 (func $apply (param $0 i64) (param $1 i64) (param $2 i64)
  (block
   (call $require_auth (i64.const 6121376101093867520))
   (call $pulse_assert
    (i64.eq
     (i64.load offset=4
      (i32.const 0)
     )
     (call $current_time)
    )
    (i32.const 0)
    (i32.const 0)
   )
  )
 )
 (func $entry
  (block
   (i64.store offset=4
    (i32.const 0)
    (call $current_time)
   )
  )
 )
)"#;