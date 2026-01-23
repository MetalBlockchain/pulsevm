# Foreign Function Interface

This crate contains a set of FFI bindings to Spring's ChainDB and other internals.

It's important to understand the memory safety implications of using these types. Types constructed from this package need to be wrapped in either a UniquePtr or SharedPtr to ensure resources are cleaned up once they go out of scope.

The only exception would be objects coming from the chainbase database, these cannot be wrapped in a smart pointer and will often times be returned as a raw pointer, treat with caution.

## Requirements

- C++20 compiler
- Boost