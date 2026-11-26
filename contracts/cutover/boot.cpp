// Fixture-only feature activator for the multi-key schedule fixture. NEVER
// DEPLOY TO MAINNET.
//
// A fresh Leap chain has only PREACTIVATE_FEATURE; every other protocol
// feature (WTMSIG_BLOCK_SIGNATURES, which eosio.bios needs for
// set_proposed_producers_ex) must be preactivated by a privileged contract
// before the block that activates it. This is the stock eosio.boot shape:
// one action, one intrinsic.

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

extern "C" {
__attribute__((eosio_wasm_import)) void preactivate_feature(const void *feature_digest);
}

namespace boot {

CONTRACT boot : public eosio::contract {
  public:
    using eosio::contract::contract;

    ACTION activate(const eosio::checksum256 &feature_digest) {
        require_auth(get_self());
        const auto bytes = feature_digest.extract_as_byte_array();
        preactivate_feature(bytes.data());
    }
};

} // namespace boot
