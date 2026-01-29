#pragma once
#include <pulsevm/chain/types.hpp>
#include <pulsevm/chain/authority.hpp>
#include <pulsevm/chain/block_timestamp.hpp>
#include <pulsevm/chain/genesis_state.hpp>

namespace pulsevm { namespace chain {
    using CxxBlockTimestamp = pulsevm::chain::block_timestamp_type;
    using CxxChainConfig = pulsevm::chain::chain_config;
    using CxxDigest = pulsevm::chain::digest_type;
    using CxxGenesisState = pulsevm::chain::genesis_state;
    using CxxMicroseconds = fc::microseconds;
    using CxxPublicKey = pulsevm::chain::public_key_type;
    using CxxSignature = pulsevm::chain::signature_type;
    using CxxSharedBlob = pulsevm::chain::shared_blob;
    using CxxTimePoint = pulsevm::chain::time_point;
    using CxxSharedAuthority = pulsevm::chain::shared_authority;
    using CxxPrivateKey = pulsevm::chain::private_key_type;
    using CxxSharedKeyWeight = pulsevm::chain::shared_key_weight;
    using CxxSharedKeyWeightVector = pulsevm::chain::shared_vector<pulsevm::chain::shared_key_weight>;
}}