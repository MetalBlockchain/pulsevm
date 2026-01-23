#pragma once
#include <rust/cxx.h>
#include <pulsevm/chain/authority.hpp>
#include <pulsevm/chain/block_timestamp.hpp>
#include <pulsevm/chain/types.hpp>
#include <pulsevm/chain/genesis_state.hpp>
#include <fc/io/json.hpp>

namespace pulsevm { namespace chain {

    using CxxAuthority = pulsevm::chain::authority;
    using CxxKeyWeight = pulsevm::chain::key_weight;
    using CxxPermissionLevelWeight = pulsevm::chain::permission_level_weight;
    using CxxWaitWeight = pulsevm::chain::wait_weight;
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

    std::unique_ptr<CxxDigest> make_empty_digest() {
        return std::make_unique<CxxDigest>();
    }

    std::unique_ptr<CxxDigest> make_digest_from_data(rust::Slice<const std::uint8_t> data) {
        return std::make_unique<CxxDigest>(reinterpret_cast<const char*>(data.data()), data.size());
    }

    std::shared_ptr<CxxDigest> make_shared_digest_from_data(rust::Slice<const std::uint8_t> data) {
        return std::make_shared<CxxDigest>(reinterpret_cast<const char*>(data.data()), data.size());
    }

    std::shared_ptr<CxxTimePoint> make_time_point_from_now() {
        return std::make_shared<CxxTimePoint>(CxxTimePoint::now());
    }

    std::shared_ptr<CxxBlockTimestamp> make_block_timestamp_from_now() {
        return std::make_shared<CxxBlockTimestamp>(CxxTimePoint::now());
    }

    std::shared_ptr<CxxBlockTimestamp> make_block_timestamp_from_slot( uint32_t slot ) {
        return std::make_shared<CxxBlockTimestamp>(slot);
    }

    std::shared_ptr<CxxTimePoint> make_time_point_from_i64(int64_t us) {
        return std::make_shared<CxxTimePoint>(CxxTimePoint(CxxMicroseconds(us)));
    }

    std::shared_ptr<CxxTimePoint> make_time_point_from_microseconds(const CxxMicroseconds& us) {
        return std::make_shared<CxxTimePoint>(CxxTimePoint(us));
    }

    std::unique_ptr<CxxGenesisState> make_empty_genesis_state() {
        return std::make_unique<CxxGenesisState>();
    }

    std::unique_ptr<CxxGenesisState> parse_genesis_state(rust::Str json) {
        std::string s(json.data(), json.size());
        fc::variant v = fc::json::from_string(s);
        genesis_state gstate = v.as<genesis_state>();
        return std::make_unique<CxxGenesisState>(std::move(gstate));
    }

    std::shared_ptr<CxxPublicKey> parse_public_key(rust::Str key_str) {
        std::string s(key_str.data(), key_str.size());
        CxxPublicKey pk = CxxPublicKey(s);
        return std::make_shared<CxxPublicKey>(std::move(pk));
    }

    std::shared_ptr<CxxPublicKey> parse_public_key_from_bytes(rust::Slice<const std::uint8_t> data, size_t& pos) {
        fc::datastream<const char*> ds(reinterpret_cast<const char*>(data.data()), data.size());
        CxxPublicKey pk;
        fc::raw::unpack(ds, pk);
        pos += ds.tellp();
        return std::make_shared<CxxPublicKey>(std::move(pk));
    }

    std::shared_ptr<CxxPrivateKey> parse_private_key(rust::Str key_str) {
        std::string s(key_str.data(), key_str.size());
        CxxPrivateKey pk = CxxPrivateKey(s);
        return std::make_shared<CxxPrivateKey>(std::move(pk));
    }

    std::shared_ptr<CxxSignature> sign_digest_with_private_key(const CxxDigest& digest, const CxxPrivateKey& private_key) {
        CxxSignature sig = private_key.sign(digest, true);
        return std::make_shared<CxxSignature>(std::move(sig));
    }

    std::shared_ptr<CxxSignature> parse_signature_from_bytes(rust::Slice<const std::uint8_t> data, size_t& pos) {
        fc::datastream<const char*> ds(reinterpret_cast<const char*>(data.data()), data.size());
        CxxSignature sig;
        fc::raw::unpack(ds, sig);
        pos += ds.tellp();
        return std::make_shared<CxxSignature>(std::move(sig));
    }

    std::shared_ptr<CxxAuthority> make_authority(uint32_t threshold, const std::vector<CxxKeyWeight>& keys, const std::vector<CxxPermissionLevelWeight>& accounts, const std::vector<CxxWaitWeight>& waits) {
        return std::make_shared<CxxAuthority>(threshold, std::move(keys), std::move(accounts), std::move(waits));
    }

    std::shared_ptr<CxxPublicKey> recover_public_key_from_signature(const CxxSignature& sig, const CxxDigest& digest) {
        CxxPublicKey pk(sig, digest, true);
        return std::make_shared<CxxPublicKey>(std::move(pk));
    }

}} // namespace pulsevm::chain