#pragma once
#include "type_defs.hpp"
#include <rust/cxx.h>
#include <fc/io/json.hpp>

namespace pulsevm { namespace chain {

    struct Authority;

    std::unique_ptr<CxxDigest> make_empty_digest();
    std::unique_ptr<CxxDigest> make_digest_from_data(rust::Slice<const std::uint8_t> data);
    std::shared_ptr<CxxDigest> make_shared_digest_from_data(rust::Slice<const std::uint8_t> data);
    std::shared_ptr<CxxDigest> make_shared_digest_from_string(rust::Str key_str);
    std::shared_ptr<CxxTimePoint> make_time_point_from_now();
    std::shared_ptr<CxxBlockTimestamp> make_block_timestamp_from_now();
    std::shared_ptr<CxxBlockTimestamp> make_block_timestamp_from_slot( uint32_t slot );
    std::shared_ptr<CxxTimePoint> make_time_point_from_i64(int64_t us);
    std::shared_ptr<CxxTimePoint> make_time_point_from_microseconds(const CxxMicroseconds& us);
    std::unique_ptr<CxxGenesisState> make_empty_genesis_state();
    std::unique_ptr<CxxGenesisState> parse_genesis_state(rust::Str json);
    std::shared_ptr<CxxPublicKey> parse_public_key(rust::Str key_str);
    std::shared_ptr<CxxPublicKey> parse_public_key_from_bytes(rust::Slice<const std::uint8_t> data);
    std::shared_ptr<CxxPrivateKey> parse_private_key(rust::Str key_str);
    rust::String private_key_to_string(const CxxPrivateKey& key);
    std::shared_ptr<CxxPrivateKey> make_k1_private_key(const CxxDigest& secret);
    std::shared_ptr<CxxSignature> sign_digest_with_private_key(const CxxDigest& digest, const CxxPrivateKey& private_key);
    std::shared_ptr<CxxSignature> parse_signature_from_bytes(rust::Slice<const std::uint8_t> data, size_t& pos);
    std::shared_ptr<CxxSignature> parse_signature(rust::Str signature_str);
    std::shared_ptr<CxxPublicKey> recover_public_key_from_signature(const CxxSignature& sig, const CxxDigest& digest);
    std::shared_ptr<CxxPublicKey> get_public_key_from_private_key(const CxxPrivateKey& private_key);
    std::shared_ptr<CxxPublicKey> make_unknown_public_key();
    rust::Vec<uint8_t> packed_public_key_bytes(const fc::crypto::public_key& public_key);
    rust::String public_key_to_string(const fc::crypto::public_key& public_key);
    size_t public_key_num_bytes(const fc::crypto::public_key& public_key);
    rust::String signature_to_string(const fc::crypto::signature& signature);
    size_t signature_num_bytes(const fc::crypto::signature& signature);
    rust::Vec<uint8_t> packed_signature_bytes(const fc::crypto::signature& signature);
    rust::Slice<const uint8_t> get_digest_data(const CxxDigest& sha);
    rust::Slice<const uint8_t> get_shared_blob_data(const CxxSharedBlob& blob);
    Authority get_authority_from_shared_authority(const CxxSharedAuthority& shared_auth);

}} // namespace pulsevm::chain