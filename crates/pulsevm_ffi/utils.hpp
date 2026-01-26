#pragma once
#include "type_defs.hpp"
#include <rust/cxx.h>
#include <fc/io/json.hpp>

namespace pulsevm { namespace chain {

    std::unique_ptr<CxxDigest> make_empty_digest() {
        return std::make_unique<CxxDigest>();
    }

    std::unique_ptr<CxxDigest> make_digest_from_data(rust::Slice<const std::uint8_t> data) {
        // Hash the data to get a SHA256 digest
        CxxDigest hash = CxxDigest::hash(
            reinterpret_cast<const char*>(data.data()), 
            data.size()
        );
        return std::make_unique<CxxDigest>(hash);
    }

    std::shared_ptr<CxxDigest> make_shared_digest_from_data(rust::Slice<const std::uint8_t> data) {
        CxxDigest hash = CxxDigest::hash(
            reinterpret_cast<const char*>(data.data()), 
            data.size()
        );
        return std::make_shared<CxxDigest>(hash);
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

    std::shared_ptr<CxxSignature> parse_signature(rust::Str signature_str) {
        std::string s(signature_str.data(), signature_str.size());
        CxxSignature sig = CxxSignature(s);
        return std::make_shared<CxxSignature>(std::move(sig));
    }

    std::shared_ptr<CxxPublicKey> recover_public_key_from_signature(const CxxSignature& sig, const CxxDigest& digest) {
        CxxPublicKey pk(sig, digest, true);
        return std::make_shared<CxxPublicKey>(std::move(pk));
    }

    std::shared_ptr<CxxPublicKey> get_public_key_from_private_key(const CxxPrivateKey& private_key) {
        CxxPublicKey pk = private_key.get_public_key();
        return std::make_shared<CxxPublicKey>(std::move(pk));
    }

}} // namespace pulsevm::chain