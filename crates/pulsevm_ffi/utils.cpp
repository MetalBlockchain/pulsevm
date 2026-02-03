#include "utils.hpp"
#include <pulsevm_ffi/src/bridge.rs.h>

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

std::shared_ptr<CxxDigest> make_shared_digest_from_existing_hash(rust::Slice<const std::uint8_t> data) {
    return std::make_shared<CxxDigest>(reinterpret_cast<const char*>(data.data()), data.size());
}

std::shared_ptr<CxxDigest> make_shared_digest_from_string(rust::Str key_str) {
    std::string s(key_str.data(), key_str.size());
    CxxDigest hash = CxxDigest::hash(s);
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

rust::String signature_to_string(const fc::crypto::signature& signature) {
    std::string s = signature.to_string(fc::yield_function_t());
    return rust::String(s);
}

rust::String public_key_to_string(const fc::crypto::public_key& public_key) {
    std::string s = public_key.to_string(fc::yield_function_t());
    return rust::String(s);
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
    return std::make_shared<CxxPublicKey>(std::move(s));
}

std::shared_ptr<CxxPublicKey> parse_public_key_from_bytes(rust::Slice<const std::uint8_t> data) {
    fc::datastream<const char*> ds(reinterpret_cast<const char*>(data.data()), data.size());
    CxxPublicKey pk;
    fc::raw::unpack(ds, pk);
    return std::make_shared<CxxPublicKey>(std::move(pk));
}

std::shared_ptr<CxxPrivateKey> parse_private_key(rust::Str key_str) {
    std::string s(key_str.data(), key_str.size());
    CxxPrivateKey pk = CxxPrivateKey(s);
    return std::make_shared<CxxPrivateKey>(std::move(pk));
}

rust::String private_key_to_string(const CxxPrivateKey& key) {
    std::string s = key.to_string(fc::yield_function_t());
    return rust::String(s);
}

std::shared_ptr<CxxSignature> sign_digest_with_private_key(const CxxDigest& digest, const CxxPrivateKey& private_key) {
    CxxSignature sig = private_key.sign(digest, true);
    return std::make_shared<CxxSignature>(std::move(sig));
}

std::shared_ptr<CxxSignature> parse_signature_from_bytes(rust::Slice<const std::uint8_t> data) {
    fc::datastream<const char*> ds(reinterpret_cast<const char*>(data.data()), data.size());
    CxxSignature sig;
    fc::raw::unpack(ds, sig);
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

rust::Vec<uint8_t> packed_public_key_bytes(const fc::crypto::public_key& public_key) {
    size_t sz = fc::raw::pack_size(public_key);
    
    // Pack into a std::vector first
    std::vector<char> temp_buffer(sz);
    fc::datastream<char*> ds(temp_buffer.data(), sz);
    fc::raw::pack(ds, public_key);
    
    // Convert to rust::Vec
    rust::Vec<uint8_t> out;
    out.reserve(sz);
    for (const auto& byte : temp_buffer) {
        out.push_back(static_cast<uint8_t>(byte));
    }
    
    return out;
}

size_t public_key_num_bytes(const fc::crypto::public_key& public_key) {
    return fc::raw::pack_size(public_key);
}

size_t signature_num_bytes(const fc::crypto::signature& signature) {
    return fc::raw::pack_size(signature);
}

rust::Vec<uint8_t> packed_signature_bytes(const fc::crypto::signature& signature) {
    size_t sz = fc::raw::pack_size(signature);
    
    // Pack into a std::vector first
    std::vector<char> temp_buffer(sz);
    fc::datastream<char*> ds(temp_buffer.data(), sz);
    fc::raw::pack(ds, signature);
    
    // Convert to rust::Vec
    rust::Vec<uint8_t> out;
    out.reserve(sz);
    for (const auto& byte : temp_buffer) {
        out.push_back(static_cast<uint8_t>(byte));
    }
    
    return out;
}

rust::Slice<const uint8_t> get_digest_data(const CxxDigest& sha) {
    if (!sha.data()) {
        return {};
    }
    return rust::Slice<const uint8_t>(
        reinterpret_cast<const uint8_t*>(sha.data()),
        sha.data_size()
    );
}

rust::Slice<const uint8_t> get_shared_blob_data(const CxxSharedBlob& blob) {
    if (!blob.data()) {
        return {};
    }

    return rust::Slice<const uint8_t>(
        reinterpret_cast<const uint8_t*>(blob.data()),
        blob.size()
    );
}

Authority get_authority_from_shared_authority(const CxxSharedAuthority& shared_auth) {
    Authority auth;
    auth.threshold = shared_auth.threshold;
    auth.keys.reserve(shared_auth.keys.size());
    auth.accounts.reserve(shared_auth.accounts.size());
    auth.waits.reserve(shared_auth.waits.size());
    for (const auto& k : shared_auth.keys) {
        auto key = std::make_shared<public_key_type>(k.key.to_public_key());
        auth.keys.emplace_back( KeyWeight { key, k.weight } );
    }
    for (const auto& a : shared_auth.accounts) {
        auth.accounts.emplace_back( PermissionLevelWeight { PermissionLevel { a.permission.actor.to_uint64_t(), a.permission.permission.to_uint64_t() }, a.weight } );
    }
    for (const auto& w : shared_auth.waits) {
        auth.waits.emplace_back( WaitWeight { w.wait_sec, w.weight } );
    }
    return auth;
}

std::shared_ptr<CxxPublicKey> make_unknown_public_key() {
    fc::ecc::public_key_data data;
    data.data[0] = 0x80; // not necessary, 0 also works
    fc::sha256 hash = fc::sha256::hash("unknown key");
    std::memcpy(&data.data[1], hash.data(), hash.data_size() );
    fc::ecc::public_key_shim shim(data);
    fc::crypto::public_key new_owner_pub_key(std::move(shim));
    return std::make_shared<CxxPublicKey>(std::move(new_owner_pub_key));
}

std::shared_ptr<CxxPrivateKey> make_k1_private_key(const CxxDigest& secret) {
    CxxPrivateKey pk = CxxPrivateKey::regenerate<fc::ecc::private_key_shim>(std::move(secret));
    return std::make_shared<CxxPrivateKey>(std::move(pk));
}

rust::Vec<uint8_t> extract_chain_id_from_genesis_state(const CxxGenesisState& genesis) {
    chain_id_type cid = genesis.compute_chain_id();
    rust::Vec<uint8_t> out;
    out.reserve(cid.data_size());
    const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(cid.data());
    for (size_t i = 0; i < cid.data_size(); ++i) {
        out.push_back(data_ptr[i]);
    }
    return out;
}

} }