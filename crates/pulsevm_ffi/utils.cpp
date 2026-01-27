#include "utils.hpp"

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

rust::Str signature_to_string(const fc::crypto::signature& signature) {
    std::string s = signature.to_string(fc::yield_function_t());
    return rust::Str(s.data(), s.size());
}

rust::Str public_key_to_string(const fc::crypto::public_key& public_key) {
    std::string s = public_key.to_string(fc::yield_function_t());
    return rust::Str(s.data(), s.size());
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

rust::Vec<uint8_t> packed_public_key_bytes(const fc::crypto::public_key& public_key) {
    rust::Vec<uint8_t> out;
    size_t sz = fc::raw::pack_size(public_key);
    out.reserve(sz);
    fc::datastream<char*> ds(reinterpret_cast<char*>(out.data()), sz);
    fc::raw::pack(ds, public_key);
    return out;
}

rust::Str public_key_to_string(const fc::crypto::public_key& public_key);

size_t public_key_num_bytes(const fc::crypto::public_key& public_key) {
    return fc::raw::pack_size(public_key);
}

rust::Str signature_to_string(const fc::crypto::signature& signature);

size_t signature_num_bytes(const fc::crypto::signature& signature) {
    return fc::raw::pack_size(signature);
}

rust::Vec<uint8_t> packed_signature_bytes(const fc::crypto::signature& signature) {
    rust::Vec<uint8_t> out;
    size_t sz = fc::raw::pack_size(signature);
    out.reserve(sz);
    fc::datastream<char*> ds(reinterpret_cast<char*>(out.data()), sz);
    fc::raw::pack(ds, signature);
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

} }