export module snet.crypt.hash;
import std;
import openssl;
import snet.crypt.bytes;


export namespace snet::crypt::hash {
    template <bool Secure = false>
    auto sha3_256(bytes::ViewBytes data) -> std::conditional_t<Secure, bytes::SecureBytes, bytes::RawBytes>;
}


template <bool Secure>
auto snet::crypt::hash::sha3_256(
    const bytes::ViewBytes data)
    -> std::conditional_t<Secure, bytes::SecureBytes, bytes::RawBytes> {
    using ret_t = std::conditional_t<Secure, bytes::SecureBytes, bytes::RawBytes>;

    // Create a new message digest context for SHA3-256.
    const auto ctx = openssl::EVP_MD_CTX_new();
    auto digest = ret_t(openssl::EVP_MD_get_size(openssl::EVP_sha3_256()));

    // Initialize the digest context and update it with the data to be hashed.
    openssl::EVP_DigestInit_ex(ctx, openssl::EVP_sha3_256(), nullptr);
    openssl::EVP_DigestUpdate(ctx, data.data(), data.size());
    openssl::EVP_DigestFinal_ex(ctx, digest.data(), nullptr);
    openssl::EVP_MD_CTX_free(ctx);

    // Return the computed hash as a SecureBytes object.
    return digest;
}
