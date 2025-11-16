export module snet.crypt.kdf;
import std;
import openssl;

import snet.crypt.bytes;


export namespace snet::crypt::kdf {
    /**
     * The @c derive_key function derives a key of the specified length from the given input key material (IKM) and
     * optional salt using the HKDF (HMAC-based Extract-and-Expand Key Derivation Function) algorithm with SHA3-256 as
     * the underlying hash function.
     * @param ikm The input key material from which to derive the key.
     * @param salt Optional salt value to use in the key derivation process.
     * @param additional_info Optional additional context and application-specific information to include in the key
     * derivation process.
     * @return A @c SecureBytes object containing the derived key of the specified length.
     */
    auto derive_key(
        bytes::ViewBytes ikm,
        bytes::ViewBytes salt = {},
        bytes::ViewBytes additional_info = {})
        -> bytes::SecureBytes;
}


auto snet::crypt::kdf::derive_key(
    const bytes::ViewBytes ikm,
    const bytes::ViewBytes salt,
    const bytes::ViewBytes additional_info)
    -> bytes::SecureBytes {
    // Create and initialize the HKDF context
    const auto pctx = openssl::EVP_PKEY_CTX_new_id(openssl::EVP_PKEY_HKDF, nullptr);
    openssl::EVP_PKEY_derive_init(pctx);
    openssl::EVP_PKEY_CTX_set_hkdf_md(pctx, openssl::EVP_sha3_256());
    openssl::EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size());
    openssl::EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size());
    openssl::EVP_PKEY_CTX_add1_hkdf_info(pctx, additional_info.data(), additional_info.size());

    auto out = bytes::SecureBytes();
    auto len = 0uz;
    openssl::EVP_PKEY_derive(pctx, out.data(), &len);
    openssl::EVP_PKEY_CTX_free(pctx);
    return out;
}
