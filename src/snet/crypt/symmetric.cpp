export module snet.crypt.symmetric;
import std;
import openssl;

import snet.crypt.bytes;


constexpr auto KEY_LEN = 32;
constexpr auto IV_LEN = 12;
constexpr auto TAG_LEN = 16;

export namespace snet::crypt::symmetric {
    struct CipherText {
        bytes::RawBytes ct;
        bytes::RawBytes iv;
        bytes::RawBytes tag;

        template <typename Ar>
        auto serialize(Ar &ar) -> void;
    };

    auto generate_key() -> bytes::SecureBytes;

    auto encrypt(
        const bytes::SecureBytes &key,
        const bytes::SecureBytes &pt)
        -> CipherText;

    auto decrypt(
        const bytes::SecureBytes &key,
        const bytes::RawBytes &ct,
        const bytes::RawBytes &iv,
        const bytes::RawBytes &tag)
        -> bytes::SecureBytes;
}


template <typename Ar>
auto snet::crypt::symmetric::CipherText::serialize(Ar &ar) -> void {
    ar & ct & iv & tag;
}


auto snet::crypt::symmetric::generate_key()
    -> bytes::SecureBytes {
    // Generate a random key of the specified length.
    auto key = bytes::SecureBytes(KEY_LEN);
    openssl::RAND_priv_bytes(key.data(), KEY_LEN);
    return key;
}


auto snet::crypt::symmetric::encrypt(
    const bytes::SecureBytes &key,
    const bytes::SecureBytes &pt)
    -> CipherText {
    // Create the initialization vector.
    auto iv = bytes::RawBytes(IV_LEN);
    openssl::RAND_priv_bytes(iv.data(), IV_LEN);

    // Create the context and set the IV length.
    const auto ctx = openssl::EVP_CIPHER_CTX_new();
    openssl::EVP_EncryptInit_ex(ctx, openssl::EVP_aes_256_ocb(), nullptr, key.data(), iv.data());
    openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, nullptr);
    openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_SET_TAG, TAG_LEN, nullptr);
    openssl::EVP_CIPHER_CTX_set_key_length(ctx, KEY_LEN);

    // Encrypt the plaintext.
    auto ct = bytes::RawBytes(pt.size());
    auto temp_len = 0;
    openssl::EVP_EncryptUpdate(ctx, ct.data(), &temp_len, pt.data(), pt.size());
    openssl::EVP_EncryptFinal_ex(ctx, ct.data() + temp_len, &temp_len);

    // Generate the authentication tag.
    auto tag = bytes::RawBytes(TAG_LEN);
    openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag.data());
    openssl::EVP_CIPHER_CTX_free(ctx);

    // Return the ciphertext, IV and tag encapsulated in a CipherText structure.
    return CipherText(std::move(ct), std::move(iv), std::move(tag));
}


auto snet::crypt::symmetric::decrypt(
    const bytes::SecureBytes &key,
    const bytes::RawBytes &ct,
    const bytes::RawBytes &iv,
    const bytes::RawBytes &tag)
    -> bytes::SecureBytes {
    // Create the context.
    const auto ctx = openssl::EVP_CIPHER_CTX_new();
    openssl::EVP_DecryptInit_ex(ctx, openssl::EVP_aes_256_ocb(), nullptr, key.data(), iv.data());

    // Set the IV length and authentication tag.
    openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, nullptr);
    openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_SET_TAG, TAG_LEN, (void*)tag.data());
    openssl::EVP_CIPHER_CTX_set_key_length(ctx, KEY_LEN);

    // Decrypt the ciphertext.
    auto pt = bytes::SecureBytes(ct.size());
    auto temp_len = 0;
    openssl::EVP_DecryptUpdate(ctx, pt.data(), &temp_len, ct.data(), ct.size());
    openssl::EVP_DecryptFinal_ex(ctx, pt.data() + temp_len, &temp_len);

    // Free the context and return the plaintext.
    openssl::EVP_CIPHER_CTX_free(ctx);
    return pt;
}
