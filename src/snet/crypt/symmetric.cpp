export module snet.crypt.symmetric;
import openssl;
import serex.serialize;
import std;

import snet.crypt.bytes;


export namespace snet::crypt::symmetric {
    constexpr auto KEY_LEN = 32;
    constexpr auto IV_LEN = 12;
    constexpr auto TAG_LEN = 16;
    constexpr auto XTS_TWEAK_LEN = 16;

    struct CipherText {
        bytes::RawBytes ct;
        bytes::RawBytes iv;
        bytes::RawBytes tag;

        auto serialize(serex::Archive &ar) -> void {
            serex::push_into_archive(ar, ct, iv, tag);
        }
    };

    auto generate_key()
        -> bytes::SecureBytes;

    auto encrypt(
        const bytes::ViewBytes &key,
        const bytes::ViewBytes &pt)
        -> CipherText;

    auto encrypt_for_disk(
        const bytes::ViewBytes &key,
        const bytes::ViewBytes &pt)
        -> CipherText;

    auto decrypt(
        const bytes::ViewBytes &key,
        const bytes::ViewBytes &ct,
        const bytes::ViewBytes &iv,
        const bytes::ViewBytes &tag)
        -> bytes::SecureBytes;

    auto decrypt_for_disk(
        const bytes::ViewBytes &key,
        const bytes::ViewBytes &ct,
        const bytes::ViewBytes &iv)
        -> bytes::SecureBytes;
}


auto snet::crypt::symmetric::generate_key()
    -> bytes::SecureBytes {
    // Generate a random key of the specified length.
    auto key = bytes::SecureBytes(KEY_LEN);
    openssl::RAND_priv_bytes(key.data(), KEY_LEN);
    return key;
}


auto snet::crypt::symmetric::encrypt(
    const bytes::ViewBytes &key,
    const bytes::ViewBytes &pt)
    -> CipherText {
    // Create the initialization vector.
    auto iv = bytes::RawBytes(IV_LEN);
    openssl::RAND_priv_bytes(iv.data(), IV_LEN);

    // Create the context and set the IV length.
    const auto ctx = openssl::EVP_CIPHER_CTX_new();
    if (openssl::EVP_EncryptInit_ex(ctx, openssl::EVP_aes_256_ocb(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to initialize encryption context");
    }
    if (openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_SET_IVLEN, IV_LEN, nullptr) != 1) {
        throw std::runtime_error("Failed to set IV length");
    }
    if (openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_SET_TAG, TAG_LEN, nullptr) != 1) {
        throw std::runtime_error("Failed to set tag length");
    }
    if (openssl::EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw std::runtime_error("Failed to set key and IV");
    }
    if (openssl::EVP_CIPHER_CTX_set_key_length(ctx, KEY_LEN) != 1) {
        throw std::runtime_error("Failed to set key length");
    }

    // Encrypt the plaintext.
    auto ct = bytes::RawBytes(pt.size());
    auto temp_len = 0;
    if (openssl::EVP_EncryptUpdate(ctx, ct.data(), &temp_len, pt.data(), pt.size()) != 1) {
        throw std::runtime_error("Failed to encrypt plaintext");
    }
    if (openssl::EVP_EncryptFinal_ex(ctx, ct.data() + temp_len, &temp_len) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }

    // Generate the authentication tag.
    auto tag = bytes::RawBytes(TAG_LEN);
    if (openssl::EVP_CIPHER_CTX_ctrl(ctx, openssl::EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag.data()) != 1) {
        throw std::runtime_error("Failed to get authentication tag");
    }
    openssl::EVP_CIPHER_CTX_free(ctx);

    // Return the ciphertext, IV and tag encapsulated in a CipherText structure.
    return CipherText(std::move(ct), std::move(iv), std::move(tag));
}


auto snet::crypt::symmetric::encrypt_for_disk(
    const bytes::ViewBytes &key,
    const bytes::ViewBytes &pt)
    -> CipherText {
    // For disk encryption, we use AES in XTS mode.
    // Create the tweak.
    auto iv = bytes::RawBytes(XTS_TWEAK_LEN);
    openssl::RAND_priv_bytes(iv.data(), XTS_TWEAK_LEN);

    // Create the context.
    const auto ctx = openssl::EVP_CIPHER_CTX_new();
    openssl::EVP_EncryptInit_ex(ctx, openssl::EVP_aes_256_xts(), nullptr, key.data(), iv.data());
    openssl::EVP_CIPHER_CTX_set_key_length(ctx, KEY_LEN);

    // Encrypt the plaintext.
    auto ct = bytes::RawBytes(pt.size());
    auto temp_len = 0;
    openssl::EVP_EncryptUpdate(ctx, ct.data(), &temp_len, pt.data(), pt.size());
    openssl::EVP_EncryptFinal_ex(ctx, ct.data() + temp_len, &temp_len);

    // Free the context and return the ciphertext and tweak (IV).
    openssl::EVP_CIPHER_CTX_free(ctx);
    return CipherText(std::move(ct), std::move(iv), {});
}


auto snet::crypt::symmetric::decrypt(
    const bytes::ViewBytes &key,
    const bytes::ViewBytes &ct,
    const bytes::ViewBytes &iv,
    const bytes::ViewBytes &tag)
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


auto snet::crypt::symmetric::decrypt_for_disk(
    const bytes::ViewBytes &key,
    const bytes::ViewBytes &ct,
    const bytes::ViewBytes &iv)
    -> bytes::SecureBytes {
    // For disk decryption, we use AES in XTS mode.
    // Create the context.
    const auto ctx = openssl::EVP_CIPHER_CTX_new();
    openssl::EVP_DecryptInit_ex(ctx, openssl::EVP_aes_256_xts(), nullptr, key.data(), iv.data());
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
