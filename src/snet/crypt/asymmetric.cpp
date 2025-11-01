export module snet.crypt.asymmetric;
import openssl;
import spdlog;
import std;

import snet.crypt.bytes;
import snet.crypt.timestamp;


constexpr auto SIG_SCHEME = "ML-DSA-87";
constexpr auto KEM_SCHEME = "ML-KEM-1024";

export namespace snet::crypt::asymmetric {
    struct CipherText {
        bytes::RawBytes ct;
        bytes::SecureBytes ss;
    };

    struct AAD {
        AAD(const bytes::RawBytes &s_id, const bytes::RawBytes &t_id);
        std::unique_ptr<openssl::OSSL_PARAM[]> params;
        std::unique_ptr<std::int64_t> timestamp;
    };

    auto generate_sig_keypair()
        -> openssl::EVP_PKEY*;

    auto generate_kem_keypair()
        -> openssl::EVP_PKEY*;

    auto sign(
        openssl::EVP_PKEY *sk,
        const bytes::ViewBytes &msg,
        const AAD *aad) -> bytes::RawBytes;

    auto verify(
        openssl::EVP_PKEY *pk,
        bytes::ViewBytes sig,
        bytes::ViewBytes msg,
        const AAD *aad,
        bytes::ViewBytes exp_msg = {},
        const AAD *exp_aad = nullptr,
        std::uint32_t tol = timestamp::TS_TOLERANCE_MESSAGE_SIGNATURE)
        -> bool;

    auto encaps(
        openssl::EVP_PKEY *pk)
        -> CipherText;

    auto decaps(
        openssl::EVP_PKEY *sk,
        bytes::ViewBytes ct)
        -> bytes::SecureBytes;

    auto create_aad(
        bytes::RawBytes const &s_id,
        bytes::RawBytes const &t_id)
        -> std::unique_ptr<AAD>;

    auto serialize_public(const openssl::EVP_PKEY *k)
        -> bytes::RawBytes;

    auto serialize_private(const openssl::EVP_PKEY *k)
        -> bytes::SecureBytes;

    auto load_kem_public_key(
        const bytes::RawBytes &pk_bytes)
        -> openssl::EVP_PKEY*;

    auto load_kem_private_key(
        const bytes::SecureBytes &sk_bytes)
        -> openssl::EVP_PKEY*;

    auto load_sig_public_key(
        const bytes::RawBytes &pk_bytes)
        -> openssl::EVP_PKEY*;

    auto load_sig_private_key(
        const bytes::SecureBytes &sk_bytes)
        -> openssl::EVP_PKEY*;
}


snet::crypt::asymmetric::AAD::AAD(
    const bytes::RawBytes &s_id,
    const bytes::RawBytes &t_id) {
    this->params = std::make_unique<openssl::OSSL_PARAM[]>(4);
    this->timestamp = std::make_unique<std::int64_t>(timestamp::timestamp());

    this->params[0] = openssl::OSSL_PARAM_construct_octet_string("session-token", (void*)s_id.data(), s_id.size());
    this->params[1] = openssl::OSSL_PARAM_construct_octet_string("target-id", (void*)t_id.data(), t_id.size());
    this->params[2] = openssl::OSSL_PARAM_construct_int64("timestamp", this->timestamp.get());
    this->params[3] = openssl::OSSL_PARAM_construct_end();
}


auto snet::crypt::asymmetric::generate_sig_keypair()
    -> openssl::EVP_PKEY* {
    const auto key = openssl::EVP_PKEY_Q_keygen(nullptr, nullptr, SIG_SCHEME);
    return key;
}


auto snet::crypt::asymmetric::generate_kem_keypair()
    -> openssl::EVP_PKEY* {
    const auto key = openssl::EVP_PKEY_Q_keygen(nullptr, nullptr, KEM_SCHEME);
    return key;
}


auto snet::crypt::asymmetric::sign(
    openssl::EVP_PKEY *sk,
    const bytes::ViewBytes &msg,
    const AAD *aad)
    -> bytes::RawBytes {
    // Create the context, algorithm and initialize the signing.
    auto sig_len = static_cast<std::size_t>(0);
    const auto sctx = openssl::EVP_PKEY_CTX_new_from_pkey(nullptr, sk, nullptr);
    const auto alg = openssl::EVP_SIGNATURE_fetch(nullptr, SIG_SCHEME, nullptr);
    openssl::EVP_PKEY_sign_message_init(sctx, alg, aad->params.get());
    openssl::EVP_PKEY_sign(sctx, nullptr, &sig_len, msg.data(), msg.size());

    // Resize the signature buffer and sign the message into the buffer.
    auto sig = bytes::RawBytes(sig_len);
    openssl::EVP_PKEY_sign(sctx, sig.data(), &sig_len, msg.data(), msg.size());
    openssl::EVP_SIGNATURE_free(alg);
    openssl::EVP_PKEY_CTX_free(sctx);

    // Return the signature.
    return sig;
}


auto snet::crypt::asymmetric::verify(
    openssl::EVP_PKEY *pk,
    const bytes::ViewBytes sig,
    const bytes::ViewBytes msg,
    const AAD *aad,
    const bytes::ViewBytes exp_msg,
    const AAD *exp_aad,
    const std::uint32_t tol)
    -> bool {

    // Create the context, algorithm and initialize the verification.
    const auto vctx = openssl::EVP_PKEY_CTX_new_from_pkey(nullptr, pk, nullptr);
    const auto alg = openssl::EVP_SIGNATURE_fetch(nullptr, SIG_SCHEME, nullptr);
    openssl::EVP_PKEY_verify_message_init(vctx, alg, aad->params.get());

    // Verify the signature.
    if (openssl::EVP_PKEY_verify(vctx, sig.data(), sig.size(), msg.data(), msg.size()) != 1) {
        openssl::EVP_PKEY_CTX_free(vctx);
        spdlog::warn("Signature verification failed");
        return false;
    }

    // Check the aad and exp_aad's "sid".
    if (aad->params[0].data_size != exp_aad->params[0].data_size or
        openssl::CRYPTO_memcmp(aad->params[0].data, exp_aad->params[0].data, aad->params[0].data_size) != 0) {
        openssl::EVP_PKEY_CTX_free(vctx);
        spdlog::warn("AAD 'sid' mismatch");
        return false;
    }

    // Check the aad and exp_aad's "tid".
    if (aad->params[1].data_size != exp_aad->params[1].data_size or
        openssl::CRYPTO_memcmp(aad->params[1].data, exp_aad->params[1].data, aad->params[1].data_size) != 0) {
        openssl::EVP_PKEY_CTX_free(vctx);
        spdlog::warn("AAD 'tid' mismatch");
        return false;
    }

    // Check the aad and exp_aad's "timestamp".
    auto timestamp = static_cast<std::int64_t>(0);
    const auto timestamp_param = openssl::OSSL_PARAM_locate(aad->params.get(), "timestamp");
    openssl::OSSL_PARAM_get_int64(timestamp_param, &timestamp);

    if (aad->params[2].data_size != timestamp::TS_BYTES_LEN or not timestamp::timestamp_in_tolerance(timestamp, tol)) {
        openssl::EVP_PKEY_CTX_free(vctx);
        spdlog::warn("Timestamp mismatch or out of tolerance");
        return false;
    }

    // Check the message matches what's expected (if a message is expected).
    if (not exp_msg.empty() and
        (exp_msg.size() != msg.size() or not openssl::CRYPTO_memcmp(msg.data(), exp_msg.data(), msg.size()) == 0)) {
        spdlog::warn("Message mismatch");
        return false;
    }

    return true;
}


auto snet::crypt::asymmetric::encaps(
    openssl::EVP_PKEY *pk)
    -> CipherText {
    // Create the context and default lengths.
    auto ss_len = static_cast<std::size_t>(0);
    auto ct_len = static_cast<std::size_t>(0);
    const auto ectx = openssl::EVP_PKEY_CTX_new_from_pkey(nullptr, pk, nullptr);

    // Initialize the encapsulation and get the lengths of the shared secret and ciphertext.
    openssl::EVP_PKEY_encapsulate_init(ectx, nullptr);
    openssl::EVP_PKEY_encapsulate(ectx, nullptr, &ct_len, nullptr, &ss_len);
    auto ss = bytes::SecureBytes(ss_len);
    auto ct = bytes::RawBytes(ct_len);

    // Encapsulate the shared secret and ciphertext.
    openssl::EVP_PKEY_encapsulate(ectx, ct.data(), &ct_len, ss.data(), &ss_len);
    openssl::EVP_PKEY_CTX_free(ectx);

    // Return the ciphertext and shared secret encapsulated in a CipherText structure.
    return CipherText(std::move(ct), std::move(ss));
}


auto snet::crypt::asymmetric::decaps(
    openssl::EVP_PKEY *sk,
    const bytes::ViewBytes ct)
    -> bytes::SecureBytes {
    // Create the context and get the lengths of the shared secret and ciphertext.
    auto ss_len = static_cast<std::size_t>(0);
    const auto ct_len = ct.size();
    const auto dctx = openssl::EVP_PKEY_CTX_new_from_pkey(nullptr, sk, nullptr);

    // Initialize the decapsulation and get the length of the shared secret.
    openssl::EVP_PKEY_decapsulate_init(dctx, nullptr);
    openssl::EVP_PKEY_decapsulate(dctx, nullptr, &ss_len, ct.data(), ct_len);
    auto ss = bytes::SecureBytes(ss_len);

    // Decapsulate the shared secret from the ciphertext.
    openssl::EVP_PKEY_decapsulate(dctx, ss.data(), &ss_len, ct.data(), ct_len);
    openssl::EVP_PKEY_CTX_free(dctx);

    // Return the shared secret.
    return ss;
}


auto snet::crypt::asymmetric::create_aad(
    bytes::RawBytes const &s_id,
    bytes::RawBytes const &t_id)
    -> std::unique_ptr<AAD> {
    // Create the AAD parameters for session ID, timestamp ID and current timestamp.
    return std::make_unique<AAD>(s_id, t_id);
}


auto snet::crypt::asymmetric::serialize_public(
    const openssl::EVP_PKEY *k)
    -> bytes::RawBytes {
    // Get the length of the public key in bytes.
    const auto pk_len = openssl::i2d_PUBKEY(k, nullptr);
    auto pk = bytes::RawBytes(pk_len);

    // Convert the public key to bytes.
    auto pk_ptr = pk.data();
    openssl::i2d_PUBKEY(k, &pk_ptr);
    return pk;
}


auto snet::crypt::asymmetric::serialize_private(
    const openssl::EVP_PKEY *k)
    -> bytes::SecureBytes {

    // Get the length of the private key in bytes.
    const auto sk_len = openssl::i2d_PrivateKey(k, nullptr);
    auto sk = bytes::SecureBytes(sk_len);

    // Convert the private key to bytes.
    auto sk_ptr = sk.data();
    openssl::i2d_PrivateKey(k, &sk_ptr);
    return sk;
}


auto snet::crypt::asymmetric::load_kem_public_key(
    const bytes::RawBytes &pk_bytes)
    -> openssl::EVP_PKEY* {
    // Create a new public key from the bytes.
    auto pk = openssl::EVP_PKEY_new();
    auto pk_d = pk_bytes.data();
    openssl::d2i_PUBKEY(&pk, &pk_d, static_cast<long>(pk_bytes.size()));
    return pk;
}


auto snet::crypt::asymmetric::load_kem_private_key(
    const bytes::SecureBytes &sk_bytes)
    -> openssl::EVP_PKEY* {
    // Create a new private key from the bytes.
    auto sk = openssl::EVP_PKEY_new();
    auto sk_d = sk_bytes.data();
    openssl::d2i_PrivateKey(openssl::OBJ_ln2nid(KEM_SCHEME), &sk, &sk_d, static_cast<long>(sk_bytes.size()));
    return sk;
}


auto snet::crypt::asymmetric::load_sig_public_key(
    const bytes::RawBytes &pk_bytes)
    -> openssl::EVP_PKEY* {
    // Create a new public key from the bytes.
    auto pk = openssl::EVP_PKEY_new();
    auto pk_d = pk_bytes.data();
    openssl::d2i_PUBKEY(&pk, &pk_d, static_cast<long>(pk_bytes.size()));
    return pk;
}


auto snet::crypt::asymmetric::load_sig_private_key(
    const bytes::SecureBytes &sk_bytes)
    -> openssl::EVP_PKEY* {
    // Create a new private key from the bytes.
    auto sk = openssl::EVP_PKEY_new();
    auto sk_d = sk_bytes.data();
    openssl::d2i_PrivateKey(openssl::OBJ_ln2nid(SIG_SCHEME), &sk, &sk_d, static_cast<long>(sk_bytes.size()));
    return sk;
}
