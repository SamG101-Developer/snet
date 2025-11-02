export module snet.credentials.key_store_data;
import std;
import serex.serialize;

import snet.crypt.bytes;


export namespace snet::credentials {
    struct KeyStoreData {
        KeyStoreData() = default;
        KeyStoreData(const KeyStoreData &) = delete;
        KeyStoreData(KeyStoreData &&) noexcept = default;
        auto operator=(const KeyStoreData &) -> KeyStoreData& = delete;
        auto operator=(KeyStoreData &&) noexcept -> KeyStoreData& = default;
        ~KeyStoreData() = default;

        KeyStoreData(
            crypt::bytes::RawBytes identifier,
            crypt::bytes::SecureBytes secret_key,
            crypt::bytes::RawBytes public_key,
            crypt::bytes::RawBytes certificate,
            crypt::bytes::RawBytes hashed_username,
            crypt::bytes::SecureBytes hashed_password,
            const std::uint16_t port) :
            identifier(std::move(identifier)),
            secret_key(std::move(secret_key)),
            public_key(std::move(public_key)),
            certificate(std::move(certificate)),
            hashed_username(std::move(hashed_username)),
            hashed_password(std::move(hashed_password)),
            port(port) {
        }

        crypt::bytes::RawBytes identifier;
        crypt::bytes::SecureBytes secret_key;
        crypt::bytes::RawBytes public_key;
        crypt::bytes::RawBytes certificate;
        crypt::bytes::RawBytes hashed_username;
        crypt::bytes::SecureBytes hashed_password;
        std::uint16_t port = 0;

        auto serialize(serex::Archive &ar) -> void {
            serex::push_into_archive(ar, identifier, secret_key, public_key, certificate, hashed_username, hashed_password, port);
        }
    };
}
