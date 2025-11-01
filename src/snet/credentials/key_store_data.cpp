export module snet.credentials.key_store_data;
import std;
import serex.serialize;

import snet.crypt.bytes;


export namespace snet::credentials {
    struct KeyStoreData {
        crypt::bytes::RawBytes identifier;
        crypt::bytes::SecureBytes secret_key;
        crypt::bytes::RawBytes public_key;
        crypt::bytes::RawBytes certificate;
        crypt::bytes::RawBytes hashed_username;
        crypt::bytes::SecureBytes hashed_password;
        std::uint16_t port;

        template <typename Ar>
        auto serialize(Ar &ar) -> void {
            ar & identifier & secret_key & public_key & certificate & hashed_username & hashed_password & port;
        }
    };
}
