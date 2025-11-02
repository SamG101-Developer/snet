export module snet.manager.key_manager;
import std;
import serex.serialize;

import snet.crypt.bytes;
import snet.credentials.key_store_data;
import snet.credentials.keyring;
import snet.utils.encoding;


export namespace snet::managers::keys {
    auto get_info(
        crypt::bytes::RawBytes const &hashed_username,
        crypt::bytes::SecureBytes const &hashed_password)
        -> std::unique_ptr<credentials::KeyStoreData>;

    auto set_info(
        credentials::KeyStoreData &&key_info)
        -> void;

    auto has_info(
        crypt::bytes::RawBytes const &hashed_username,
        crypt::bytes::SecureBytes const &hashed_password)
        -> bool;

    auto del_info(
        crypt::bytes::RawBytes const &hashed_username)
        -> void;
}


auto snet::managers::keys::get_info(
    crypt::bytes::RawBytes const &hashed_username,
    crypt::bytes::SecureBytes const &hashed_password)
    -> std::unique_ptr<credentials::KeyStoreData> {
    const auto serialized = credentials::keyring::get_password(hashed_username, hashed_password);
    auto on_stack = serex::load<credentials::KeyStoreData>(serialized);
    return std::make_unique<credentials::KeyStoreData>(std::move(on_stack));
}


auto snet::managers::keys::set_info(
    credentials::KeyStoreData &&key_info)
    -> void {
    const auto serialized = serex::save(key_info);
    credentials::keyring::set_password(key_info.hashed_username, key_info.hashed_password, serialized);
}


auto snet::managers::keys::has_info(
    crypt::bytes::RawBytes const &hashed_username,
    crypt::bytes::SecureBytes const &hashed_password)
    -> bool {
    const auto serialized = credentials::keyring::get_password(hashed_username, hashed_password);
    return not serialized.empty();
}


auto snet::managers::keys::del_info(
    crypt::bytes::RawBytes const &hashed_username)
    -> void {
    credentials::keyring::del_password(hashed_username);
}
