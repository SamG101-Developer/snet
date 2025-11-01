export module snet.manager.key_manager;
import std;
import serex.serialize;

import snet.crypt.bytes;
import snet.credentials.key_store_data;
import snet.credentials.keyring;
import snet.utils.encoding;


export namespace snet::managers::keys {
    auto get_info(
        crypt::bytes::RawBytes hashed_username)
        -> std::optional<credentials::KeyStoreData>;

    auto set_info(
        credentials::KeyStoreData &&key_info)
        -> void;

    auto has_info(
        crypt::bytes::RawBytes hashed_username)
        -> bool;

    auto del_info(
        crypt::bytes::RawBytes hashed_username)
        -> void;
}


auto snet::managers::keys::get_info(
    crypt::bytes::RawBytes hashed_username)
    -> std::optional<credentials::KeyStoreData> {
    const auto serialized = credentials::keyring::get_password(utils::to_hex(hashed_username));
    const auto info = serex::load<credentials::KeyStoreData>(serialized);
    return {info};
}


auto snet::managers::keys::set_info(
    credentials::KeyStoreData &&key_info)
    -> void {
    const auto serialized = serex::save(key_info);
    credentials::keyring::set_password(utils::to_hex(key_info.hashed_username), serialized);
}


auto snet::managers::keys::has_info(
    crypt::bytes::RawBytes hashed_username)
    -> bool {
    const auto serialized = credentials::keyring::get_password(utils::to_hex(hashed_username));
    return not serialized.empty();
}


auto snet::managers::keys::del_info(
    crypt::bytes::RawBytes hashed_username)
    -> void {
    credentials::keyring::del_password(utils::to_hex(hashed_username));
}
