export module snet.credentials.keyring;
import serex.serialize;
import spdlog;
import std;

import snet.constants;
import snet.crypt.bytes;
import snet.crypt.symmetric;
import snet.crypt.hash;
import snet.utils.encoding;
import snet.utils.files;


export namespace snet::credentials::keyring {
    auto set_password(
        crypt::bytes::RawBytes hashed_username,
        crypt::bytes::SecureBytes hashed_password,
        const std::string_view info)
        -> void {
        // Encrypt "info" based on user and store it in the keyring.
        auto ct = crypt::symmetric::encrypt(hashed_password, utils::encode_string<true>(info));
        const auto serialize = serex::save(ct);
        utils::write_file(constants::KEYRING_DIR / utils::to_hex(hashed_username), serialize);
    }

    auto get_password(
        crypt::bytes::RawBytes hashed_username,
        crypt::bytes::SecureBytes hashed_password)
        -> std::string {
        // Retrieve the encrypted info from the keyring and decrypt it based on user.
        const auto path = constants::KEYRING_DIR / utils::to_hex(hashed_username);
        const auto serialized = utils::decode_bytes(utils::read_file(path));
        const auto [ct, iv, tag] = serex::load<crypt::symmetric::CipherText>(serialized);

        // Decrypt and return the info.
        const auto decrypted = crypt::symmetric::decrypt(hashed_password, ct, iv, tag);
        return utils::decode_bytes(decrypted);
    }

    auto del_password(
        crypt::bytes::RawBytes hashed_username)
        -> bool {
        // Delete the password entry for the user from the keyring.
        const auto path = constants::KEYRING_DIR / utils::to_hex(hashed_username);
        return std::filesystem::remove(path);
    }
}
