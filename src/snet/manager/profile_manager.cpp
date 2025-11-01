module;

#include <genex/to_container.hpp>
#include <genex/algorithms/contains.hpp>
#include <genex/algorithms/max_element.hpp>
#include <genex/algorithms/min_element.hpp>
#include <genex/views/iota.hpp>
#include <genex/views/remove_if.hpp>

export module snet.manager.profile_manager;
import json;
import openssl;
import spdlog;
import std;

import snet.constants;
import snet.credentials.key_store_data;
import snet.credentials.keyring;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.hash;
import snet.manager.key_manager;
import snet.utils.files;
import snet.utils.encoding;


export namespace snet::managers::profile {
    auto create_profile(
        std::string const &username,
        std::string const &password)
        -> void;

    auto delete_profile(
        std::string const &username,
        std::string const &password)
        -> void;

    auto validate_profile(
        std::string const &username,
        std::string const &password)
        -> std::optional<std::tuple<crypt::bytes::RawBytes, crypt::bytes::RawBytes, std::uint16_t>>;

    auto list_usernames()
        -> std::vector<std::string>;

    auto generate_profile_cert(
        crypt::bytes::RawBytes const &hashed_username,
        crypt::bytes::RawBytes const &hashed_password,
        crypt::bytes::RawBytes const &identifier,
        openssl::EVP_PKEY *ssk,
        std::uint16_t port)
        -> void;

    auto load_current_profiles()
        -> nlohmann::json;

    auto has_password(
        std::string const &username)
        -> bool;
}


auto snet::managers::profile::create_profile(
    std::string const &username,
    std::string const &password)
    -> void {
    // Hash the username and password.
    auto hashed_username = crypt::hash::sha3_256(utils::encode_string(username));
    auto hashed_password = crypt::hash::sha3_256(utils::encode_string(password));
    auto current_profiles = load_current_profiles();

    // Check if the username already exists.
    if (current_profiles.contains(username)) {
        spdlog::error(std::format("Profile creation failed: username '{}' already exists.", username));
        return;
    }

    // Get the next available port from the current profiles.
    auto ports = std::set<std::uint16_t>{};
    for (const auto &entry : current_profiles.items()) {
        ports.insert(entry.value().at("port").get<std::uint16_t>());
    }
    if (ports.empty()) { ports.insert(40'000); }
    const auto port = genex::algorithms::min_element(
        genex::views::iota(genex::algorithms::min_element(ports), static_cast<std::uint16_t>(genex::algorithms::max_element(ports) + 2))
        | genex::views::remove_if([&ports](auto &&x) { return ports.contains(x); })
        | genex::to<std::vector>());

    // Generate the profile information for the user.
    const auto profile_entry = nlohmann::json{
        {"username", username},
        {"hashed_username", utils::to_hex(hashed_username)},
        {"hashed_password", utils::to_hex(hashed_password)},
        {"port", port}
    };
    current_profiles[username] = profile_entry;
    utils::write_file(constants::PROFILE_FILE, current_profiles.dump(4));

    // Create the profile cache directory if it doesn't exist.
    utils::write_file(constants::PROFILE_CACHE_DIR / (utils::to_hex(hashed_username) + ".json"), nlohmann::json::object().dump(4));

    // Key and certificate information, and set information into the keyring.
    const auto ssk = crypt::asymmetric::generate_sig_keypair();
    const auto identifier = crypt::hash::sha3_256(crypt::asymmetric::serialize_public(ssk));
    generate_profile_cert(hashed_username, hashed_password, identifier, ssk, port);
}


auto snet::managers::profile::delete_profile(
    std::string const &username,
    std::string const &password)
    -> void {
    // Hash the username and password.
    auto hashed_username = crypt::hash::sha3_256(utils::encode_string(username));
    auto current_profiles = load_current_profiles();
    if (not validate_profile(username, password).has_value()) { return; }

    // Delete the profile from the profiles file.
    current_profiles.erase(username);
    utils::write_file(constants::PROFILE_FILE, current_profiles.dump(4));

    // Delete the profile cache file.
    std::filesystem::remove(constants::PROFILE_CACHE_DIR / (utils::to_hex(hashed_username) + ".json"));
}


auto snet::managers::profile::validate_profile(
    std::string const &username,
    std::string const &password)
    -> std::optional<std::tuple<crypt::bytes::RawBytes, crypt::bytes::RawBytes, std::uint16_t>> {
    // Hash the username and password.
    auto hashed_username = crypt::hash::sha3_256(utils::encode_string(username));
    auto hashed_password = crypt::hash::sha3_256(utils::encode_string(password));
    auto current_profiles = load_current_profiles();

    // Check if the username exists.
    if (not current_profiles.contains(username)) {
        spdlog::error(std::format("Profile validation failed: username '{}' does not exist.", username));
        return std::nullopt;
    }

    // Check if the password matches.
    const auto stored_hashed_password = utils::from_hex(current_profiles.at(username).at("hashed_password").get<std::string>());
    if (stored_hashed_password != hashed_password) {
        spdlog::error(std::format("Profile validation failed: incorrect password for username '{}'.", username));
        return std::nullopt;
    }

    // Create the cache if it doesn't exist.
    const auto cache_path = constants::PROFILE_CACHE_DIR / (utils::to_hex(hashed_username) + ".json");
    if (not std::filesystem::exists(cache_path)) {
        utils::write_file(cache_path, nlohmann::json::object().dump(4));
    }

    // Return the profile information.
    const auto port = current_profiles.at(username).at("port").get<std::uint16_t>();
    return {std::make_tuple(hashed_username, hashed_password, port)};
}


auto snet::managers::profile::list_usernames()
    -> std::vector<std::string> {
    auto current_profiles = load_current_profiles();
    auto usernames = std::vector<std::string>{};
    for (const auto &entry : current_profiles.items()) {
        const auto username = std::string(entry.key());
        auto prefix = std::string(has_password(username) ? "🔒" : "🔓");
        usernames.push_back(prefix.append(username));
    }
    return usernames;
}


auto snet::managers::profile::generate_profile_cert(
    crypt::bytes::RawBytes const &hashed_username,
    crypt::bytes::RawBytes const &hashed_password,
    crypt::bytes::RawBytes const &identifier,
    openssl::EVP_PKEY *ssk,
    const std::uint16_t port)
    -> void {
    // Generate the certificate signing request.
    const auto cert = crypt::certificate::create_self_signed_certificate(ssk);
    auto key_info = credentials::KeyStoreData(
        identifier, crypt::asymmetric::serialize_private(ssk), crypt::asymmetric::serialize_public(ssk),
        crypt::certificate::serialize_certificate(cert), hashed_username, hashed_password, port);
    keys::set_info(std::move(key_info));
}


auto snet::managers::profile::load_current_profiles()
    -> nlohmann::json {
    const auto profile_info = utils::read_file(constants::PROFILE_FILE);
    return nlohmann::json::parse(profile_info);
}


auto snet::managers::profile::has_password(
    std::string const &username)
    -> bool {
    const auto current_profiles = load_current_profiles();
    const auto hashed_empty_password = crypt::hash::sha3_256(utils::encode_string(""));
    const auto stored_hashed_password = utils::from_hex(current_profiles.at(username).at("hashed_password").get<std::string>());
    return stored_hashed_password != hashed_empty_password;
}
