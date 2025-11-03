module;

#include <genex/to_container.hpp>
#include <genex/actions/shuffle.hpp>
#include <genex/algorithms/contains.hpp>
#include <genex/algorithms/max_element.hpp>
#include <genex/algorithms/min_element.hpp>
#include <genex/views/iota.hpp>
#include <genex/views/map.hpp>
#include <genex/views/remove_if.hpp>
#include <genex/views/transform.hpp>

export module snet.manager.ds_manager;
import std;
import openssl;
import json;
import spdlog;

import snet.constants;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.hash;
import snet.manager.profile_manager;
import snet.net.address;
import snet.utils.files;
import snet.utils.encoding;


export namespace snet::managers::ds {
    auto create_directory_profile(std::string const &username)
        -> bool;

    auto get_random_directory_profile(std::vector<std::string> const &exclude)
        -> std::tuple<std::string, std::string, std::uint16_t, crypt::bytes::RawBytes, crypt::bytes::RawBytes>;

    auto validate_directory_profile(std::string const &username)
        -> std::optional<std::tuple<crypt::bytes::RawBytes, crypt::bytes::SecureBytes, std::uint16_t, crypt::bytes::RawBytes, openssl::EVP_PKEY*>>;

    auto load_directory_profiles()
        -> nlohmann::json;
}


auto snet::managers::ds::create_directory_profile(
    std::string const &username)
    -> bool {
    // Generate a static keypair and get the address of the current machine (internal ip).
    const auto ssk = crypt::asymmetric::generate_sig_keypair();
    const auto addr = net::get_private_ipv4_address();

    // Check the current directory services for the name.
    auto ds_json = ( {
        auto ds_str = utils::read_file(constants::DIRECTORY_SERVICE_PUBLIC_FILE);
        nlohmann::json::parse(ds_str);
    });
    if (ds_json.contains(username)) { return false; }

    // Get the next available port from the current directory services.
    auto ports = std::set<std::uint16_t>{};
    for (const auto &entry : ds_json.items()) {
        ports.insert(entry.value().at("port").get<std::uint16_t>());
    }
    if (ports.empty()) { ports.emplace(30'000); }
    const auto port = genex::algorithms::min_element(
        genex::views::iota(genex::algorithms::min_element(ports), static_cast<std::uint16_t>(genex::algorithms::max_element(ports) + 2))
        | genex::views::remove_if([&ports](auto &&x) { return ports.contains(x); })
        | genex::to<std::vector>());

    // Generate the public information for the directory service.
    auto spk_serialized = crypt::asymmetric::serialize_public(ssk);
    auto ssk_serialized = crypt::asymmetric::serialize_private(ssk);
    auto identifier = crypt::hash::sha3_256(spk_serialized);
    const auto public_directory_service_entry = nlohmann::json{
        {"name", username},
        {"identifier", utils::to_hex(identifier)},
        {"public_key", utils::to_hex(spk_serialized)},
        {"address", addr},
        {"port", port}
    };

    // Generate the private information for the directory service.
    auto private_directory_service_entry = public_directory_service_entry;
    private_directory_service_entry.emplace("secret_key", utils::to_hex(ssk_serialized));

    // Update the directory service files.
    ds_json[username] = public_directory_service_entry;
    utils::write_file(constants::DIRECTORY_SERVICE_PUBLIC_FILE, ds_json.dump());
    utils::write_file(constants::DIRECTORY_SERVICE_PRIVATE_DIR / (username + ".json"), nlohmann::json(private_directory_service_entry).dump(4));
    utils::write_file(constants::DIRECTORY_SERVICE_NODE_CACHE_DIR / (username + ".json"), nlohmann::json::object().dump(4));

    // Make DIRECTORY_SERVICE_PRIVATE_FILE % name readonly with 0o400 permissions.
    auto path = constants::DIRECTORY_SERVICE_PRIVATE_DIR / (username + ".json");
    std::filesystem::permissions(path, std::filesystem::perms::owner_read, std::filesystem::perm_options::replace);

    // Key and certificate information, and set information into the keyring.
    auto info = validate_directory_profile(username);
    if (not info.has_value()) { return false; }
    auto [hashed_username, hashed_password, _, _, _] = std::move(*info);
    profile::generate_profile_cert(hashed_username, hashed_password, identifier, ssk, port);
    return true;
}


auto snet::managers::ds::get_random_directory_profile(
    std::vector<std::string> const &exclude)
    -> std::tuple<std::string, std::string, std::uint16_t, crypt::bytes::RawBytes, crypt::bytes::RawBytes> {
    // Load the directory profiles.
    const auto ds_json = load_directory_profiles();

    // Filter out the excluded usernames.
    auto available_profiles = ds_json.items()
        | genex::views::transform([](auto const &item) { return std::string(item.key()); })
        | genex::views::remove_if([&exclude](auto &&x) { return genex::algorithms::contains(exclude, x); })
        | genex::to<std::vector>();
    available_profiles |= genex::actions::shuffle(genex::actions::detail::default_random);

    // Select a random profile from the available ones.
    if (available_profiles.empty()) {
        throw std::runtime_error("No available directory profiles.");
    }
    const auto &entry = available_profiles.front();

    // Extract the profile information.
    const auto &profile_json = ds_json.at(entry);
    const auto name = profile_json.at("name").get<std::string>();
    const auto address = profile_json.at("address").get<std::string>();
    const auto port = profile_json.at("port").get<std::uint16_t>();
    const auto identifier = utils::from_hex(profile_json.at("identifier").get<std::string>());
    const auto public_key = utils::from_hex(profile_json.at("public_key").get<std::string>());
    return {name, address, port, identifier, public_key};
}


auto snet::managers::ds::validate_directory_profile(
    std::string const &username)
    -> std::optional<std::tuple<crypt::bytes::RawBytes, crypt::bytes::SecureBytes, std::uint16_t, crypt::bytes::RawBytes, openssl::EVP_PKEY*>> {
    // Hash the username and password.
    const auto hashed_username = crypt::hash::sha3_256(utils::encode_string(username));
    const auto hashed_password = crypt::hash::sha3_256<true>({});
    const auto current_profiles = load_directory_profiles();

    // Check if the username exists.
    if (not std::filesystem::exists(constants::DIRECTORY_SERVICE_PRIVATE_DIR / (username + ".json"))) {
        spdlog::error(std::format("Directory profile '{}' does not exist", username));
        return std::nullopt;
    }
    if (not std::filesystem::exists(constants::DIRECTORY_SERVICE_NODE_CACHE_DIR / (username + ".json"))) {
        spdlog::warn(std::format("Directory profile '{}' cache file missing; recreating.", username));
        utils::write_file(constants::DIRECTORY_SERVICE_NODE_CACHE_DIR / (username + ".json"), nlohmann::json::object().dump(4));
    }

    // Load the keys.
    const auto priv_info = utils::read_file(constants::DIRECTORY_SERVICE_PRIVATE_DIR / (username + ".json"));
    const auto priv_json = nlohmann::json::parse(priv_info);
    const auto identifier = utils::from_hex(priv_json.at("identifier").get<std::string>());
    const auto port = priv_json.at("port").get<std::uint16_t>();
    const auto ssk_serialized = utils::from_hex<true>(priv_json.at("secret_key").get<std::string>());
    auto ssk = crypt::asymmetric::load_private_key_sig(ssk_serialized);

    // Return the profile information.
    return {std::make_tuple(hashed_username, hashed_password, port, identifier, ssk)};
}


auto snet::managers::ds::load_directory_profiles()
    -> nlohmann::json {
    // Load and parse the directory profiles JSON file.
    const auto ds_str = utils::read_file(constants::DIRECTORY_SERVICE_PUBLIC_FILE);
    return nlohmann::json::parse(ds_str);
}
