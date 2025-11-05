module;
#include <snet/macros.hpp>

#include <genex/actions/remove_if.hpp>
#include <genex/algorithms/contains.hpp>

export module snet.comm_stack.system_layers.layer_d;
import json;
import openssl;
import spdlog;
import serex.serialize;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.system_layers.system_layer_base;
import snet.comm_stack.system_layers.layer_4;
import snet.constants;
import snet.credentials.key_store_data;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.manager.ds_manager;
import snet.net.socket;
import snet.utils.files;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    class LayerD final : SystemLayerBase {
        crypt::bytes::RawBytes m_self_id;
        crypt::bytes::RawBytes m_self_cert;
        bool m_is_directory_service;
        openssl::EVP_PKEY *m_directory_service_ssk;
        std::map<std::tuple<std::string, std::uint16_t>, openssl::EVP_PKEY*> m_directory_service_temp_map = {};
        std::string m_node_cache_file_path;
        Layer4 *m_l4 = nullptr;

    public:
        LayerD(
            credentials::KeyStoreData *self_node_info,
            net::UDPSocket *sock,
            std::string const &directory_service_name,
            openssl::EVP_PKEY *directory_service_ssk,
            Layer4 *l4);

        auto layer_proto_name() -> std::string override {
            return "LayerD";
        }

        auto request_bootstrap()
            -> void;

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req = nullptr)
            -> void;

    private:
        auto load_cache_from_file() const
            -> void;

        auto handle_bootstrap_request(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<LayerD_BootstrapRequest> &&req) const
            -> void;

        auto handle_bootstrap_response(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<LayerD_BootstrapResponse> &&req)
            -> void;
    };
}


snet::comm_stack::layers::LayerD::LayerD(
    credentials::KeyStoreData *self_node_info,
    net::UDPSocket *sock,
    std::string const &directory_service_name,
    openssl::EVP_PKEY *directory_service_ssk,
    Layer4 *l4) :
    SystemLayerBase(self_node_info, sock, utils::create_logger(layer_proto_name())),
    m_self_id(self_node_info->identifier),
    m_self_cert(self_node_info->certificate),
    m_is_directory_service(not directory_service_name.empty()),
    m_directory_service_ssk(directory_service_ssk),
    m_l4(l4) {

    // Set the cache path and load the cache.
    const auto self_id_as_str = utils::to_hex(m_self_node_info->hashed_username);
    m_node_cache_file_path = m_is_directory_service
                                 ? constants::DIRECTORY_SERVICE_NODE_CACHE_DIR / (directory_service_name + ".json")
                                 : constants::PROFILE_CACHE_DIR / (utils::to_hex(m_self_node_info->hashed_username) + ".json");
    load_cache_from_file();
}


auto snet::comm_stack::layers::LayerD::request_bootstrap()
    -> void {
    // Define the exclusion list to prevent duplicates.
    auto exclude = std::vector<std::string>();

    for (auto i = 0; i < 1; ++i) {
        // Choose a random directory service to connect to.
        auto [d_name, d_address, d_port, d_id, d_spk] = managers::ds::get_random_directory_profile(exclude);
        m_directory_service_temp_map[{d_address, d_port}] = crypt::asymmetric::load_public_key_sig(d_spk);
        exclude.push_back(d_name);

        // Create an encrypted connection to the directory service.
        m_logger->info(std::format("Bootstrapping from directory service {}@{}:{}", d_name, d_address, d_port));
        const auto conn = m_l4->connect(d_address, d_port, d_id);

        // Check if the connection couldn't be established.
        if (conn == nullptr) {
            m_logger->warn(std::format("Failed to connect to directory service {}@{}:{}", d_name, d_address, d_port));
            continue;
        }

        // Send the bootstrapping request to the directory service.
        auto req = std::make_unique<LayerD_BootstrapRequest>(m_self_cert, m_self_id);
        send_secure(conn, std::move(req));
    }
}


auto snet::comm_stack::layers::LayerD::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&)
    -> void {
    m_logger->info(std::format(
        "LayerD received request of type {} from {}@{}:{}",
        req->serex_type(), peer_ip, peer_port, utils::to_hex(req->conn_tok)));

    // Map the request type to the appropriate handler.
    MAP_TO_HANDLER(D, LayerD_BootstrapRequest, m_is_directory_service, handle_bootstrap_request);
    MAP_TO_HANDLER(D, LayerD_BootstrapResponse, not m_is_directory_service, handle_bootstrap_response);

    // If no handler matched, log a warning.
    m_logger->warn(std::format(
        "LayerD received invalid request type from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));
}


auto snet::comm_stack::layers::LayerD::load_cache_from_file() const
    -> void {
    // Load the cache from the file.
    const auto current_cache = nlohmann::json::parse(utils::read_file(m_node_cache_file_path));

    // Convert the cache into a vector of tuples for ConnectionCache::cached_nodes.
    for (auto const &cache_entry : current_cache) {
        auto ip_address = cache_entry["address"].get<std::string>();
        auto port = cache_entry["port"].get<std::uint16_t>();
        auto identifier = utils::from_hex(cache_entry["identifier"].get<std::string>());
        ConnectionCache::cached_nodes.emplace_back(ip_address, port, identifier);
    }
}


auto snet::comm_stack::layers::LayerD::handle_bootstrap_request(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<LayerD_BootstrapRequest> &&req) const
    -> void {
    m_logger->info(std::format(
        "LayerD received bootstrap request from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));

    // Get the connection from the cache.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();

    // Cache this node and its associated data.
    ConnectionCache::cached_nodes.emplace_back(peer_ip, peer_port, req->node_id);

    // Chose some random known nodes to send back in the response.
    const auto sample_size = std::min<std::size_t>(5, ConnectionCache::cached_nodes.size());
    auto sampled_nodes = decltype(ConnectionCache::cached_nodes)(sample_size);
    std::ranges::sample(
        ConnectionCache::cached_nodes, std::back_inserter(sampled_nodes),
        static_cast<std::int64_t>(sample_size), std::mt19937{std::random_device{}()});

    // Todo: why is a bugged entry in the cache?
    // Todo: temp patch: remove all entries with port=0
    sampled_nodes |= genex::actions::remove_if([](auto const &entry) { return std::get<1>(entry) == 0; });

    // Print the sampled nodes for debugging.
    for (auto &[ip, port, id] : sampled_nodes) {
        m_logger->info(std::format(
            "LayerD sampled node for bootstrap response: {}@{}:{}",
            ip, port, utils::to_hex(id)));
    }

    const auto serialize = utils::encode_string(serex::save(sampled_nodes));
    const auto aad = crypt::asymmetric::create_aad(req->conn_tok, conn->peer_id);
    const auto sig = crypt::asymmetric::sign(m_directory_service_ssk, serialize, aad.get());

    // Create the response and send it securely.
    auto response = std::make_unique<LayerD_BootstrapResponse>(serialize, sig);
    send_secure(conn, std::move(response));
}


auto snet::comm_stack::layers::LayerD::handle_bootstrap_response(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<LayerD_BootstrapResponse> &&req)
    -> void {
    m_logger->info(std::format(
        "LayerD received bootstrap response from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));

    // Check the signature on the response.
    const auto d_spk = m_directory_service_temp_map[{peer_ip, peer_port}];
    const auto aad = crypt::asymmetric::create_aad(req->conn_tok, m_self_id);
    if (not crypt::asymmetric::verify(d_spk, req->sig, req->node_info, aad.get())) {
        m_logger->warn("LayerD failed to verify bootstrap response signature");
        return;
    }

    // Add the nodes from the response to the cache.
    const auto nodes = serex::load<decltype(ConnectionCache::cached_nodes)>(utils::decode_bytes(req->node_info));
    for (auto const &node : nodes) {
        if (not genex::algorithms::contains(ConnectionCache::cached_nodes, std::get<2>(node), [](auto const &entry) { return std::get<2>(entry); })) {
            ConnectionCache::cached_nodes.emplace_back(node);
        }
    }
    m_logger->info(std::format("LayerD successfully bootstrapped and added {} nodes to cache", nodes.size()));

    // Update the file based cache.
    auto file_data = nlohmann::json::array();
    for (auto &entry : ConnectionCache::cached_nodes) {
        const auto json_entry = nlohmann::json{
            {"address", std::get<0>(entry)},
            {"port", std::get<1>(entry)},
            {"identifier", utils::to_hex(std::get<2>(entry))}
        };
        file_data.emplace_back(json_entry);
    }
    utils::write_file(m_node_cache_file_path, file_data.dump(4));
}
