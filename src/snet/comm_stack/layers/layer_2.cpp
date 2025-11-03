module;
#include <snet/macros.hpp>

#include <genex/to_container.hpp>
#include <genex/actions/remove_if.hpp>
#include <genex/actions/shuffle.hpp>
#include <genex/views/reverse.hpp>

export module snet.comm_stack.layers.layer_2;
import serex.serialize;
import spdlog;
import std;

import snet.comm_stack.layers.layer_n;
import snet.credentials.key_store_data;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.hash;
import snet.crypt.random;
import snet.crypt.symmetric;
import snet.crypt.timestamp;
import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.layers.layer_3;
import snet.comm_stack.layers.layer_d;
import snet.comm_stack.layers.layer_4;
import snet.net.socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    constexpr auto HOP_COUNT = 3uz;

    struct Route {
        crypt::bytes::RawBytes route_token;
        crypt::bytes::RawBytes entry_token;
        std::vector<Connection*> nodes;
        Connection *candidate_node = nullptr;
        bool ready = false;
    };

    class Layer2 final : LayerN {
        std::unique_ptr<Route> m_route;
        std::map<crypt::bytes::RawBytes, crypt::bytes::RawBytes> m_route_forward_token_map;
        std::map<crypt::bytes::RawBytes, crypt::bytes::RawBytes> m_route_reverse_token_map;
        std::map<crypt::bytes::RawBytes, crypt::bytes::SecureBytes> m_participating_route_keys;
        Connection *m_self_conn = nullptr;

        Layer3 *m_l3 = nullptr;
        LayerD *m_ld = nullptr;
        Layer4 *m_l4 = nullptr;

    public:
        Layer2(
            credentials::KeyStoreData *self_node_info,
            net::Socket *sock,
            Layer3 *l3,
            LayerD *ld,
            Layer4 *l4);

        auto create_route()
            -> void;

        [[nodiscard]]
        auto get_participating_route_keys() const -> decltype(auto) {
            return m_participating_route_keys;
        }

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req = nullptr)
            -> void;

    private:
        auto handle_route_extension_request(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer2_RouteExtensionRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;

        auto handle_tunnel_join_request(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer2_TunnelJoinRequest> &&req)
            -> void;

        auto handle_tunnel_join_accept(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer2_TunnelJoinAccept> &&req)
            -> void;

        auto handle_tunnel_join_reject(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer2_TunnelJoinReject> &&req)
            -> void;

        auto handle_tunnel_data_forward(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer2_TunnelDataForward> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;

        auto handle_tunnel_data_backward(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer2_TunnelDataBackward> &&req)
            -> void;

        auto send_tunnel_forward(
            std::unique_ptr<RawRequest> &&req,
            std::size_t hops = HOP_COUNT + 1,
            bool for_route_setup = false) const
            -> void;

        auto send_tunnel_backward(
            Connection *prev_conn,
            std::unique_ptr<RawRequest> &&req) const
            -> void;
    };
}


snet::comm_stack::layers::Layer2::Layer2(
    credentials::KeyStoreData *self_node_info,
    net::Socket *sock,
    Layer3 *l3,
    LayerD *ld,
    Layer4 *l4) :
    LayerN(self_node_info, sock),
    m_l3(l3),
    m_ld(ld),
    m_l4(l4) {
    m_logger = utils::create_logger("Layer2");
    m_logger->info("Layer2 initialized");
}


auto snet::comm_stack::layers::Layer2::create_route()
    -> void {
    // Checked there are enough cached nodes to create a route.
    while (ConnectionCache::cached_nodes.size() < HOP_COUNT + 1) {
        m_logger->warn("Not enough cached nodes to create a route; waiting...");
        m_ld->request_bootstrap();
    }
    m_logger->info("Sufficient cached nodes available; creating route");

    // Copy the cache and remove this node from it.
    auto cache = ConnectionCache::cached_nodes;
    cache |= genex::actions::remove_if([this](auto const &node) { return std::get<2>(node) == m_self_node_info->identifier; });

    // Add this node as the first in the route (self-send to tunnel onwards).
    m_logger->info("Creating pre-entry self connection");
    auto self_conn = std::make_unique<Connection>(
        "127.0.0.1", m_self_node_info->port, m_self_node_info->identifier,
        crypt::random::random_bytes(32) + crypt::timestamp::timestamp_bytes(), ConnectionState::CONNECTION_OPEN);
    self_conn->e2e_key = crypt::symmetric::generate_key();
    m_self_conn = self_conn.get();
    ConnectionCache::connections[m_self_conn->conn_tok] = std::move(self_conn);

    // Create the route object.
    m_logger->info(std::format("Creating route with {} hops", HOP_COUNT));
    m_route = std::make_unique<Route>(crypt::random::random_bytes(32), m_self_conn->conn_tok);
    m_route->nodes.emplace_back(m_self_conn);
    m_participating_route_keys[m_route->entry_token] = *m_self_conn->e2e_key;

    // For each hop in the route, create a connection to the next node.
    while (m_route->nodes.size() < HOP_COUNT + 1) {
        cache |= genex::actions::shuffle(genex::actions::detail::default_random);

        // Pop a candidate node from the cache to use for the route.
        const auto self_esk = crypt::asymmetric::generate_sig_keypair();
        auto cand_info = cache.back();
        cache.pop_back();

        // Generate the mock connection object to store candidate node information.
        auto cand_node = std::make_unique<Connection>(
            std::get<0>(cand_info), std::get<1>(cand_info), std::get<2>(cand_info),
            crypt::random::random_bytes(32) + crypt::timestamp::timestamp_bytes(), ConnectionState::PENDING_CONNECTION);
        cand_node->self_esk = self_esk;
        m_route->candidate_node = cand_node.get();
        m_logger->info(std::format(
            "Extending route to candidate node {}@{}:{}",
            cand_node->peer_ip, cand_node->peer_port, utils::to_hex(cand_node->conn_tok)));

        // Send the extension request to the last node in the route so far.
        const auto cand_epk = crypt::asymmetric::serialize_public(cand_node->self_esk);
        auto req = std::make_unique<Layer2_RouteExtensionRequest>(
            cand_node->conn_tok, cand_epk, cand_node->peer_ip, cand_node->peer_port, cand_node->peer_id);
        send_tunnel_forward(std::move(req), m_route->nodes.size(), true);

        // Wait for either the candidate node to accept or reject the connection.
        while (not(cand_node->is_accepted() or cand_node->is_rejected())) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Add the node if it was accepted; otherwise, try again.
        if (cand_node->is_accepted()) {
            m_logger->info(std::format(
                "Route extension to node {}@{}:{} accepted",
                cand_node->peer_ip, cand_node->peer_port, utils::to_hex(cand_node->conn_tok)));
            m_route->nodes.emplace_back(m_route->candidate_node);
        }
    }

    m_route->ready = true;
    m_logger->info("Route creation complete");
}


auto snet::comm_stack::layers::Layer2::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    // Get the token and state of the connection.
    auto tok = req->conn_tok;

    // Map the request type and connection state to the appropriate handler.
    MAP_TO_HANDLER(2, Layer2_RouteExtensionRequest, true, handle_route_extension_request, std::move(tun_req));
    MAP_TO_HANDLER(2, Layer2_TunnelJoinRequest, true, handle_tunnel_join_request);
    MAP_TO_HANDLER(2, Layer2_TunnelJoinAccept, true, handle_tunnel_join_accept);
    MAP_TO_HANDLER(2, Layer2_TunnelJoinReject, true, handle_tunnel_join_reject);
    MAP_TO_HANDLER(2, Layer2_TunnelDataForward, true, handle_tunnel_data_forward, std::move(tun_req));
    MAP_TO_HANDLER(2, Layer2_TunnelDataBackward, true, handle_tunnel_data_backward);

    // If no handler matched, log a warning.
    m_logger->warn(std::format(
        "Layer2 received invalid request type from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(tok)));
}


auto snet::comm_stack::layers::Layer2::handle_route_extension_request(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer2_RouteExtensionRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    // Log the receipt of the route extension request.
    m_logger->info(std::format(
        "Layer2 received route extension request from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));
    m_logger->info(std::format(
        "Layer2 sending route extension response to {}@{}:{}",
        req->next_node_ip, req->next_node_port, utils::to_hex(req->conn_tok)));

    // Create a new connection to the next node.
    const auto prev_conn = ConnectionCache::connections[tun_req->conn_tok].get();
    const auto next_conn = m_l4->connect(req->next_node_ip, req->next_node_port, req->next_node_id);
    next_conn->conn_tok = req->conn_tok;

    // If the connection cannot be made, reject the request.
    if (next_conn == nullptr) {
        auto rejection = std::make_unique<Layer2_TunnelJoinReject>(req->route_tok, "Node unreachable");
        send(prev_conn, std::move(rejection));
        return;
    }

    // Otherwise, the connection is successful; send the join request to the next node.
    auto tunnel_join_request = std::make_unique<Layer2_TunnelJoinRequest>(req->route_tok, req->route_owner_epk);
    m_route_forward_token_map[prev_conn->conn_tok] = next_conn->conn_tok;
    m_route_reverse_token_map[next_conn->conn_tok] = prev_conn->conn_tok;
    send(next_conn, std::move(tunnel_join_request));
}


auto snet::comm_stack::layers::Layer2::handle_tunnel_join_request(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer2_TunnelJoinRequest> &&req)
    -> void {
    // Log the receipt of the tunnel join rejection.
    m_logger->info(std::format(
        "Layer2 received tunnel join rejection from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));

    // Get the connection from the cache.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();
    const auto remote_session_id = crypt::asymmetric::create_aad(req->route_token + req->route_token, conn->peer_id);
    const auto route_owner_epk = crypt::asymmetric::load_public_key_kem(req->route_owner_epk);

    // Check if this node is eligible to accept the tunnel join request.
    if (m_participating_route_keys.size() >= 3) {
        auto rejection = std::make_unique<Layer2_TunnelJoinReject>(req->route_token, "Node decision (capacity full)");
        send(conn, std::move(rejection));
        return;
    }

    // Create a master key and kem-wrapped master key,
    const auto kem = crypt::asymmetric::encaps(route_owner_epk);
    const auto self_ssk = crypt::asymmetric::load_private_key_sig(m_self_node_info->secret_key);
    const auto kem_sig = crypt::asymmetric::sign(self_ssk, kem.ct, remote_session_id.get());
    m_participating_route_keys[req->conn_tok] = kem.ss;

    // Create a new Layer2_TunnelJoinAccept response and send it.
    m_logger->info(std::format(
        "Layer2 sending tunnel join accept to {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));
    auto response = std::make_unique<Layer2_TunnelJoinAccept>(req->route_token, m_self_node_info->certificate, kem.ct, kem_sig);
    send(conn, std::move(response));
}


auto snet::comm_stack::layers::Layer2::handle_tunnel_join_accept(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer2_TunnelJoinAccept> &&req)
    -> void {
    // Log the receipt of the tunnel join acceptance.
    m_logger->info(std::format(
        "Layer2 received tunnel join acceptance from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));
    const auto peer_cert = crypt::certificate::load_certificate(req->acceptor_cert);

    // If the route token is not for this node's route, tunnel the request backwards.
    if (m_route == nullptr or m_route->candidate_node->conn_tok != req->route_token) {
        const auto prev_conn_tok = m_route_reverse_token_map[req->conn_tok];
        const auto prev_conn = ConnectionCache::connections[prev_conn_tok].get();
        send_tunnel_backward(prev_conn, std::move(req));
        return;
    }

    // Check the node identifier on the acceptor certificate matches the candidate node.
    auto peer_id = crypt::certificate::extract_id_from_cert(peer_cert);
    if (m_route->candidate_node->peer_id != peer_id) {
        m_logger->warn(std::format("Layer2 Invalid node trying to join route: {}", utils::to_hex(peer_id)));
        m_route->candidate_node->state = ConnectionState::CONNECTION_CLOSED;
        return;
    }

    // Verify the certificate of the remote node.
    const auto peer_spk = crypt::certificate::extract_pkey_from_cert(peer_cert);
    if (not crypt::certificate::verify_certificate(peer_cert, peer_spk)) {
        m_logger->warn(std::format("Layer2 Certificate verification failed for node: {}", utils::to_hex(peer_id)));
        m_route->candidate_node->state = ConnectionState::CONNECTION_CLOSED;
        return;
    }

    // Verify the signature of the kem encapsulation.
    const auto self_tunnel_epk = crypt::asymmetric::serialize_public(m_route->candidate_node->self_esk);
    const auto local_session_id = crypt::asymmetric::create_aad(m_route->candidate_node->conn_tok + self_tunnel_epk, m_route->nodes.back()->peer_id);
    if (not crypt::asymmetric::verify(peer_spk, req->sig, req->kem_wrapped_p2p_primary_key, local_session_id.get())) {
        m_logger->warn(std::format("Layer2 KEM-wrapped primary key signature verification failed for node: {}", utils::to_hex(peer_id)));
        m_route->candidate_node->state = ConnectionState::CONNECTION_CLOSED;
        return;
    }

    // Unwrap the kem encapsulation and set the e2e primary key for the tunnel.
    auto ss = crypt::asymmetric::decaps(m_route->candidate_node->self_esk, req->kem_wrapped_p2p_primary_key);
    m_route->candidate_node->e2e_key = std::move(ss);
    m_route->candidate_node->state = ConnectionState::CONNECTION_OPEN;

    // Log the successful addition of the node to the route.
    m_logger->info(std::format("Layer2 node {} successfully joined the route", utils::to_hex(peer_id)));
}


auto snet::comm_stack::layers::Layer2::handle_tunnel_join_reject(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer2_TunnelJoinReject> &&req)
    -> void {
    // Log the receipt of the tunnel join rejection.
    m_logger->info(std::format(
        "Layer2 received tunnel join rejection from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(req->conn_tok)));

    // If the route token is not for this node's route, tunnel the request backwards.
    if (m_route == nullptr or m_route->candidate_node->conn_tok != req->route_tok) {
        auto prev_conn_tok = m_route_reverse_token_map[req->conn_tok];
        const auto prev_conn = ConnectionCache::connections[std::move(prev_conn_tok)].get();
        send_tunnel_backward(prev_conn, std::move(req));
        return;
    }

    // Otherwise, mark the candidate node as rejected.
    m_logger->info(std::format(
        "Layer2 node {} rejected from joining the route: {}",
        utils::to_hex(m_route->candidate_node->peer_id), req->reason));
    m_route->candidate_node->state = ConnectionState::CONNECTION_CLOSED;
}


auto snet::comm_stack::layers::Layer2::handle_tunnel_data_forward(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer2_TunnelDataForward> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    // Unwrap the request and get the internal request object and send it over a secure connection.
    auto next_conn_tok = m_route_forward_token_map[tun_req->conn_tok];
    const auto next_conn = ConnectionCache::connections[std::move(next_conn_tok)].get();
    auto inner_enc_req = serex::load<RawRequest*>(utils::decode_bytes(req->data));
    send_secure(next_conn, std::move(inner_enc_req));
}


auto snet::comm_stack::layers::Layer2::handle_tunnel_data_backward(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer2_TunnelDataBackward> &&req)
    -> void {
    // Encrypt and send the request to the previous node in the route.
    if (m_route_reverse_token_map.contains(req->conn_tok)) {
        auto prev_conn_tok = m_route_reverse_token_map[req->conn_tok];
        const auto prev_conn = ConnectionCache::connections[std::move(prev_conn_tok)].get();

        attach_metadata(prev_conn, req.get());
        auto ct = crypt::symmetric::encrypt(m_participating_route_keys[prev_conn->conn_tok], utils::encode_string<true>(serex::save(req)));
        auto enc_req = std::make_unique<EncryptedRequest>(utils::encode_string(serex::save(ct)));
        enc_req->conn_tok = req->conn_tok;
        auto wrapped_req = Layer2_TunnelDataBackward(utils::encode_string(serex::save(enc_req)));
        send_secure(prev_conn, std::move(req));
        return;
    }

    // Ensure the request is valid for a route owner
    if (m_route == nullptr and m_route->nodes.front()->conn_tok != req->conn_tok) {
        m_logger->warn(std::format("Layer2 received invalid tunnel data backward request from {}@{}:{}", peer_ip, peer_port, utils::to_hex(req->conn_tok)));
        return;
    }

    // Route owner decrypts all the layers of encryption and handles the internal request.
    for (auto const *node : m_route->nodes) {
        // Todo: check every node tunnel token layered inside the request
        const auto inner_enc_req = serex::load<EncryptedRequest*>(utils::decode_bytes(req->data));
        const auto [ct, iv, tag] = serex::load<crypt::symmetric::CipherText>(utils::decode_bytes(inner_enc_req->ciphertext));
        const auto plaintext = crypt::symmetric::decrypt(*node->e2e_key, ct, iv, tag);

        auto inner_req = serex::load<RawRequest*>(utils::decode_bytes(plaintext));
        if (serex::poly_non_owning_cast<Layer2_TunnelDataBackward>(inner_req) != nullptr) {
            req = serex::poly_owning_cast<Layer2_TunnelDataBackward>(std::move(inner_req));
            continue;
        }
        break;
    }

    // Handle the innermost request.
    m_logger->info("Layer2 fully unwrapped tunnelled request");
    send_secure(m_self_conn, std::move(req));
}


auto snet::comm_stack::layers::Layer2::send_tunnel_forward(
    std::unique_ptr<RawRequest> &&req,
    std::size_t hops,
    const bool for_route_setup) const
    -> void {
    // Wait for the route to be created to fix timing issues (only called from route owner).
    while (m_route == nullptr or (not for_route_setup and not m_route->ready)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Get the list of nodes in reverse order.
    const auto node_list = m_route->nodes | genex::views::reverse | genex::to<std::vector>();

    // Create the packaged request for the target node.
    attach_metadata(node_list.front(), req.get());
    m_logger->info(std::format("Layer2 sending tunnel forward request via {} hops", hops));
    auto ct = crypt::symmetric::encrypt(*node_list.front()->e2e_key, utils::encode_string<true>(serex::save(req)));
    auto enc_req = std::make_unique<EncryptedRequest>(utils::encode_string(serex::save(ct)));
    enc_req->conn_tok = node_list.front()->conn_tok;

    // Layer the tunnel for subsequent nodes in the route.
    for (auto const *node : std::vector(node_list.begin() + 1, node_list.end())) {
        auto wrapped_req = std::make_unique<Layer2_TunnelDataForward>(utils::encode_string(serex::save(enc_req)));
        attach_metadata(node, wrapped_req.get());
        ct = crypt::symmetric::encrypt(*node->e2e_key, utils::encode_string<true>(serex::save(wrapped_req)));
        enc_req = std::make_unique<EncryptedRequest>(utils::encode_string(serex::save(ct)));
        enc_req->conn_tok = node->conn_tok;
    }

    // Send the request to the first node in the route.
    m_logger->info("Layer2 sending tunnel forward request to first node in route");
    send_secure(node_list.back(), std::move(enc_req));
}


auto snet::comm_stack::layers::Layer2::send_tunnel_backward(
    Connection *prev_conn,
    std::unique_ptr<RawRequest> &&req) const
    -> void {
    // Encrypt and send the request to the previous node in the route.
    attach_metadata(prev_conn, req.get());
    auto ct = crypt::symmetric::encrypt(m_participating_route_keys.at(prev_conn->conn_tok), utils::encode_string<true>(serex::save(req)));
    auto enc_req = std::make_unique<EncryptedRequest>(utils::encode_string(serex::save(ct)));
    enc_req->conn_tok = prev_conn->conn_tok;
    auto wrapped_req = std::make_unique<Layer2_TunnelDataBackward>(utils::encode_string(serex::save(enc_req)));
    send_secure(prev_conn, std::move(wrapped_req));
}
