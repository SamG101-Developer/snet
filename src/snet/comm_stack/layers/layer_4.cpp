module;
#include <snet/macros.hpp>

#include <genex/to_container.hpp>
#include <genex/views/take_last.hpp>

export module snet.comm_stack.layers.layer_4;
import openssl;
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
import snet.crypt.timestamp;
import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.net.socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    class Layer4 final : LayerN {
        crypt::bytes::RawBytes m_self_id;
        openssl::EVP_PKEY *m_static_skey;
        crypt::bytes::RawBytes m_self_cert;

        std::map<crypt::bytes::RawBytes, openssl::X509*> m_cached_certs = {};
        std::map<crypt::bytes::RawBytes, openssl::EVP_PKEY*> m_cached_pkeys = {};

    public:
        Layer4(
            credentials::KeyStoreData *self_node_info,
            net::Socket *sock);

        auto connect(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            crypt::bytes::RawBytes const &peer_id,
            crypt::bytes::RawBytes const &pre_conn_tok = {})
            -> Connection*;

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req)
            -> void;

    private:
        auto handle_connection_request(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer4_ConnectionRequest> &&req)
            -> void;

        auto handle_connection_accept(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer4_ConnectionAccept> &&req)
            -> void;

        auto handle_connection_ack(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer4_ConnectionAck> &&req)
            -> void;

        auto handle_connection_close(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer4_ConnectionClose> &&req)
            -> void;
    };
}


snet::comm_stack::layers::Layer4::Layer4(
    credentials::KeyStoreData *self_node_info,
    net::Socket *sock) :
    LayerN(self_node_info, sock),
    m_static_skey(crypt::asymmetric::load_private_key_sig(self_node_info->secret_key)),
    m_self_cert(self_node_info->certificate) {
    m_logger = utils::create_logger("Layer4");
    m_logger->info("Layer4 initialized");
}


auto snet::comm_stack::layers::Layer4::connect(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    crypt::bytes::RawBytes const &peer_id,
    crypt::bytes::RawBytes const &pre_conn_tok)
    -> Connection* {
    // Generate a unique connection token unless provided.
    auto conn_tok = pre_conn_tok.empty() ? crypt::random::random_bytes(32) + crypt::timestamp::timestamp_bytes() : pre_conn_tok;
    const auto remote_session_id = conn_tok + peer_id;

    // Generate an ephemeral key pair for this connection (exclusively).
    const auto self_esk = crypt::asymmetric::generate_kem_keypair();
    const auto self_epk = crypt::asymmetric::serialize_public(self_esk);
    const auto aad = crypt::asymmetric::create_aad(conn_tok, peer_id);
    const auto self_epk_sig = crypt::asymmetric::sign(m_static_skey, self_epk, aad.get());

    // Create the connection object to track the conversation.
    auto conn = std::make_unique<Connection>(
        peer_ip, peer_port, peer_id, conn_tok, ConnectionState::PENDING_CONNECTION);
    conn->self_esk = self_esk;

    const auto conn_ptr = conn.get();
    ConnectionCache::connections[conn_tok] = std::move(conn);

    // Create the request to request a connection.
    auto req = std::make_unique<Layer4_ConnectionRequest>(
        m_self_cert, self_epk, self_epk_sig);

    send(ConnectionCache::connections[conn_tok].get(), std::move(req));
    m_logger->info(std::format(
        "Layer4 sent connection request to {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(conn_tok)));

    // Wait for the connection to be accepted or rejected.
    while (not(conn_ptr->is_accepted() or conn_ptr->is_rejected())) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    m_logger->info(std::format(
        "Layer4 connection to {}@{}:{} {}",
        peer_ip, peer_port, utils::to_hex(conn_tok),
        conn_ptr->is_accepted() ? "accepted" : "rejected"));
    return conn_ptr->is_accepted() ? conn_ptr : nullptr;
}


auto snet::comm_stack::layers::Layer4::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req)
    -> void {
    m_logger->info(std::format(
        "Layer4 received request of type {} from {}@{}:{}",
        req->serex_type(), peer_ip, peer_port, utils::to_hex(req->conn_tok)));

    // Get the token and state of the connection.
    auto tok = req->conn_tok;
    const auto state = ConnectionCache::connections.contains(tok)
                           ? ConnectionCache::connections[tok]->state
                           : ConnectionState::NOT_CONNECTED;

    // Map the request type and connection state to the appropriate handler.
    MAP_TO_HANDLER(4, Layer4_ConnectionRequest, state == ConnectionState::NOT_CONNECTED, handle_connection_request);
    MAP_TO_HANDLER(4, Layer4_ConnectionAccept, state == ConnectionState::PENDING_CONNECTION, handle_connection_accept);
    MAP_TO_HANDLER(4, Layer4_ConnectionAck, state == ConnectionState::PENDING_CONNECTION, handle_connection_ack);
    MAP_TO_HANDLER(4, Layer4_ConnectionClose, true, handle_connection_close);

    // If no handler matched, log a warning.
    m_logger->warn(std::format(
        "Layer4 received invalid request type or state from {}@{}:{}",
        peer_ip, peer_port, utils::to_hex(tok)));
}


auto snet::comm_stack::layers::Layer4::handle_connection_request(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer4_ConnectionRequest> &&req)
    -> void {

    // Load information off of the request.
    const auto peer_cert = crypt::certificate::load_certificate(req->req_cert);
    const auto peer_spk = crypt::certificate::extract_pkey_from_cert(peer_cert);
    const auto peer_epk = crypt::asymmetric::load_public_key_kem(req->req_epk);
    const auto peer_id = crypt::certificate::extract_id_from_cert(peer_cert);

    // Create the connection object to track the conversation.
    auto conn = std::make_unique<Connection>(
        peer_ip, peer_port, peer_id, req->conn_tok, ConnectionState::PENDING_CONNECTION, peer_epk);

    // Create the local and remote session identifiers.
    const auto local_session_id = crypt::asymmetric::create_aad(conn->conn_tok, m_self_id);;
    const auto remote_session_id = crypt::asymmetric::create_aad(conn->conn_tok, conn->peer_id);

    // Verify the certificate of the remote node.
    if (not crypt::certificate::verify_certificate(peer_cert, peer_spk)) {
        auto response = std::make_unique<Layer4_ConnectionClose>("Certificate verification failed");
        send(conn.get(), std::move(response));
        return;
    }

    // Verify the signature on the ephemeral public key.
    if (not crypt::asymmetric::verify(peer_spk, req->sig, req->req_epk, local_session_id.get())) {
        auto response = std::make_unique<Layer4_ConnectionClose>("Ephemeral public key signature verification failed");
        send(conn.get(), std::move(response));
        return;
    }

    // Validate the connection's timestamp is within tolerance.
    const auto ts = crypt::timestamp::unpack_timestamp(conn->conn_tok | genex::views::take_last(8) | genex::to<crypt::bytes::RawBytes>());
    if (not crypt::timestamp::timestamp_in_tolerance(ts)) {
        auto response = std::make_unique<Layer4_ConnectionClose>("Connection request timestamp out of tolerance");
        send(conn.get(), std::move(response));
        return;
    }

    // Cache the public key and certificate for future use.
    m_cached_certs[conn->peer_id] = peer_cert;
    m_cached_pkeys[conn->peer_id] = peer_spk;

    // Create a master key and kem-wrapped master key,
    const auto kem = crypt::asymmetric::encaps(peer_epk);
    const auto kem_sig = crypt::asymmetric::sign(m_static_skey, kem.ct, remote_session_id.get());
    conn->e2e_key = kem.ss;

    // Create a new Layer4_ConnectionAccept response and send it.
    auto response = std::make_unique<Layer4_ConnectionAccept>(m_self_cert, kem.ct, kem_sig);
    send(conn.get(), std::move(response));

    // Update and store the connection in the cache.
    conn->state = ConnectionState::PENDING_CONNECTION;
    ConnectionCache::connections[conn->conn_tok] = std::move(conn);
}


auto snet::comm_stack::layers::Layer4::handle_connection_accept(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer4_ConnectionAccept> &&req)
    -> void {
    // Get the connection from the cache.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();
    const auto peer_cert = crypt::certificate::load_certificate(req->acceptor_cert);
    const auto peer_spk = crypt::certificate::extract_pkey_from_cert(peer_cert);

    // Create the local and remote session identifiers.
    const auto local_session_id = crypt::asymmetric::create_aad(conn->conn_tok, m_self_id);;
    const auto remote_session_id = crypt::asymmetric::create_aad(conn->conn_tok, conn->peer_id);

    // Verify the certificate of the remote node.
    if (not crypt::certificate::verify_certificate(peer_cert, peer_spk)) {
        auto response = std::make_unique<Layer4_ConnectionClose>("Certificate verification failed");
        send(conn, std::move(response));
        return;
    }

    // Verify the signature on the KEM-wrapped primary key.
    if (not crypt::asymmetric::verify(peer_spk, req->sig, req->kem_wrapped_p2p_primary_key, local_session_id.get())) {
        auto response = std::make_unique<Layer4_ConnectionClose>("KEM-wrapped primary key signature verification failed");
        send(conn, std::move(response));
        return;
    }

    // Cache the public key and certificate for future use.
    m_cached_certs[conn->peer_id] = peer_cert;
    m_cached_pkeys[conn->peer_id] = peer_spk;

    // Decapsulate the KEM-wrapped primary key to get the shared secret.
    auto shared_secret = crypt::asymmetric::decaps(conn->self_esk, req->kem_wrapped_p2p_primary_key);
    conn->e2e_key = std::move(shared_secret);

    // Create a new Layer4_ConnectionAck response and send it.
    const auto hash_e2e_primary_key = crypt::hash::sha3_256(*conn->e2e_key);
    const auto hash_e2e_primary_key_sig = crypt::asymmetric::sign(m_static_skey, hash_e2e_primary_key, remote_session_id.get());
    auto response = std::make_unique<Layer4_ConnectionAck>(hash_e2e_primary_key_sig);
    send(conn, std::move(response));

    // Clean-up keys and mark the connection as accepted.
    conn->clean_ephemeral_keys();
    conn->state = ConnectionState::CONNECTION_OPEN;
    m_logger->info(std::format("Layer4 connection established with {}", utils::to_hex(conn->peer_id)));
}


auto snet::comm_stack::layers::Layer4::handle_connection_ack(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer4_ConnectionAck> &&req)
    -> void {
    // Get the connection from the cache.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();

    // Create the local and remote session identifiers.
    const auto local_session_id = crypt::asymmetric::create_aad(conn->conn_tok, m_self_id);
    const auto remote_session_id = crypt::asymmetric::create_aad(conn->conn_tok, conn->peer_id);
    const auto peer_spk = m_cached_pkeys[conn->peer_id];

    // Verify the signature on the hash of the shared secret.
    const auto hash_e2e_primary_key = crypt::hash::sha3_256(*conn->e2e_key);  // todo: this "*" fails.
    if (not crypt::asymmetric::verify(peer_spk, req->sig, hash_e2e_primary_key, local_session_id.get())) {
        auto response = std::make_unique<Layer4_ConnectionClose>("Shared secret hash signature verification failed");
        send(conn, std::move(response));
        return;
    }

    // Clean-up keys and mark the connection as accepted.
    conn->clean_ephemeral_keys();
    conn->state = ConnectionState::CONNECTION_OPEN;
    m_logger->info(std::format("Layer4 connection established with {}", utils::to_hex(conn->peer_id)));
}


auto snet::comm_stack::layers::Layer4::handle_connection_close(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer4_ConnectionClose> &&req)
    -> void {
    // Get the connection from the cache.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();

    // Mark the connection as closed, and delete the connection.
    conn->state = ConnectionState::CONNECTION_CLOSED;
    m_logger->info(std::format("Layer4 connection closed with {} because {}", utils::to_hex(conn->peer_id), req->reason));
    ConnectionCache::connections.erase(req->conn_tok);
}
