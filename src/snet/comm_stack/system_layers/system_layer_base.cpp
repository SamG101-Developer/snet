export module snet.comm_stack.system_layers.system_layer_base;
import spdlog;
import serex.serialize;
import std;

import snet.comm_stack.layer_base;
import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.credentials.key_store_data;
import snet.crypt.symmetric;
import snet.net.udp_socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    class SystemLayerBase : public LayerBase {
    protected:
        credentials::KeyStoreData *m_self_node_info = nullptr;
        net::UDPSocket *m_sock;

    public:
        SystemLayerBase(
            credentials::KeyStoreData *self_node_info,
            net::UDPSocket *sock,
            std::shared_ptr<spdlog::logger> logger);

        ~SystemLayerBase() override = default;

        virtual auto send(
            Connection *conn,
            std::unique_ptr<RawRequest> &&req) const
            -> void final;

        virtual auto send_secure(
            Connection *conn,
            std::unique_ptr<RawRequest> &&req) const
            -> void final;

    protected:
        template <typename T>
        static auto attach_metadata(
            const Connection *conn,
            T *req)
            -> void;
    };
}


snet::comm_stack::layers::SystemLayerBase::SystemLayerBase(
    credentials::KeyStoreData *self_node_info,
    net::UDPSocket *sock,
    std::shared_ptr<spdlog::logger> logger) :
    LayerBase(std::move(logger)),
    m_self_node_info(self_node_info),
    m_sock(sock) {
    m_logger->info(std::format("{} initialized", m_logger->name()));
}


auto snet::comm_stack::layers::SystemLayerBase::send(
    Connection *conn,
    std::unique_ptr<RawRequest> &&req) const
    -> void {
    // Attach connection metadata to the request and serialize.
    attach_metadata(conn, req.get());
    auto req_serialized = utils::encode_string(serex::save(req));

    // Debug the send action and send the data via the socket.
    m_sock->send(req_serialized, conn->peer_ip, conn->peer_port);
}


auto snet::comm_stack::layers::SystemLayerBase::send_secure(
    Connection *conn,
    std::unique_ptr<RawRequest> &&req) const
    -> void {
    // Attach connection metadata to the request and serialize.
    attach_metadata(conn, req.get());
    const auto req_serialized = utils::encode_string<true>(serex::save(req));

    // Queue the request until the connection is accepted.
    while (not conn->is_accepted()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Create the ciphertext using the correct primary key.
    auto ct = crypt::symmetric::encrypt(
        *ConnectionCache::connections[conn->conn_tok]->e2e_key, req_serialized);
    auto enc_req = std::make_unique<EncryptedRequest>(utils::encode_string(serex::save(ct)));
    send(conn, std::move(enc_req));
}


template <typename T>
auto snet::comm_stack::layers::SystemLayerBase::attach_metadata(
    const Connection *conn,
    T *req)
    -> void {
    req->conn_tok = conn->conn_tok;
}
