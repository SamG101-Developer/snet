export module snet.comm_stack.layers.layer_n;
import spdlog;
import serex.serialize;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.credentials.key_store_data;
import snet.crypt.symmetric;
import snet.net.socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    class LayerN {
    protected:
        credentials::KeyStoreData *m_self_node_info = nullptr;
        net::Socket *m_sock;
        std::shared_ptr<spdlog::logger> m_logger;

    public:
        LayerN(
            credentials::KeyStoreData *self_node_info,
            net::Socket *sock);

        virtual ~LayerN() = default;

    protected:
        template <typename T>
        auto attach_metadata(
            const Connection *conn,
            T *req) const
            -> void;

        template <typename T>
        auto send(
            Connection *conn,
            std::unique_ptr<T> &&req)
            -> void;

        template <typename T>
        auto send_secure(
            Connection *conn,
            std::unique_ptr<T> &&req)
            -> void;
    };
}


snet::comm_stack::layers::LayerN::LayerN(
    credentials::KeyStoreData *self_node_info,
    net::Socket *sock) :
    m_self_node_info(self_node_info),
    m_sock(sock),
    m_logger(spdlog::default_logger()) {
}


template <typename T>
auto snet::comm_stack::layers::LayerN::attach_metadata(
    const Connection *conn,
    T *req) const
    -> void {
    req->conn_tok = conn->conn_tok;
}


template <typename T>
auto snet::comm_stack::layers::LayerN::send(
    Connection *conn,
    std::unique_ptr<T> &&req)
    -> void {
    // Attach connection metadata to the request and serialize.
    attach_metadata(conn, req.get());
    auto req_serialized = utils::encode_string(serex::save(*req));

    // Debug the send action and send the data via the socket.
    m_logger->debug(std::format(
        "LayerN sending request of size {} to {}@{}:{}",
        req_serialized.size(), utils::to_hex(conn->peer_id), conn->peer_ip, conn->peer_port));
    m_sock->send(req_serialized, conn->peer_ip, conn->peer_port);
}


template <typename T>
auto snet::comm_stack::layers::LayerN::send_secure(
    Connection *conn,
    std::unique_ptr<T> &&req)
    -> void {
    // Attach connection metadata to the request and serialize.
    attach_metadata(conn, req.get());
    const auto req_serialized = utils::encode_string<true>(serex::save(*req));

    // Queue the request until the connection is accepted.
    while (not conn->is_accepted()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Create the ciphertext using the correct primary key.
    auto ct = crypt::symmetric::encrypt(
        *ConnectionCache::connections[conn->conn_tok]->e2e_key, req_serialized);
    auto enc_req = EncryptedRequest(utils::encode_string(serex::save(ct)));
    auto enc_req_serialized = utils::encode_string(serex::save(enc_req));

    // Debug the send action and send the data via the socket.
    m_logger->debug(std::format(
        "LayerN sending SECURE request of size {} to {}@{}:{}",
        enc_req.ciphertext.size(), utils::to_hex(conn->peer_id), conn->peer_ip, conn->peer_port));
    m_sock->send(enc_req_serialized, conn->peer_ip, conn->peer_port);
}
