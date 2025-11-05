module;
#include <snet/macros.hpp>

export module snet.comm_stack.comm_stack;
import serex.serialize;
import spdlog;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.system_layers.layer_1;
import snet.comm_stack.system_layers.layer_2;
import snet.comm_stack.system_layers.layer_3;
import snet.comm_stack.system_layers.layer_4;
import snet.comm_stack.system_layers.layer_d;
import snet.credentials.key_store_data;
import snet.crypt.bytes;
import snet.crypt.symmetric;
import snet.net.socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack {
    class CommStack {
        std::uint16_t m_port;
        std::shared_ptr<spdlog::logger> m_logger;
        std::jthread m_listener_thread;
        credentials::KeyStoreData *m_info = nullptr;

        std::unique_ptr<net::UDPSocket> m_sock;
        std::unique_ptr<layers::Layer1> m_l1 = nullptr;
        std::unique_ptr<layers::Layer2> m_l2 = nullptr;
        std::unique_ptr<layers::Layer3> m_l3 = nullptr;
        std::unique_ptr<layers::Layer4> m_l4 = nullptr;
        std::unique_ptr<layers::LayerD> m_ld = nullptr;

    public:
        explicit CommStack(std::uint16_t port);

        [[nodiscard]]
        auto get_socket() const -> net::UDPSocket* {
            return m_sock.get();
        }

        [[nodiscard]]
        auto get_layer_1() const -> layers::Layer1* {
            return m_l1.get();
        }

        [[nodiscard]]
        auto get_layer_2() const -> layers::Layer2* {
            return m_l2.get();
        }

        [[nodiscard]]
        auto get_layer_3() const -> layers::Layer3* {
            return m_l3.get();
        }

        [[nodiscard]]
        auto get_layer_4() const -> layers::Layer4* {
            return m_l4.get();
        }

        [[nodiscard]]
        auto get_layer_d() const -> layers::LayerD* {
            return m_ld.get();
        }

        [[nodiscard]]
        auto all_layers_ready() const -> bool {
            return m_l1 != nullptr and m_l2 != nullptr and m_l3 != nullptr and m_l4 != nullptr and m_ld != nullptr;
        }

        // Todo: change to recv the args here and construct ld in this class
        // Todo: probably merge with "start" function
        auto setup_boostrap(
            std::unique_ptr<layers::LayerD> &&ld)
            -> void;

        auto start(
            credentials::KeyStoreData *info)
            -> void;

        [[noreturn]]
        auto listen() const -> void;
    };
}


snet::comm_stack::CommStack::CommStack(
    const std::uint16_t port) :
    m_port(port),
    m_logger(utils::create_logger("CommStack")),
    m_sock(std::make_unique<net::UDPSocket>()) {

    // Setup the socket.
    m_sock->bind(m_port);
    m_logger->info(std::format("CommStack initialized on port {}", m_port));

    // Setup the listener thread for receiving incoming connections.
    m_listener_thread = std::jthread([this] { listen(); });
}


auto snet::comm_stack::CommStack::setup_boostrap(
    std::unique_ptr<layers::LayerD> &&ld)
    -> void {
    m_ld = std::move(ld);
    m_l2 = std::make_unique<layers::Layer2>(m_info, m_sock.get(), m_l3.get(), m_ld.get(), m_l4.get());
    m_l1 = std::make_unique<layers::Layer1>(m_info, m_sock.get(), m_l4.get(), m_l3.get(), m_ld.get(), m_l2.get());
}


auto snet::comm_stack::CommStack::start(
    credentials::KeyStoreData *info)
    -> void {
    m_logger->info("CommStack starting...");

    // Create the layers on the stack.
    m_info = info;
    m_l4 = std::make_unique<layers::Layer4>(m_info, m_sock.get());
    m_l3 = std::make_unique<layers::Layer3>(m_info, m_sock.get(), m_l4.get());
    m_logger->info("CommStack started");
}


auto snet::comm_stack::CommStack::listen() const
    -> void {
    m_logger->info("CommStack listener thread started");
    // Listen for incoming raw requests, and handle them in a new thread.
    while (true) {
        const auto [data, peer_ip, peer_port] = m_sock->recv();
        auto req = serex::load<RawRequest*>(utils::decode_bytes(data));
        auto tunnel_response = std::unique_ptr<EncryptedRequest>(nullptr);
        m_logger->debug("CommStack processing request" + FORMAT_PEER_INFO());

        // Handle secure p2p requests.
        if (req->secure) {
            auto tok = req->conn_tok;
            auto ct_serialized = utils::decode_bytes(serex::poly_non_owning_cast<EncryptedRequest>(req)->ciphertext);
            auto [ct, iv, tag] = serex::load<crypt::symmetric::CipherText>(ct_serialized);

            // Ensure the token exists in the connection cache.
            if (ConnectionCache::connections.contains(tok)) {
                auto e2e_key = *ConnectionCache::connections[tok]->e2e_key;
                auto raw_data = crypt::symmetric::decrypt(e2e_key, ct, iv, tag);
                req = serex::load<RawRequest*>(utils::decode_bytes(raw_data));

                // If the response is still encrypted, it is for tunneling. Decrypt a layer and push onwards.
                // Todo: maybe use a "if (serex::poly_non_owning_cast<EncryptedRequest>(req) != nullptr)" instead
                if (req->secure) {
                    m_logger->info("Received tunneled request from" + FORMAT_PEER_INFO());
                    tunnel_response = serex::poly_owning_cast<EncryptedRequest>(std::move(req));
                    e2e_key = m_l2->get_participating_route_keys()[tunnel_response->conn_tok];
                    auto [ct2, iv2, tag2] = serex::load<crypt::symmetric::CipherText>(
                        utils::decode_bytes(tunnel_response->ciphertext));
                    raw_data = crypt::symmetric::decrypt(e2e_key, ct2, iv2, tag2);
                    req = serex::load<RawRequest*>(utils::decode_bytes(raw_data));
                }
            }

            // If the token is unknown, log a warning and continue.
            else {
                m_logger->warn("Received secure request with unknown token" + FORMAT_PEER_INFO());
                continue;
            }
        }

        while (not all_layers_ready()) {
            m_logger->info("Waiting for all layers to be ready...");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        MASTER_HANDLER(Layer4_ConnectionRequest, m_l4);
        MASTER_HANDLER(Layer4_ConnectionAccept, m_l4);
        MASTER_HANDLER(Layer4_ConnectionAck, m_l4);
        MASTER_HANDLER(Layer4_ConnectionClose, m_l4);

        MASTER_HANDLER(Layer2_RouteExtensionRequest, m_l2, tunnel_response);
        MASTER_HANDLER(Layer2_TunnelJoinRequest, m_l2);
        MASTER_HANDLER(Layer2_TunnelJoinReject, m_l2);
        MASTER_HANDLER(Layer2_TunnelJoinAccept, m_l2);
        MASTER_HANDLER(Layer2_TunnelDataForward, m_l2, tunnel_response);
        MASTER_HANDLER(Layer2_TunnelDataBackward, m_l2);

        MASTER_HANDLER(LayerD_BootstrapRequest, m_ld);
        MASTER_HANDLER(LayerD_BootstrapResponse, m_ld);
    }
}
