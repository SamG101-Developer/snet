module;
#include <snet/macros.hpp>

export module snet.comm_stack.comm_stack;
import serex.serialize;
import spdlog;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.layers.layer_2;
import snet.comm_stack.layers.layer_3;
import snet.comm_stack.layers.layer_4;
import snet.comm_stack.layers.layer_d;
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

        std::unique_ptr<net::Socket> m_sock;
        std::unique_ptr<layers::Layer2> m_l2 = nullptr;
        std::unique_ptr<layers::Layer3> m_l3 = nullptr;
        std::unique_ptr<layers::Layer4> m_l4 = nullptr;
        std::unique_ptr<layers::LayerD> m_ld = nullptr;

    public:
        explicit CommStack(std::uint16_t port);

        [[nodiscard]]
        auto get_socket() const -> net::Socket* {
            return m_sock.get();
        }

        [[nodiscard]]
        auto get_layer_2() const -> layers::Layer2* {
            return m_l2.get();
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
            return m_l2 != nullptr and m_l3 != nullptr and m_l4 != nullptr and m_ld != nullptr;
        }

        auto setup_boostrap(std::unique_ptr<layers::LayerD> &&ld) -> void {
            m_ld = std::move(ld);
        }

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
    m_sock(std::make_unique<net::Socket>()) {
    // Setup the socket.
    m_sock->bind(m_port);
    m_logger->info(std::format("CommStack initialized on port {}", m_port));

    // Setup the listener thread for receiving incoming connections.
    m_listener_thread = std::jthread([this] { listen(); });
}


auto snet::comm_stack::CommStack::start(
    credentials::KeyStoreData *info)
    -> void {
    m_logger->info("CommStack starting...");

    // Create the layers on the stack.
    m_l4 = std::make_unique<layers::Layer4>(info, m_sock.get());
    m_l3 = std::make_unique<layers::Layer3>(info, m_sock.get(), m_l4.get());
    m_l2 = std::make_unique<layers::Layer2>(info, m_sock.get(), m_l3.get(), m_l4.get());
    m_logger->info("CommStack started");
}


auto snet::comm_stack::CommStack::listen() const
    -> void {
    // Listen for incoming raw requests, and handle them in a new thread.
    while (true) {
        const auto [data, peer_ip, peer_port] = m_sock->recv();
        auto response = serex::load<RawRequest*>(utils::decode_bytes(data));
        auto tunnel_response = std::unique_ptr<EncryptedRequest>(nullptr);

        // Handle secure p2p requests.
        if (response->secure) {
            auto tok = response->conn_tok;
            auto ct_serialized = utils::decode_bytes(serex::poly_non_owning_cast<EncryptedRequest>(response)->ciphertext);
            auto [ct, iv, tag] = serex::load<crypt::symmetric::CipherText>(ct_serialized);

            // Ensure the token exists in the connection cache.
            if (ConnectionCache::connections.contains(tok)) {
                auto e2e_key = *ConnectionCache::connections[tok]->e2e_key;
                auto raw_data = crypt::symmetric::decrypt(e2e_key, ct, iv, tag);
                response = serex::load<RawRequest*>(utils::decode_bytes(raw_data));

                // If the response is still encrypted, it is for tunneling.
                if (response->secure) {
                    m_logger->info(std::format("Received tunneled request from {}@{}:{}", peer_ip, peer_port, utils::to_hex(tok)));
                    tunnel_response = serex::poly_owning_cast<EncryptedRequest>(std::move(response));
                    e2e_key = m_l2->get_participating_route_keys()[tunnel_response->conn_tok];
                    auto [ct2, iv2, tag2] = serex::load<crypt::symmetric::CipherText>(utils::decode_bytes(tunnel_response->ciphertext));
                    raw_data = crypt::symmetric::decrypt(e2e_key, ct2, iv2, tag2);
                    response = serex::load<RawRequest*>(utils::decode_bytes(raw_data));
                }
            }
            else {
                m_logger->warn(std::format("Received secure request with unknown token {} from {}@{}", utils::to_hex(tok), peer_ip, peer_port));
                continue;
            }
        }
        m_logger->info(std::format("<- Received response of type '{}' from {}@{}", response->serex_type(), peer_ip, peer_port));

        // Handle insecure requests
        while (not all_layers_ready()) {
            m_logger->info("Waiting for all layers to be ready...");
            std::this_thread::sleep_for(std::chrono::seconds(1));
       }

        MASTER_HANDLER(Layer4_ConnectionRequest, m_l4);
        MASTER_HANDLER(Layer4_ConnectionAccept, m_l4);
        MASTER_HANDLER(Layer4_ConnectionAck, m_l4);
        MASTER_HANDLER(Layer4_ConnectionClose, m_l4);

        MASTER_HANDLER(Layer2_RouteExtensionRequest, m_l2);
        MASTER_HANDLER(Layer2_TunnelJoinRequest, m_l2);
        MASTER_HANDLER(Layer2_TunnelJoinReject, m_l2);
        MASTER_HANDLER(Layer2_TunnelJoinAccept, m_l2);
        MASTER_HANDLER(Layer2_TunnelDataForward, m_l2);
        MASTER_HANDLER(Layer2_TunnelDataBackward, m_l2);

        MASTER_HANDLER(LayerD_BootstrapRequest, m_ld);
        MASTER_HANDLER(LayerD_BootstrapResponse, m_ld);
    }
}
