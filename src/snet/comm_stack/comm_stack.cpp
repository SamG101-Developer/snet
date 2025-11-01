export module snet.comm_stack.comm_stack;
import spdlog;
import std;

import snet.comm_stack.layers.layer_2;
import snet.comm_stack.layers.layer_3;
import snet.comm_stack.layers.layer_4;
import snet.comm_stack.layers.layer_d;
import snet.credentials.key_store_data;
import snet.crypt.bytes;
import snet.net.socket;


export namespace snet::comm_stack {
    class CommStack {
        std::uint16_t m_port;
        spdlog::logger m_logger;
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

        auto setup_boostrap(std::unique_ptr<layers::LayerD> &&ld) -> void {
            m_ld = std::move(ld);
        }

        auto start(
            credentials::KeyStoreData *info)
            -> void;

        [[noreturn]]
        auto listen() -> void;
    };
}


snet::comm_stack::CommStack::CommStack(
    const std::uint16_t port) :
    m_port(port),
    m_logger(spdlog::logger("CommStack")),
    m_sock(std::make_unique<net::Socket>()) {
    // Setup the socket.
    m_sock->bind(m_port);
    m_logger.info(std::format("CommStack initialized on port {}", m_port));

    // Setup the listener thread for receiving incoming connections.
    m_listener_thread = std::jthread([this] { listen(); });
}


auto snet::comm_stack::CommStack::start(
    credentials::KeyStoreData *info)
    -> void {
    m_logger.info("CommStack starting...");

    // Create the layers on the stack.
    m_l4 = std::make_unique<layers::Layer4>(info, m_sock.get());
    m_l3 = std::make_unique<layers::Layer3>(info, m_sock.get(), m_l4.get());
    m_l2 = std::make_unique<layers::Layer2>(info, m_sock.get(), m_l3.get(), m_l4.get());
    m_logger.info("CommStack started");
}


auto snet::comm_stack::CommStack::listen()
    -> void {
    // Listen for incoming raw requests, and handle them in a new thread.
    while (true) {
        const auto [data, ip, port] = m_sock->recv();
    }
}
