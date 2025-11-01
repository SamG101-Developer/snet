export module snet.comm_stack.comm_stack;
import std;

import snet.comm_stack.layers.layer_2;
import snet.comm_stack.layers.layer_4;
import snet.comm_stack.layers.layer_d;
import snet.crypt.bytes;
import snet.net.socket;


export namespace snet::comm_stack {
    class CommStack {
        std::unique_ptr<net::Socket> m_sock;
        std::unique_ptr<layers::Layer2> m_l2 = nullptr;
        std::unique_ptr<layers::Layer4> m_l4 = nullptr;
        std::unique_ptr<layers::LayerD> m_ld = nullptr;

    public:
        CommStack(crypt::bytes::RawBytes const &hashed_username, std::uint16_t port);

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

        auto start() -> void {}
    };
}
