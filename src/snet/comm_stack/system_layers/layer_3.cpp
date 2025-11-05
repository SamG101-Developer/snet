module;
#include <snet/macros.hpp>

export module snet.comm_stack.system_layers.layer_3;
import spdlog;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.system_layers.layer_4;
import snet.comm_stack.system_layers.system_layer_base;
import snet.credentials.key_store_data;
import snet.crypt.bytes;
import snet.net.socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    class Layer3 final : SystemLayerBase {
        Layer4 *m_l4 = nullptr;

    public:
        Layer3(
            credentials::KeyStoreData *self_node_info,
            net::UDPSocket *sock,
            Layer4 *l4);

        auto layer_proto_name() -> std::string override {
            return "Layer3";
        }

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void override;
    };
}


snet::comm_stack::layers::Layer3::Layer3(
    credentials::KeyStoreData *self_node_info,
    net::UDPSocket *sock,
    Layer4 *l4) :
    SystemLayerBase(self_node_info, sock, utils::create_logger(layer_proto_name())),
    m_l4(l4) {
}


auto snet::comm_stack::layers::Layer3::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    m_logger->info("Layer3 received request of type " + req->serex_type() + " from" + FORMAT_PEER_INFO());
}
