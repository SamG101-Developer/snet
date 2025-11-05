module;

#include <snet/macros.hpp>

#include <genex/algorithms/find_if.hpp>
#include <genex/views/materialize.hpp>
#include <genex/views/ptr.hpp>

export module snet.comm_stack.system_layers.layer_1;
import serex.serialize;
import spdlog;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.system_layers.system_layer_base;
import snet.comm_stack.system_layers.layer_4;
import snet.comm_stack.system_layers.layer_3;
import snet.comm_stack.system_layers.layer_d;
import snet.comm_stack.system_layers.layer_2;
import snet.comm_stack.request;
import snet.credentials.key_store_data;
import snet.net.socket;
import snet.utils.encoding;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    class Layer1 final : SystemLayerBase {
        Layer4 *m_l4 = nullptr;
        Layer3 *m_l3 = nullptr;
        LayerD *m_ld = nullptr;
        Layer2 *m_l2 = nullptr;

        std::vector<std::unique_ptr<LayerBase>> m_application_layers;

    public:
        Layer1(
            credentials::KeyStoreData *self_node_info,
            net::UDPSocket *sock,
            Layer4 *l4,
            Layer3 *l3,
            LayerD *ld,
            Layer2 *l2);

        auto layer_proto_name() -> std::string override {
            return "Layer1";
        }

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void override;

        template <typename T, typename... Args>
        auto register_protocol(Args &&... args)
            -> void;

        auto tunnel_application_data_forwards(
            std::string const &proto_name,
            std::unique_ptr<RawRequest> &&req) const
            -> void;

        auto tunnel_application_data_backwards(
            std::string const &proto_name,
            Connection *conn,
            std::unique_ptr<RawRequest> &&req) const
            -> void;

    private:
        auto handle_application_layer_request(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer1_ApplicationLayerRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;

        auto handle_application_layer_response(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer1_ApplicationLayerResponse> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;
    };
}


snet::comm_stack::layers::Layer1::Layer1(
    credentials::KeyStoreData *self_node_info,
    net::UDPSocket *sock,
    Layer4 *l4,
    Layer3 *l3,
    LayerD *ld,
    Layer2 *l2) :
    SystemLayerBase(self_node_info, sock, utils::create_logger(layer_proto_name())),
    m_l4(l4),
    m_l3(l3),
    m_ld(ld),
    m_l2(l2) {
}


auto snet::comm_stack::layers::Layer1::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    m_logger->info("Layer2 received request of type " + req->serex_type() + " from" + FORMAT_PEER_INFO());

    // Map the request type to the appropriate handler.
    MAP_TO_HANDLER(1, Layer1_ApplicationLayerRequest, true, handle_application_layer_request, std::move(tun_req));
    MAP_TO_HANDLER(1, Layer1_ApplicationLayerResponse, true, handle_application_layer_response, std::move(tun_req));
}


template <typename T, typename... Args>
auto snet::comm_stack::layers::Layer1::register_protocol(
    Args &&... args)
    -> void {
    auto application_layer = std::make_unique<T>(std::forward<Args>(args)...);
    application_layer->initialize(m_logger, this, m_l2, m_l3, m_ld, m_l4);
    m_application_layers.emplace_back(std::move(application_layer));
}


auto snet::comm_stack::layers::Layer1::tunnel_application_data_forwards(
    std::string const &proto_name,
    std::unique_ptr<RawRequest> &&req) const
    -> void {
    m_logger->info("Tunnel application data forwards for {}" + proto_name);
    auto wrapped = std::make_unique<Layer1_ApplicationLayerRequest>(
        utils::encode_string(proto_name), utils::encode_string(serex::save(req)));
    m_l2->send_tunnel_forward(std::move(wrapped));
}


auto snet::comm_stack::layers::Layer1::tunnel_application_data_backwards(
    std::string const &proto_name,
    Connection *conn,
    std::unique_ptr<RawRequest> &&req) const -> void {
    m_logger->info("Tunnel application data backwards for {}" + proto_name);
    auto wrapped = std::make_unique<Layer1_ApplicationLayerResponse>(
        utils::encode_string(proto_name), utils::encode_string(serex::save(req)));
    m_l2->send_tunnel_backward(conn, std::move(wrapped));
}


auto snet::comm_stack::layers::Layer1::handle_application_layer_request(
    std::string const &peer_ip,
    const std::uint16_t peer_port,
    std::unique_ptr<Layer1_ApplicationLayerRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    // Find the correct application layer for the protocol.
    m_logger->info("Handling application layer request for protocol " + utils::decode_bytes(req->proto_name));
    const auto layer = *genex::algorithms::find_if(
        m_application_layers | genex::views::ptr | genex::views::materialize,
        [&req](auto const &l) { return l->layer_proto_name() == utils::decode_bytes(req->proto_name); });

    // Send the command into the application layer.
    layer->handle_command(
        peer_ip, peer_port, serex::load<RawRequest*>(utils::decode_bytes(req->req_serialized)), std::move(tun_req));
}


auto snet::comm_stack::layers::Layer1::handle_application_layer_response(
    std::string const &peer_ip,
    const std::uint16_t peer_port,
    std::unique_ptr<Layer1_ApplicationLayerResponse> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    // Find the correct application layer for the protocol.
    m_logger->info("Handling application layer response for protocol " + utils::decode_bytes(req->proto_name));
    const auto layer = *genex::algorithms::find_if(
        m_application_layers | genex::views::ptr | genex::views::materialize,
        [&req](auto const &l) { return l->layer_proto_name() == utils::decode_bytes(req->proto_name); });

    // Send the command into the application layer.
    layer->handle_command(
        peer_ip, peer_port, serex::load<RawRequest*>(utils::decode_bytes(req->resp_serialized)), std::move(tun_req));
}
