export module snet.nodes.node;
import std;

import snet.comm_stack.comm_stack;
import snet.comm_stack.system_layers.layer_d;
import snet.crypt.bytes;
import snet.manager.key_manager;
import snet.nodes.abstract_node;

import snet.utils.encoding;
import snet.comm_stack.application_layers.http.layer_http;


export namespace snet::nodes {
    class Node final : public AbstractNode {
    public:
        Node(
            crypt::bytes::RawBytes const &hashed_username,
            crypt::bytes::SecureBytes const &hashed_password,
            std::uint16_t port);
    };
}


snet::nodes::Node::Node(
    crypt::bytes::RawBytes const &hashed_username,
    crypt::bytes::SecureBytes const &hashed_password,
    const std::uint16_t port) :
    AbstractNode(managers::keys::get_info(hashed_username, hashed_password), std::make_unique<comm_stack::CommStack>(port)) {
    // Create the communication stack, and the bootstrapper layer.
    m_comm_stack->start(m_node_info.get());
    m_comm_stack->setup_boostrap(std::make_unique<comm_stack::layers::LayerD>(
        m_node_info.get(), m_comm_stack->get_socket(), "", nullptr, m_comm_stack->get_layer_4()));

    // Thread a call to the bootstrapper.
    std::jthread bootstrap([this] {
        m_comm_stack->get_layer_d()->request_bootstrap();
    });

    // Default enabled protocols.
    const auto tester_node = utils::to_hex(m_node_info->hashed_username) == "cdd5a8e37ff76bd3ec78ef8238b699c31a3f22adc5f55278a07a9b7b389960dc";
    m_comm_stack->get_layer_1()->register_protocol<comm_stack::layers::http::LayerHttp>(tester_node);
    if (tester_node) {
        std::cout << "THIS NODE WILL TEST ROUTING" << std::endl;
        m_comm_stack->get_layer_2()->create_route();
    }
}
