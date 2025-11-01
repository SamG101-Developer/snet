export module snet.nodes.node;
import std;
import snet.comm_stack.comm_stack;
import snet.comm_stack.layers.layer_d;
import snet.crypt.bytes;
import snet.manager.key_manager;
import snet.nodes.abstract_node;


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
    AbstractNode(*managers::keys::get_info(hashed_username, hashed_password), comm_stack::CommStack(port)) {
    // Create the communication stack, and the bootstrapper layer.
    m_comm_stack.start(&m_node_info);
    m_comm_stack.setup_boostrap(std::make_unique<comm_stack::layers::LayerD>(
        &m_node_info, m_comm_stack.get_socket(), false, nullptr, m_comm_stack.get_layer_4()));
    m_comm_stack.get_layer_d()->request_bootstrap();

    // Todo: request a tunnel for a testing node, enable http proxying etc.
}
