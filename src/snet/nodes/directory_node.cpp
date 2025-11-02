export module snet.nodes.directory_node;
import openssl;
import std;

import snet.nodes.abstract_node;
import snet.comm_stack.comm_stack;
import snet.comm_stack.layers.layer_d;
import snet.crypt.bytes;
import snet.manager.key_manager;
import snet.utils.encoding;


export namespace snet::nodes {
    class DirectoryNode final : public AbstractNode {
        crypt::bytes::RawBytes m_name;

    public:
        DirectoryNode(
            crypt::bytes::RawBytes name,
            crypt::bytes::RawBytes const &hashed_username,
            crypt::bytes::SecureBytes const &hashed_password,
            std::uint16_t port,
            openssl::EVP_PKEY *ssk);
    };
}


snet::nodes::DirectoryNode::DirectoryNode(
    crypt::bytes::RawBytes name,
    crypt::bytes::RawBytes const &hashed_username,
    crypt::bytes::SecureBytes const &hashed_password,
    const std::uint16_t port,
    openssl::EVP_PKEY *ssk) :
    AbstractNode(managers::keys::get_info(hashed_username, hashed_password), std::make_unique<comm_stack::CommStack>(port)),
    m_name(std::move(name)) {

    // Create the communication stack and bootstrapping layer.
    m_comm_stack->start(m_node_info.get());
    m_comm_stack->setup_boostrap(std::make_unique<comm_stack::layers::LayerD>(
        m_node_info.get(), m_comm_stack->get_socket(), utils::decode_bytes(m_name), ssk, m_comm_stack->get_layer_4()));
}
