export module snet.nodes.abstract_node;
import std;
import snet.credentials.key_store_data;
import snet.comm_stack.comm_stack;


export namespace snet::nodes {
    class AbstractNode {
    protected:
        std::unique_ptr<credentials::KeyStoreData> m_node_info;
        std::unique_ptr<comm_stack::CommStack> m_comm_stack;

    public:
        AbstractNode(std::unique_ptr<credentials::KeyStoreData> &&node_info, std::unique_ptr<comm_stack::CommStack> &&comm_stack);
        virtual ~AbstractNode() = default;
    };
}


snet::nodes::AbstractNode::AbstractNode(
    std::unique_ptr<credentials::KeyStoreData> &&node_info,
    std::unique_ptr<comm_stack::CommStack> &&comm_stack) :
    m_node_info(std::move(node_info)),
    m_comm_stack(std::move(comm_stack)) {
}
