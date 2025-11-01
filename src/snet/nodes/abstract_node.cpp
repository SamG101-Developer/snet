export module snet.nodes.abstract_node;
import std;
import snet.credentials.key_store_data;
import snet.comm_stack.comm_stack;


export namespace snet::nodes {
    class AbstractNode {
    protected:
        credentials::KeyStoreData m_node_info;
        comm_stack::CommStack m_comm_stack;

    public:
        AbstractNode(credentials::KeyStoreData node_info, comm_stack::CommStack comm_stack);
        virtual ~AbstractNode() = default;
    };
}


snet::nodes::AbstractNode::AbstractNode(
    credentials::KeyStoreData node_info,
    comm_stack::CommStack comm_stack) :
    m_node_info(std::move(node_info)),
    m_comm_stack(std::move(comm_stack)) {
}
