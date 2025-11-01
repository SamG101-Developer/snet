module;

export module snet.comm_stack.layers.layer_3;
import spdlog;
import std;

import snet.comm_stack.layers.layer_n;
import snet.credentials.key_store_data;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.hash;
import snet.crypt.random;
import snet.crypt.timestamp;
import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.layers.layer_4;
import snet.net.socket;


export namespace snet::comm_stack::layers {
    class Layer3 final : LayerN {
        Layer4 m_l4;

    public:
        Layer3(
            credentials::KeyStoreData *self_node_info,
            net::Socket *sock,
            Layer4 *l4);
    };
}


snet::comm_stack::layers::Layer3::Layer3(
    credentials::KeyStoreData *self_node_info,
    net::Socket *sock,
    Layer4 *l4) :
    LayerN(self_node_info, sock),
    m_l4(*l4) {
    m_logger = spdlog::logger("Layer3");
    m_logger.info("Layer3 initialized");
}
