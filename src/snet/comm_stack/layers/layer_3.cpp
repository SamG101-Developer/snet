module;

export module snet.comm_stack.layers.layer_3;
import std;
import snet.comm_stack.layers.layer_n;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.hash;
import snet.crypt.random;
import snet.crypt.timestamp;
import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.layers.layer_4;


export namespace snet::comm_stack::layers {
    class Layer3 final : LayerN {
        Layer4 m_l4;

        using LayerN::LayerN;
    };
}