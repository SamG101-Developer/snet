export module snet.boot;
import std;
import serex.serialize;
import snet.comm_stack.request;

import snet.utils.encoding;
import snet.crypt.random;


export namespace snet::boot {
    auto boot_serex() -> void;
}


auto snet::boot::boot_serex() -> void {
    // Register serialization polymorphic types.
    serex::register_polymorphic_type<snet::comm_stack::RawRequest>("snet.comm_stack.RawRequest");
    serex::register_polymorphic_type<snet::comm_stack::EncryptedRequest>("snet.comm_stack.EncryptedRequest");
    serex::register_polymorphic_type<snet::comm_stack::LayerD_BootstrapRequest>("snet.comm_stack.layers.LayerD_BootstrapRequest");
    serex::register_polymorphic_type<snet::comm_stack::LayerD_BootstrapResponse>("snet.comm_stack.layers.LayerD_BootstrapResponse");
    serex::register_polymorphic_type<snet::comm_stack::Layer4_ConnectionRequest>("snet.comm_stack.layers.Layer4_ConnectionRequest");
    serex::register_polymorphic_type<snet::comm_stack::Layer4_ConnectionAccept>("snet.comm_stack.layers.Layer4_ConnectionAccept");
    serex::register_polymorphic_type<snet::comm_stack::Layer4_ConnectionAck>("snet.comm_stack.layers.Layer4_ConnectionAck");
    serex::register_polymorphic_type<snet::comm_stack::Layer4_ConnectionClose>("snet.comm_stack.layers.Layer4_ConnectionClose");
    serex::register_polymorphic_type<snet::comm_stack::Layer2_RouteExtensionRequest>("snet.comm_stack.layers.Layer2_RouteExtensionRequest");
    serex::register_polymorphic_type<snet::comm_stack::Layer2_TunnelJoinRequest>("snet.comm_stack.layers.Layer2_TunnelJoinRequest");
    serex::register_polymorphic_type<snet::comm_stack::Layer2_TunnelJoinAccept>("snet.comm_stack.layers.Layer2_TunnelJoinAccept");
    serex::register_polymorphic_type<snet::comm_stack::Layer2_TunnelJoinReject>("snet.comm_stack.layers.Layer2_TunnelJoinReject");
    serex::register_polymorphic_type<snet::comm_stack::Layer2_TunnelDataForward>("snet.comm_stack.layers.Layer2_TunnelDataForward");
    serex::register_polymorphic_type<snet::comm_stack::Layer2_TunnelDataBackward>("snet.comm_stack.layers.Layer2_TunnelDataBackward");
}
