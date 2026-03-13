export module snet.comm_stack.dht.services;
import serex.serialize;

import snet.crypt.bytes;


export namespace snet::comm_stack::dht::services {
    struct ServiceDescriptor final {
        crypt::bytes::RawBytes service_id = {};
        crypt::bytes::RawBytes service_cert = {};

        ServiceDescriptor() = default;

        auto serialize(serex::Archive &ar) -> void {
            serex::push_into_archive(ar, service_id, service_cert);
        }
    };
}
