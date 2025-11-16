export module snet.comm_stack.application_layers.bfsp.request;
import serex.serialize;
import std;

import snet.comm_stack.request;
import snet.comm_stack.dht.services;
import snet.crypt.bytes;


export namespace snet::comm_stack::layers::bfsp {
    struct LayerBfsp_BrokerNodeCreationRequest final : RawRequest {
        crypt::bytes::RawBytes route_token;
        dht::services::ServiceDescriptor service_descriptor;
        crypt::bytes::RawBytes sig;

        LayerBfsp_BrokerNodeCreationRequest() = default;

        LayerBfsp_BrokerNodeCreationRequest(
            crypt::bytes::RawBytes route_token,
            dht::services::ServiceDescriptor const &service_descriptor,
            crypt::bytes::RawBytes sig) :
            route_token(std::move(route_token)),
            service_descriptor(service_descriptor),
            sig(std::move(sig)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerNodeCreationRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, route_token, service_descriptor, sig);
        }
    };


    struct LayerBfsp_BrokerNodeRevokeRequest final : RawRequest {
        crypt::bytes::RawBytes route_token;
        dht::services::ServiceDescriptor service_descriptor;
        crypt::bytes::RawBytes sig;

        LayerBfsp_BrokerNodeRevokeRequest() = default;

        LayerBfsp_BrokerNodeRevokeRequest(
            crypt::bytes::RawBytes route_token,
            dht::services::ServiceDescriptor service_descriptor,
            crypt::bytes::RawBytes sig) :
            route_token(std::move(route_token)),
            service_descriptor(std::move(service_descriptor)),
            sig(std::move(sig)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerNodeRevokeRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, route_token, service_descriptor, sig);
        }
    };


    struct LayerBfsp_BrokerNodeAcceptanceResponse final : RawRequest {
        crypt::bytes::RawBytes service_id;

        LayerBfsp_BrokerNodeAcceptanceResponse() = default;

        explicit LayerBfsp_BrokerNodeAcceptanceResponse(
            crypt::bytes::RawBytes service_id) :
            service_id(std::move(service_id)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerNodeAcceptanceResponse";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, service_id);
        }
    };


    struct LayerBfsp_BrokerNodeRejectionResponse final : RawRequest {
        crypt::bytes::RawBytes service_id;
        std::string reason;

        LayerBfsp_BrokerNodeRejectionResponse() = default;

        LayerBfsp_BrokerNodeRejectionResponse(
            crypt::bytes::RawBytes service_id,
            std::string reason) :
            service_id(std::move(service_id)),
            reason(std::move(reason)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerNodeRejectionResponse";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, service_id, reason);
        }
    };


    struct LayerBfsp_ServiceAccessRequest final : RawRequest {
        crypt::bytes::RawBytes consumer_token;
        crypt::bytes::RawBytes consumer_epk;
        crypt::bytes::RawBytes service_id;
        crypt::bytes::RawBytes provider_route_token; // Attached by broker node.

        LayerBfsp_ServiceAccessRequest() = default;

        LayerBfsp_ServiceAccessRequest(
            crypt::bytes::RawBytes consumer_tok,
            crypt::bytes::RawBytes consumer_epk,
            crypt::bytes::RawBytes service_id) :
            consumer_token(std::move(consumer_tok)),
            consumer_epk(std::move(consumer_epk)),
            service_id(std::move(service_id)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_ServiceAccessRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, consumer_token, consumer_epk, service_id, provider_route_token);
        }
    };


    struct LayerBfsp_GrantServiceAccessResponse final : RawRequest {
        crypt::bytes::RawBytes consumer_token;
        crypt::bytes::RawBytes service_cert;
        crypt::bytes::RawBytes kem_wrapped_p2p_primary_key;
        crypt::bytes::RawBytes sig;

        auto serex_type() -> std::string override {
            return "LayerBfsp_GrantServiceAccessResponse";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, consumer_token, service_cert, kem_wrapped_p2p_primary_key, sig);
        }
    };


    struct LayerBfsp_BrokerDoesNotHostServiceResponse final : RawRequest {
        crypt::bytes::RawBytes service_id;

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerDoesNotHostServiceResponse";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, service_id);
        }
    };


    struct LayerBfsp_BrokerRelayToProviderRequest final : RawRequest {
        crypt::bytes::RawBytes service_id;
        crypt::bytes::RawBytes payload;

        LayerBfsp_BrokerRelayToProviderRequest() = default;

        explicit LayerBfsp_BrokerRelayToProviderRequest(
            crypt::bytes::RawBytes service_id,
            crypt::bytes::RawBytes payload) :
            service_id(std::move(service_id)),
            payload(std::move(payload)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerRelayToProviderRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, service_id, payload);
        }
    };


    struct LayerBfsp_BrokerRelayToConsumerRequest final : RawRequest {
        crypt::bytes::RawBytes service_id;
        crypt::bytes::RawBytes payload;

        LayerBfsp_BrokerRelayToConsumerRequest() = default;

        explicit LayerBfsp_BrokerRelayToConsumerRequest(
            crypt::bytes::RawBytes service_id,
            crypt::bytes::RawBytes payload) :
            service_id(std::move(service_id)),
            payload(std::move(payload)) {}

        auto serex_type() -> std::string override {
            return "LayerBfsp_BrokerRelayToConsumerRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::push_into_archive(ar, service_id, payload);
        }
    };
}
