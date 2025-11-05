export module snet.comm_stack.request;
import serex.serialize;
import std;

import snet.crypt.bytes;


export namespace snet::comm_stack {
    struct AbstractRequest : serex::SerializablePolymorphicBase {
        ~AbstractRequest() override = default;
    };

    struct RawRequest : AbstractRequest {
        crypt::bytes::RawBytes conn_tok;
        bool secure = false;

        RawRequest() = default;
        RawRequest(RawRequest const &) = default;
        RawRequest(RawRequest &&) noexcept = default;
        auto operator=(RawRequest const &) -> RawRequest& = default;
        auto operator=(RawRequest &&) noexcept -> RawRequest& = default;
        ~RawRequest() override = default;

        auto serex_type() -> std::string override {
            return "snet.comm_stack.RawRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            serex::SerializablePolymorphicBase::serialize(ar);
            serex::push_into_archive(ar, conn_tok, secure);
        }
    };

    struct EncryptedRequest final : RawRequest {
        crypt::bytes::RawBytes ciphertext;

        EncryptedRequest() = default;

        explicit EncryptedRequest(
            crypt::bytes::RawBytes &&ciphertext) :
            ciphertext(std::move(ciphertext)) {
            this->secure = true;
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.EncryptedRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, ciphertext);
        }
    };

    struct LayerD_BootstrapRequest final : RawRequest {
        crypt::bytes::RawBytes node_cert;
        crypt::bytes::RawBytes node_id;

        LayerD_BootstrapRequest() = default;

        explicit LayerD_BootstrapRequest(
            crypt::bytes::RawBytes node_cert,
            crypt::bytes::RawBytes node_id) :
            node_cert(std::move(node_cert)),
            node_id(std::move(node_id)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.LayerD_BootstrapRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, node_cert, node_id);
        }
    };

    struct LayerD_BootstrapResponse final : RawRequest {
        crypt::bytes::RawBytes node_info;
        crypt::bytes::RawBytes sig;

        LayerD_BootstrapResponse() = default;

        explicit LayerD_BootstrapResponse(
            crypt::bytes::RawBytes node_info,
            crypt::bytes::RawBytes sig) :
            node_info(std::move(node_info)),
            sig(std::move(sig)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.LayerD_BootstrapResponse";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, node_info, sig);
        }
    };

    struct Layer4_ConnectionRequest final : RawRequest {
        crypt::bytes::RawBytes req_cert;
        crypt::bytes::RawBytes req_epk;
        crypt::bytes::RawBytes sig;

        Layer4_ConnectionRequest() = default;

        explicit Layer4_ConnectionRequest(
            crypt::bytes::RawBytes req_cert,
            crypt::bytes::RawBytes req_epk,
            crypt::bytes::RawBytes sig) :
            req_cert(std::move(req_cert)),
            req_epk(std::move(req_epk)),
            sig(std::move(sig)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer4_ConnectionRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, req_cert, req_epk, sig);
        }
    };

    struct Layer4_ConnectionAccept final : RawRequest {
        crypt::bytes::RawBytes acceptor_cert;
        crypt::bytes::RawBytes kem_wrapped_p2p_primary_key;
        crypt::bytes::RawBytes sig;

        Layer4_ConnectionAccept() = default;

        explicit Layer4_ConnectionAccept(
            crypt::bytes::RawBytes acceptor_cert,
            crypt::bytes::RawBytes kem_wrapped_p2p_primary_key,
            crypt::bytes::RawBytes sig) :
            acceptor_cert(std::move(acceptor_cert)),
            kem_wrapped_p2p_primary_key(std::move(kem_wrapped_p2p_primary_key)),
            sig(std::move(sig)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer4_ConnectionAccept";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, acceptor_cert, kem_wrapped_p2p_primary_key, sig);
        }
    };

    struct Layer4_ConnectionAck final : RawRequest {
        crypt::bytes::RawBytes sig;

        Layer4_ConnectionAck() = default;

        explicit Layer4_ConnectionAck(
            crypt::bytes::RawBytes sig) :
            sig(std::move(sig)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer4_ConnectionAck";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, sig);
        }
    };

    struct Layer4_ConnectionClose final : RawRequest {
        std::string reason;

        Layer4_ConnectionClose() = default;

        explicit Layer4_ConnectionClose(
            std::string reason) :
            reason(std::move(reason)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer4_ConnectionClose";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, reason);
        }
    };

    struct Layer2_RouteExtensionRequest final : RawRequest {
        crypt::bytes::RawBytes route_tok;
        crypt::bytes::RawBytes route_owner_epk;
        std::string next_node_ip;
        std::uint16_t next_node_port = 0;
        crypt::bytes::RawBytes next_node_id;

        Layer2_RouteExtensionRequest() = default;

        explicit Layer2_RouteExtensionRequest(
            crypt::bytes::RawBytes route_tok,
            crypt::bytes::RawBytes route_owner_epk,
            std::string next_node_ip,
            const std::uint16_t next_node_port,
            crypt::bytes::RawBytes next_node_id) :
            route_tok(std::move(route_tok)),
            route_owner_epk(std::move(route_owner_epk)),
            next_node_ip(std::move(next_node_ip)),
            next_node_port(next_node_port),
            next_node_id(std::move(next_node_id)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer2_RouteExtensionRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, route_tok, route_owner_epk, next_node_ip, next_node_port, next_node_id);
        }
    };

    struct Layer2_TunnelJoinRequest final : RawRequest {
        crypt::bytes::RawBytes route_token;
        crypt::bytes::RawBytes route_owner_epk;

        Layer2_TunnelJoinRequest() = default;

        explicit Layer2_TunnelJoinRequest(
            crypt::bytes::RawBytes route_token,
            crypt::bytes::RawBytes route_owner_epk) :
            route_token(std::move(route_token)),
            route_owner_epk(std::move(route_owner_epk)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer2_TunnelJoinRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, route_token, route_owner_epk);
        }
    };

    struct Layer2_TunnelJoinAccept final : RawRequest {
        crypt::bytes::RawBytes route_token;
        crypt::bytes::RawBytes acceptor_cert;
        crypt::bytes::RawBytes kem_wrapped_p2p_primary_key;
        crypt::bytes::RawBytes sig;

        Layer2_TunnelJoinAccept() = default;

        explicit Layer2_TunnelJoinAccept(
            crypt::bytes::RawBytes route_token,
            crypt::bytes::RawBytes acceptor_cert,
            crypt::bytes::RawBytes kem_wrapped_p2p_primary_key,
            crypt::bytes::RawBytes sig) :
            route_token(std::move(route_token)),
            acceptor_cert(std::move(acceptor_cert)),
            kem_wrapped_p2p_primary_key(std::move(kem_wrapped_p2p_primary_key)),
            sig(std::move(sig)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer2_TunnelJoinAccept";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, route_token, acceptor_cert, kem_wrapped_p2p_primary_key, sig);
        }
    };

    struct Layer2_TunnelJoinReject final : RawRequest {
        crypt::bytes::RawBytes route_tok;
        std::string reason;

        Layer2_TunnelJoinReject() = default;

        explicit Layer2_TunnelJoinReject(
            crypt::bytes::RawBytes route_tok,
            std::string reason) :
            route_tok(std::move(route_tok)),
            reason(std::move(reason)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer2_TunnelJoinReject";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, route_tok, reason);
        }
    };

    struct Layer2_TunnelDataForward final : RawRequest {
        crypt::bytes::RawBytes data;

        Layer2_TunnelDataForward() = default;

        explicit Layer2_TunnelDataForward(
            crypt::bytes::RawBytes data) :
            data(std::move(data)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer2_TunnelDataForward";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, data);
        }
    };

    struct Layer2_TunnelDataBackward final : RawRequest {
        crypt::bytes::RawBytes data;

        Layer2_TunnelDataBackward() = default;

        explicit Layer2_TunnelDataBackward(
            crypt::bytes::RawBytes data) :
            data(std::move(data)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer2_TunnelDataBackward";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, data);
        }
    };

    struct Layer1_ApplicationLayerRequest final : RawRequest {
        crypt::bytes::RawBytes proto_name;
        crypt::bytes::RawBytes req_serialized;

        Layer1_ApplicationLayerRequest() = default;

        explicit Layer1_ApplicationLayerRequest(
            crypt::bytes::RawBytes proto_name,
            crypt::bytes::RawBytes req_serialized) :
            proto_name(std::move(proto_name)),
            req_serialized(std::move(req_serialized)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer1_ApplicationLayerRequest";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, proto_name, req_serialized);
        }
    };

    struct Layer1_ApplicationLayerResponse final : RawRequest {
        crypt::bytes::RawBytes proto_name;
        crypt::bytes::RawBytes resp_serialized;

        Layer1_ApplicationLayerResponse() = default;

        explicit Layer1_ApplicationLayerResponse(
            crypt::bytes::RawBytes proto_name,
            crypt::bytes::RawBytes resp_serialized) :
            proto_name(std::move(proto_name)),
            resp_serialized(std::move(resp_serialized)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.Layer1_ApplicationLayerResponse";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, proto_name, resp_serialized);
        }
    };
}
