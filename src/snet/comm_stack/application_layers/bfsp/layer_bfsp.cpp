export module snet.comm_stack.application_layers.bfsp.layer_bfsp;
import openssl;
import genex;
import serex.serialize;
import spdlog;
import std;

import snet.comm_stack.application_layers.application_layer_base;
import snet.comm_stack.application_layers.bfsp.request;
import snet.comm_stack.connection;
import snet.comm_stack.dht.services;
import snet.comm_stack.request;
import snet.comm_stack.system_layers.layer_2;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.hash;
import snet.utils.encoding;


export namespace snet::comm_stack::layers::bfsp {
    constexpr auto MAX_SERVICES_PER_BROKER_NODE = 3uz;

    class LayerBfsp final : public ApplicationLayerBase {
        std::mutex m_brokered_services_lock;
        std::map<crypt::bytes::RawBytes, dht::services::ServiceDescriptor> m_brokered_services;
        std::map<crypt::bytes::RawBytes, std::tuple<crypt::bytes::RawBytes, crypt::bytes::RawBytes>> m_tokens_to_service_id_map;
        std::map<crypt::bytes::RawBytes, crypt::bytes::SecureBytes> m_service_tunnel_keys;

        // For consumers
        std::vector<crypt::bytes::RawBytes> m_requested_service_ids;
        std::map<crypt::bytes::RawBytes, openssl::EVP_PKEY*> m_service_provider_epk_map;

        // For providers

    public:
        LayerBfsp() = default;

        auto layer_proto_name()
            -> std::string override;

        auto start_hosting_service(
            dht::services::ServiceDescriptor const &service_descriptor)
            -> void;

        auto stop_hosting_service(
            dht::services::ServiceDescriptor const &service_descriptor)
            -> void;

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req = nullptr)
            -> void override;

    private:
        auto generate_epoch_adjusted_resource_key(
            dht::services::ServiceDescriptor const &service_descriptor)
            -> crypt::bytes::RawBytes;

        auto handle_broker_node_creation_request(
            std::unique_ptr<LayerBfsp_BrokerNodeCreationRequest> &&req)
            -> void;

        auto handle_broker_node_revoke_request(
            std::unique_ptr<LayerBfsp_BrokerNodeRevokeRequest> &&req)
            -> void;

        auto handle_broker_node_acceptance_response(
            std::unique_ptr<LayerBfsp_BrokerNodeAcceptanceResponse> &&req)
            -> void;

        auto handle_broker_node_rejection_response(
            std::unique_ptr<LayerBfsp_BrokerNodeRejectionResponse> &&req)
            -> void;

        auto handle_service_access_request(
            std::unique_ptr<LayerBfsp_ServiceAccessRequest> &&req)
            -> void;

        auto handle_grant_service_access_response(
            std::unique_ptr<LayerBfsp_GrantServiceAccessResponse> &&req)
            -> void;

        auto handle_broker_node_does_not_host_service_response(
            std::unique_ptr<LayerBfsp_BrokerDoesNotHostServiceResponse> &&req)
            -> void;

        auto handle_broker_relay_to_provider_request(
            std::unique_ptr<LayerBfsp_BrokerRelayToProviderRequest> &&req)
            -> void;

        auto handle_provider_relay_to_consumer_request(
            std::unique_ptr<LayerBfsp_BrokerRelayToConsumerRequest> &&req)
            -> void;
    };
}


// auto snet::comm_stack::layers::bfsp::LayerBfsp::start_hosting_service(
//     dht::services::ServiceDescriptor const &service_descriptor)
//     -> void {
//     // Get a list of broker nodes using the DHT (layer 3).
//     const auto res_key = generate_epoch_adjusted_resource_key(service_descriptor);
//     const auto closest_nodes = m_l3->closest_k_nodes_to(res_key);
//
//     // Start hosting the service by initiating an e2e tunnel to the broker nodes.
//     for (auto const &node : closest_nodes) {
//         std::jthread([&] {
//             const auto route = m_l2->create_route(Layer2::HOP_COUNT + 1, {node->peer_ip, node->peer_port, node->peer_id});
//             const auto aad = crypt::asymmetric::create_aad(route->route_token, node->peer_id);
//             const auto sig = crypt::asymmetric::sign(m_l4->m_self_static_skey, serex::save(service_descriptor), aad.get());
//             const auto req = std::make_unique<LayerBfsp_BrokerNodeCreationRequest>(route->route_token, service_descriptor, sig);
//
//             m_l1->tunnel_application_data_forwards(layer_proto_name(), std::move(req));
//         }).detach();
//     }
// }
//
//
// auto snet::comm_stack::layers::bfsp::LayerBfsp::handle_broker_node_creation_request(
//     std::unique_ptr<LayerBfsp_BrokerNodeCreationRequest> &&req) -> void {
//     // Verify the signature on the service descriptor.
//     const auto service_cert = crypt::certificate::load_certificate(req->service_descriptor.service_cert);
//     const auto service_spk = crypt::certificate::extract_pkey_from_cert(service_cert);
//     const auto prev_conn_ptr = ConnectionCache::connections[req->route_token].get();
//
//     // Verify the certificate of the remote node.
//     if (not crypt::certificate::verify_certificate(service_cert, service_spk)) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Certificate verification failed");
//         m_logger->warn("BFSB Broker Node Creation Request: Certificate verification failed");
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn_ptr, req->route_token, std::move(response));
//         return;
//     }
//
//     // Verify the signature on the service descriptor.
//     const auto aad = crypt::asymmetric::create_aad(req->route_token, m_l4->m_self_node_info->identifier);
//     if (not crypt::asymmetric::verify(service_spk, req->sig, utils::encode_string(serex::save(req->service_descriptor)), aad.get())) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Service descriptor signature verification failed");
//         m_logger->warn("BFSB Broker Node Creation Request: Service descriptor signature verification failed");
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn_ptr, req->route_token, std::move(response));
//         return;
//     }
//
//     // Send a broker node acceptance response if under the max services limit.
//     std::scoped_lock lock(m_brokered_services_lock);
//     if (m_brokered_services.size() < MAX_SERVICES_PER_BROKER_NODE) {
//         m_brokered_services[req->service_descriptor.service_id] = req->service_descriptor;
//         auto response = std::make_unique<LayerBfsp_BrokerNodeAcceptanceResponse>(req->service_descriptor.service_id);
//
//         m_logger->info(std::format("Accepted brokering for service {}", utils::to_hex(req->service_descriptor.service_id)));
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn_ptr, req->route_token, std::move(response));
//         m_tokens_to_service_id_map[req->service_descriptor.service_id] = {prev_conn_ptr->conn_tok, req->route_token};
//         return;
//     }
//
//     // Otherwise, send a rejection response.
//     auto response = std::make_unique<LayerBfsp_BrokerNodeRejectionResponse>(req->service_descriptor.service_id, "Broker node at capacity");
//     m_logger->info(std::format("Rejected brokering for service {}: at capacity", utils::to_hex(req->service_descriptor.service_id)));
//     m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn_ptr, req->route_token, std::move(response));
// }
//
//
// auto snet::comm_stack::layers::bfsp::LayerBfsp::handle_broker_node_revoke_request(
//     std::unique_ptr<LayerBfsp_BrokerNodeRevokeRequest> &&req)
//     -> void {
//     // Verify the signature on the service descriptor.
//     const auto service_cert = crypt::certificate::load_certificate(req->service_descriptor.service_cert);
//     const auto service_spk = crypt::certificate::extract_pkey_from_cert(service_cert);
//     const auto prev_conn_ptr = ConnectionCache::connections[req->route_token].get();
//
//     // Verify the certificate of the remote node.
//     if (not crypt::certificate::verify_certificate(service_cert, service_spk)) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Certificate verification failed");
//         m_logger->warn("BFSB Broker Node Creation Request: Certificate verification failed");
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn_ptr, req->route_token, std::move(response));
//         return;
//     }
//
//     // Verify the signature on the service descriptor.
//     const auto aad = crypt::asymmetric::create_aad(req->route_token, m_l4->m_self_node_info->identifier);
//     if (not crypt::asymmetric::verify(service_spk, req->sig, utils::encode_string(serex::save(req->service_descriptor)), aad.get())) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Service descriptor signature verification failed");
//         m_logger->warn("BFSB Broker Node Creation Request: Service descriptor signature verification failed");
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn_ptr, req->route_token, std::move(response));
//         return;
//     }
//
//     // Remove the brokered service from the map.
//     std::scoped_lock lock(m_brokered_services_lock);
//     if (m_brokered_services.contains(req->service_descriptor.service_id)) {
//         m_brokered_services.erase(req->service_descriptor.service_id);
//     }
//
//     // Log the revocation.
//     m_logger->info(std::format("Broker node revoked brokering for service {}: {}", utils::to_hex(req->service_descriptor.service_id), FORMAT_PEER_INFO()));
// }
//
//
// auto snet::comm_stack::layers::bfsp::LayerBfsp::handle_broker_node_acceptance_response(
//     std::unique_ptr<LayerBfsp_BrokerNodeAcceptanceResponse> &&req)
//     -> void {
//     // The broker node is happy to host the service. Log the acceptance.
//     m_logger->info(std::format("Broker node accepted brokering for service {}", utils::to_hex(req->service_id)));
// }
//
//
// auto snet::comm_stack::layers::bfsp::LayerBfsp::handle_broker_node_rejection_response(
//     std::unique_ptr<LayerBfsp_BrokerNodeRejectionResponse> &&req)
//     -> void {
//     // The broker node rejected hosting the service. Log the rejection.
//     m_logger->info(std::format("Broker node rejected brokering for service {}: {}", utils::to_hex(req->service_id), req->reason));
// }
//
//
// auto snet::comm_stack::layers::bfsp::LayerBfsp::handle_service_access_request(
//     std::unique_ptr<LayerBfsp_ServiceAccessRequest> &&req)
//     -> void {
//     //
//     const auto remote_session_id = crypt::asymmetric::create_aad(req->consumer_token + req->consumer_epk, req->consumer_token);
//     const auto consumer_epk = crypt::asymmetric::load_public_key_kem(req->consumer_epk);
//
//     // Create a master key and kem-wrapped master key.
//     const auto kem = crypt::asymmetric::encaps(consumer_epk);
//     const auto self_ssk = crypt::asymmetric::load_private_key_sig(m_l4->m_self_node_info->secret_key);
//     const auto kem_sig = crypt::asymmetric::sign(self_ssk, kem.ct, remote_session_id.get());
//     m_service_tunnel_keys[req->consumer_token] = kem.ss; // todo: kdf
//
//     // Craft response for service <-> consumer inner tunnel.
//     m_logger->info("BFSP providing service to anonymous consumer node");
//     auto res = std::unique_ptr<RawRequest>(nullptr);
//     res = std::make_unique<LayerBfsp_GrantServiceAccessResponse>(
//         req->consumer_token, m_l4->m_self_node_info->certificate, kem.ct, kem_sig);
//     res = std::make_unique<LayerBfsp_BrokerRelayToProviderRequest>(
//         req->service_id, utils::encode_string(serex::save(*res)));
//     m_l1->tunnel_application_data_forwards(
//         layer_proto_name(), req->provider_route_token, std::move(res));
// }
//
//
// auto snet::comm_stack::layers::bfsp::LayerBfsp::handle_grant_service_access_response(
//     std::unique_ptr<LayerBfsp_GrantServiceAccessResponse> &&req)
//     -> void {
//     // Check the node identifier on the acceptor certificate matches the candidate node.
//     const auto service_cert = crypt::certificate::load_certificate(req->service_cert);
//     const auto service_id = crypt::certificate::extract_id_from_cert(service_cert);
//     if (not genex::algorithms::contains(m_requested_service_ids, service_id)) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Service not requested by this node");
//         m_logger->warn(std::format("Layer2 Invalid node trying to join route: {}", utils::to_hex(service_id)));
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), nullptr, req->consumer_token, std::move(response));
//         return;
//     }
//
//     // Check the public key hashes to the identifier on the certificate.
//     const auto peer_spk = crypt::certificate::extract_pkey_from_cert(service_cert);
//     const auto derived_id = crypt::hash::sha3_256(crypt::asymmetric::serialize_public(peer_spk));
//     if (derived_id != service_id) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Node ID does not match public key");
//         m_logger->warn(std::format("Layer2 Node ID does not match public key for node: {}", utils::to_hex(service_id)));
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), nullptr, req->consumer_token, std::move(response));
//         return;
//     }
//
//     // Verify the certificate of the remote node.
//     if (not crypt::certificate::verify_certificate(service_cert, peer_spk)) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("Certificate verification failed");
//         m_logger->warn(std::format("Layer2 Certificate verification failed for node: {}", utils::to_hex(service_id)));
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), nullptr, req->consumer_token, std::move(response));
//         return;
//     }
//
//     // Verify the signature of the kem encapsulation.
//     const auto self_tunnel_epk = crypt::asymmetric::serialize_public(route->candidate_node->self_esk);
//     const auto local_session_id = crypt::asymmetric::create_aad(route->candidate_node->conn_tok + self_tunnel_epk, route->nodes.back()->peer_id);
//     if (not crypt::asymmetric::verify(peer_spk, req->sig, req->kem_wrapped_p2p_primary_key, local_session_id.get())) {
//         auto response = std::make_unique<Layer4_ConnectionClose>("KEM-wrapped primary key signature verification failed");
//         m_logger->warn(std::format("Layer2 KEM-wrapped primary key signature verification failed for node: {}", utils::to_hex(service_id)));
//         m_l1->tunnel_application_data_backwards(layer_proto_name(), nullptr, req->consumer_token, std::move(response));
//         return;
//     }
//
//     // Unwrap the kem encapsulation and set the e2e primary key for the tunnel.
//     auto ss = crypt::asymmetric::decaps(route->candidate_node->self_esk, req->kem_wrapped_p2p_primary_key);
//     route->candidate_node->e2e_key = std::move(ss); // todo: kdf
//     route->candidate_node->state = ConnectionState::CONNECTION_OPEN;
// }
