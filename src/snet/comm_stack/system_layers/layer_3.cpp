module;
#include <snet/macros.hpp>

export module snet.comm_stack.system_layers.layer_3;
import genex;
import serex.serialize;
import spdlog;
import std;

import snet.comm_stack.connection;
import snet.comm_stack.dht.services;
import snet.comm_stack.request;
import snet.comm_stack.system_layers.layer_4;
import snet.comm_stack.system_layers.system_layer_base;
import snet.constants;
import snet.credentials.key_store_data;
import snet.crypt.asymmetric;
import snet.crypt.bytes;
import snet.crypt.certificate;
import snet.crypt.hash;
import snet.crypt.kdf;
import snet.crypt.symmetric;
import snet.net.udp_socket;
import snet.utils.encoding;
import snet.utils.files;
import snet.utils.logging;


export namespace snet::comm_stack::layers {
    using KBucket = std::vector<Connection*>;
    using KBuckets = std::vector<KBucket>;

    constexpr auto GET_RESOURCE_TIMEOUT_MS = std::chrono::milliseconds(5000);
    constexpr auto PING_TIMEOUT_MS = std::chrono::milliseconds(2000);
    constexpr auto PING_PONG_TOLERANCE_MS = std::chrono::milliseconds(500);

    auto node_distance(crypt::bytes::RawBytes const &a, crypt::bytes::RawBytes const &b) -> std::uint64_t;

    struct NodeLookup {
        crypt::bytes::RawBytes target_id;
        Connection *closest_node = nullptr;
        std::mutex lock;
        std::vector<Connection*> queried_nodes;

        auto closest_distance() const -> std::uint64_t {
            return closest_node ?
                       node_distance(target_id, closest_node->peer_id) :
                       std::numeric_limits<std::uint64_t>::max();
        }

        explicit NodeLookup(crypt::bytes::RawBytes id) :
            target_id(std::move(id)) {}

        NodeLookup(NodeLookup &&other) noexcept :
            target_id(std::move(other.target_id)),
            closest_node(other.closest_node),
            queried_nodes(std::move(other.queried_nodes)) {}

        auto operator=(NodeLookup &&other) noexcept -> NodeLookup& {
            target_id = std::move(other.target_id);
            closest_node = other.closest_node;
            queried_nodes = std::move(other.queried_nodes);
            return *this;
        }
    };

    class Layer3 final : SystemLayerBase {
        Layer4 *m_l4 = nullptr;
        KBuckets m_k_buckets;
        std::vector<std::tuple<std::double_t, Connection*>> m_ping_queue;
        std::vector<crypt::bytes::RawBytes> m_stored_keys;
        std::map<crypt::bytes::RawBytes, NodeLookup> m_active_lookups;

    public:
        Layer3(
            credentials::KeyStoreData *self_node_info,
            net::UDPSocket *sock,
            Layer4 *l4);

        auto layer_proto_name() -> std::string override {
            return "Layer3";
        }

        auto join_dht(
            Connection *known_node)
            -> void;

        auto closest_k_nodes_to(
            crypt::bytes::RawBytes const &target_id)
            -> KBucket;

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void override;

    private:
        auto all_known_nodes()
            -> std::vector<Connection*>;

        auto node_lookup(
            crypt::bytes::RawBytes const &target_id)
            -> void;

        auto recursive_search(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            crypt::bytes::RawBytes const &peer_id,
            crypt::bytes::RawBytes const &target_id) const
            -> void;

        auto update_k_buckets(
            Connection *connection)
            -> void;

        auto handle_ping_request(
            std::unique_ptr<Layer3_PingRequest> &&req) const
            -> void;

        auto handle_pong_request(
            std::unique_ptr<Layer3_PongRequest> &&req)
            -> void;

        auto handle_find_node_request(
            std::unique_ptr<Layer3_FindNodeRequest> &&req)
            -> void;

        auto handle_find_node_response(
            std::unique_ptr<Layer3_FindNodeResponse> &&req)
            -> void;
    };
}


auto snet::comm_stack::layers::node_distance(
    crypt::bytes::RawBytes const &a,
    crypt::bytes::RawBytes const &b)
    -> std::uint64_t {
    // Convert the byte arrays to integers and compute the XOR distance.
    auto distance = static_cast<std::uint64_t>(0);
    for (std::size_t i = 0; i < constants::DHT_KEY_LEN; ++i) {
        distance <<= 8;
        distance |= static_cast<std::uint64_t>(a[i] ^ b[i]);
    }
    return distance;
}


snet::comm_stack::layers::Layer3::Layer3(
    credentials::KeyStoreData *self_node_info,
    net::UDPSocket *sock,
    Layer4 *l4) :
    SystemLayerBase(self_node_info, sock, utils::create_logger(layer_proto_name())),
    m_l4(l4) {
    // Initialize k-buckets.
    m_k_buckets = KBuckets(8 * constants::DHT_KEY_LEN);
}


auto snet::comm_stack::layers::Layer3::join_dht(
    Connection *known_node)
    -> void {
    m_logger->info("Joining dht");

    // Calculate the distance between this node and the known node. Store the node in the appropriate k-bucket.
    const auto distance = node_distance(m_self_node_info->identifier, known_node->peer_id);
    const auto k_bucket_idx = static_cast<std::size_t>(std::floor(std::log2(distance)));
    m_k_buckets[k_bucket_idx].push_back(known_node);

    // Lookup this node, as this contacts the known node and other nodes, joining this node to the network.
    node_lookup(m_self_node_info->identifier);

    // Load the stored keys from disk.
    std::jthread([this] {
        const auto storage_path = constants::DHT_STORAGE_DIR / utils::to_hex(m_self_node_info->hashed_username);
        for (auto const &file : std::filesystem::directory_iterator(storage_path)) {
            const auto file_name = file.path().filename().string();
            const auto res_key = utils::from_hex(file_name);
            m_stored_keys.emplace_back(res_key);
        }
    });
}


auto snet::comm_stack::layers::Layer3::closest_k_nodes_to(
    crypt::bytes::RawBytes const &target_id)
    -> KBucket {
    // Return the closest k nodes to the target id.
    auto node_distances = all_known_nodes()
        | genex::views::transform([&target_id](auto *node) { return std::make_tuple(node_distance(target_id, node->peer_id), node); })
        | genex::to<std::vector>();

    node_distances |= genex::actions::sort({}, genex::get<0>);
    const auto closest_nodes = node_distances
        | genex::views::take(constants::DHT_K_VALUE)
        | genex::views::transform(genex::get<1>)
        | genex::to<KBucket>();
    return closest_nodes;
}


auto snet::comm_stack::layers::Layer3::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    m_logger->info("Layer3 received request of type " + req->serex_type() + " from" + FORMAT_PEER_INFO());

    // Map the request type and connection state to the appropriate handler.
    MAP_TO_HANDLER(3, Layer3_PingRequest, true, handle_ping_request);
    MAP_TO_HANDLER(3, Layer3_PongRequest, true, handle_pong_request);
    MAP_TO_HANDLER(3, Layer3_FindNodeRequest, true, handle_find_node_request);
    MAP_TO_HANDLER(3, Layer3_FindNodeResponse, true, handle_find_node_response);

    // If no handler matched, log a warning.
    m_logger->warn("Layer3 received invalid request");
}


auto snet::comm_stack::layers::Layer3::all_known_nodes()
    -> std::vector<Connection*> {
    // Return all known nodes from all k-buckets.
    return m_k_buckets
        | genex::views::join
        | genex::to<std::vector>();
}


auto snet::comm_stack::layers::Layer3::node_lookup(
    crypt::bytes::RawBytes const &target_id)
    -> void {
    // Get this node's closest "alpha" nodes, and initiate a node lookup request.
    m_active_lookups.emplace(target_id, NodeLookup(target_id));
    const auto closest_a = all_known_nodes()
        | genex::views::take(constants::DHT_ALPHA_VALUE)
        | genex::to<std::vector>();

    // Send a find node request to the closest alpha nodes.
    for (const auto node : closest_a) {
        auto req = std::make_unique<Layer3_FindNodeRequest>(target_id);
        send_secure(node, std::move(req));
    }
}


auto snet::comm_stack::layers::Layer3::recursive_search(
    std::string const &peer_ip,
    const std::uint16_t peer_port,
    crypt::bytes::RawBytes const &peer_id,
    crypt::bytes::RawBytes const &target_id) const
    -> void {
    // Connect to the node and update the k-buckets.
    const auto conn = m_l4->connect(peer_ip, peer_port, peer_id);

    // Send a "find node" request to the node.
    auto req = std::make_unique<Layer3_FindNodeRequest>(target_id);
    send_secure(conn, std::move(req));
}


auto snet::comm_stack::layers::Layer3::update_k_buckets(
    Connection *connection)
    -> void {
    // Determine the distance between this node and the new node.
    const auto distance = node_distance(m_self_node_info->identifier, connection->peer_id);
    if (distance == 0) { return; }
    const auto k_bucket_idx = static_cast<std::size_t>(std::floor(std::log2(distance)));
    auto &k_bucket = m_k_buckets[k_bucket_idx];

    // If the node is already in the k-bucket, move it to the tail.
    const auto k_bucket_ids = k_bucket | genex::views::transform(&Connection::peer_id) | genex::to<std::vector>();
    if (genex::contains(k_bucket_ids, connection->peer_id)) {
        const auto node_index = genex::position(k_bucket_ids, genex::operations::eq_fixed(connection->peer_id));
        k_bucket.emplace_back(k_bucket[node_index]);
        k_bucket.erase(k_bucket.begin() + node_index);
    }

    // Otherwise, if the k-bucket is not full, add the node to the tail.
    else if (k_bucket.size() < constants::DHT_K_VALUE) {
        k_bucket.emplace_back(connection);
    }

    // Otherwise, if the k-bucket is full, ping the head node.
    else {
        // Get the head node, and send a ping request.
        const auto head_node = k_bucket.front();
        const auto cur_time = std::chrono::steady_clock::now();
        const auto cur_time_dbl = std::chrono::duration<std::double_t>(cur_time.time_since_epoch()).count();
        auto req = std::make_unique<Layer3_PingRequest>(cur_time_dbl);

        // Add the ping request to the ping queue, and send the ping request.
        auto time_node_pair = std::tuple{cur_time_dbl, head_node};
        m_ping_queue.emplace_back(time_node_pair);
        send_secure(head_node, std::move(req));

        // Wait for the ping response, or until the timeout.
        while (genex::contains(m_ping_queue, time_node_pair) and std::chrono::steady_clock::now() - cur_time < PING_TIMEOUT_MS) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // If the ping response was not received, remove the head node from the k-bucket.
        if (genex::contains(m_ping_queue, time_node_pair)) {
            m_logger->info("Removing unresponsive node from k-bucket");
            k_bucket |= genex::actions::pop_front();
            m_ping_queue |= genex::actions::remove(time_node_pair);
        }

        // Otherwise, move the head node to the tail, and discard the new node.
        else {
            k_bucket.erase(k_bucket.begin());
            k_bucket.emplace_back(head_node);
        }
    }
}


auto snet::comm_stack::layers::Layer3::handle_ping_request(
    std::unique_ptr<Layer3_PingRequest> &&req) const
    -> void {
    // Get the connection object for this request.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();

    // Response with a pong request, including a timestamp.
    auto pong_ts = std::chrono::duration<std::double_t>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto pong_req = std::make_unique<Layer3_PongRequest>(pong_ts, req->ping_ts);
    send_secure(conn, std::move(pong_req));
}


auto snet::comm_stack::layers::Layer3::handle_pong_request(
    std::unique_ptr<Layer3_PongRequest> &&req)
    -> void {
    // Get the connection object for this request.
    const auto conn_ptr = ConnectionCache::connections[req->conn_tok].get();
    const auto ping_ts = req->ping_ts;

    // Remove the ping request from the ping queue.
    const auto time_node_pair = std::tuple{ping_ts, conn_ptr};
    m_ping_queue |= genex::actions::remove(time_node_pair);

    // Ensure the pong response is within tolerance.
    const auto pong_ts = req->pong_ts;
    if (pong_ts - ping_ts > PING_PONG_TOLERANCE_MS.count()) {
        const auto conn = m_l4->close_connection(conn_ptr, "Pong response outside of tolerance");
        m_logger->warn("Received pong response outside of tolerance from" + FORMAT_CONN_INFO(conn));
    }
}


// auto snet::comm_stack::layers::Layer3::handle_put_resource_request(
//     std::string const &peer_ip,
//     const std::uint16_t peer_port,
//     std::unique_ptr<Layer3_PutResourceRequest> &&req)
//     -> void {
//     // Store the key and value to disk.
//     const auto storage_path = constants::DHT_STORAGE_DIR / utils::to_hex(m_self_node_info->hashed_username);
//     const auto file_name = utils::to_hex(req->res_key);
//     const auto file_path = storage_path / file_name;
//     m_stored_keys.emplace_back(req->res_key);
//
//     // Determine the encryption key (HDFK with password & filename)
//     const auto ad = utils::encode_string(file_name);
//     const auto enc_key = crypt::kdf::derive_key(m_self_node_info->hashed_password, {}, ad);
//     auto ciphertext = crypt::symmetric::encrypt_for_disk(enc_key, req->res_val);
//     utils::write_file(file_path, serex::save(ciphertext));
// }
//
//
// auto snet::comm_stack::layers::Layer3::handle_get_resource_request(
//     std::string const &peer_ip,
//     const std::uint16_t peer_port,
//     std::unique_ptr<Layer3_GetResourceRequest> &&req)
//     -> void {
//     // Get the connection object for this request.
//     const auto conn = ConnectionCache::connections[req->conn_tok].get();
//     const auto res_key = req->res_key;
//
//     // Check if this node is hosting the requested key.
//     if (genex::algorithms::contains(m_stored_keys, res_key)) {
//
//         // Load the resource from disk.
//         const auto storage_path = constants::DHT_STORAGE_DIR / utils::to_hex(m_self_node_info->hashed_username);
//         const auto file_name = utils::to_hex(res_key);
//         const auto file_path = storage_path / file_name;
//         const auto [ct, iv, _] = serex::load<crypt::symmetric::CipherText>(utils::decode_bytes(utils::read_file(file_path)));
//
//         // Decrypt the resource.
//         const auto ad = utils::encode_string(file_name);
//         const auto enc_key = crypt::kdf::derive_key(m_self_node_info->hashed_password, {}, ad);
//         const auto res_val = crypt::symmetric::decrypt_for_disk(enc_key, ct, iv);
//
//         // Send a resource success response.
//         auto res_req = std::make_unique<Layer3_RetResourceSuccessRequest>(res_key, crypt::bytes::RawBytes(res_val.begin(), res_val.end()));
//         send_secure(conn, std::move(res_req));
//         m_logger->info("Sent resource success response to" + FORMAT_PEER_INFO());
//     }
//     else {
//         // Determine the closest k nodes to the resource key.
//         const auto closest_k = closest_k_nodes_to(res_key)
//             | genex::views::transform([](Connection *node) { return std::make_tuple(node->peer_ip, node->peer_port, node->peer_id); })
//             | genex::to<std::vector>();
//
//         // Send a resource failure response.
//         auto res_req = std::make_unique<Layer3_RetResourceFailureRequest>(res_key, closest_k);
//         send_secure(conn, std::move(res_req));
//         m_logger->info("Sent resource failure response to" + FORMAT_PEER_INFO());
//     }
// }
//
//
// auto snet::comm_stack::layers::Layer3::handle_ret_resource_success_request(
//     std::string const &peer_ip,
//     const std::uint16_t peer_port,
//     std::unique_ptr<Layer3_RetResourceSuccessRequest> &&req)
//     -> void {
//     // Map to "put resource" as the logic is the same.
//     auto mapped_req = std::make_unique<Layer3_PutResourceRequest>(req->res_key, req->res_val);
//     handle_put_resource_request(peer_ip, peer_port, std::move(mapped_req));
// }
//
//
// auto snet::comm_stack::layers::Layer3::handle_ret_resource_failure_request(
//     std::string const &peer_ip,
//     std::uint16_t peer_port,
//     std::unique_ptr<Layer3_RetResourceFailureRequest> &&req)
//     -> void {
//     // Request the resource from the closest k nodes provided in the response.
//     for (const auto &[node_ip, node_port, node_id] : req->closest_node_info) {
//         std::jthread(&Layer3::recursive_search, this, node_ip, node_port, node_id, req->res_key).detach();
//     }
// }


auto snet::comm_stack::layers::Layer3::handle_find_node_request(
    std::unique_ptr<Layer3_FindNodeRequest> &&req)
    -> void {
    // Get the connection object for this request.
    const auto conn = ConnectionCache::connections[req->conn_tok].get();

    // Get the k closest nodes to the target identifier.
    const auto closest_k = closest_k_nodes_to(req->target_id)
        | genex::views::transform([](Connection *node) { return std::make_tuple(node->peer_ip, node->peer_port, node->peer_id); })
        | genex::to<std::vector>();
    auto res_req = std::make_unique<Layer3_FindNodeResponse>(req->target_id, closest_k);
    send_secure(conn, std::move(res_req));
}


auto snet::comm_stack::layers::Layer3::handle_find_node_response(
    std::unique_ptr<Layer3_FindNodeResponse> &&req)
    -> void {
    const auto target_id = req->target_id;
    const auto active_lookup = &m_active_lookups.at(target_id);

    // Mark the node as queried.
    {
        const auto conn = ConnectionCache::connections[req->conn_tok].get();
        std::scoped_lock lock(active_lookup->lock);
        active_lookup->queried_nodes.emplace_back(conn);
    }

    // If all the closest nodes have already been queried, return.
    const auto known_nodes = all_known_nodes();
    const auto nodes = req->closest_node_info
        | genex::views::filter([&known_nodes](auto const &node_info) { return not genex::contains(known_nodes, genex::get<2>(node_info), &Connection::peer_id); })
        | genex::to<std::vector>();

    // If there are no new nodes to query, return.
    if (nodes.empty()) { return; }

    // Select a sample of the nodes to query.
    auto alpha_filtered_nodes = nodes;
    alpha_filtered_nodes |= genex::actions::shuffle();
    alpha_filtered_nodes |= genex::actions::take(constants::DHT_ALPHA_VALUE);
    for (const auto &[node_ip, node_port, node_id] : alpha_filtered_nodes) {
        std::jthread(&Layer3::recursive_search, this, node_ip, node_port, node_id, target_id).detach();
    }

    // If all the nodes are further away than the closest known node, query all other k nodes.
    const auto distances = nodes
        | genex::views::transform([&target_id](auto const &node_info) { return node_distance(target_id, genex::get<2>(node_info)); })
        | genex::to<std::vector>();

    if (genex::all_of(distances, genex::operations::gt_fixed(active_lookup->closest_distance()))) {
        for (auto const &node : nodes) {
            auto [node_ip, node_port, node_id] = node;
            std::jthread(&Layer3::recursive_search, this, node_ip, node_port, node_id, target_id).detach();
        }
    }
}
