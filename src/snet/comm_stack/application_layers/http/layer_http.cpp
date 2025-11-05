module;
#include <snet/macros.hpp>
#include <spdlog/logger.h>

export module snet.comm_stack.application_layers.http.layer_http;
import serex.serialize;
import std;
import sys;

import snet.comm_stack.application_layers.application_layer_base;
import snet.comm_stack.application_layers.http.request;
import snet.comm_stack.application_layers.http.utils;
import snet.comm_stack.connection;
import snet.comm_stack.request;
import snet.comm_stack.system_layers.layer_1;
import snet.crypt.bytes;
import snet.net.socket;
import snet.utils.encoding;


export namespace snet::comm_stack::layers::http {
    const auto HTTP_OK = std::string("HTTP/1.1 200 Connection Established\r\n\r\n");
    constexpr auto HTTPS_PORT = 443;

    class LayerHttp final : public ApplicationLayerBase {
        net::TCPSocket m_proxy_socket;
        std::mutex m_mutex;
        std::map<std::size_t, SelectableBytesIO> m_received_data_at_client;
        std::map<std::size_t, SelectableBytesIO> m_received_data_at_server;

    public:
        explicit LayerHttp(
            bool enable_socket = false);

        auto layer_proto_name()
            -> std::string override;

        auto handle_command(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<RawRequest> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req = nullptr)
            -> void override;

    private:
        [[noreturn]]
        auto start() -> void;

        auto handle_proxy_request(
            net::TCPSocket &&client_socket)
            -> void;

        auto handle_http_connect_to_server(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer1_HttpConnectToServer> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;

        auto handle_http_data_to_server(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer1_HttpDataToServer> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;

        auto handle_http_data_to_client(
            std::string const &peer_ip,
            std::uint16_t peer_port,
            std::unique_ptr<Layer1_HttpDataToClient> &&req,
            std::unique_ptr<EncryptedRequest> &&tun_req)
            -> void;

        auto handle_data_exchange_as_client(
            net::TCPSocket &client_socket,
            SelectableBytesIO &routing_entry_point)
            -> void;

        auto handle_data_exchange_as_server(
            net::TCPSocket &server_socket,
            SelectableBytesIO &routing_exit_point,
            sys::socket_t client_socket_fd,
            crypt::bytes::RawBytes prev_conn_tok)
            -> void;
    };
}


snet::comm_stack::layers::http::LayerHttp::LayerHttp(
    const bool enable_socket) {

    if (enable_socket) {
        m_proxy_socket = net::TCPSocket();
        m_proxy_socket.bind(9090);
        m_proxy_socket.listen();
        std::jthread([this] { start(); }).detach();
    }
}


auto snet::comm_stack::layers::http::LayerHttp::layer_proto_name()
    -> std::string {
    return "HTTP";
}


auto snet::comm_stack::layers::http::LayerHttp::handle_command(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<RawRequest> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {
    // Map the request type and connection state to the appropriate handler.
    MAP_TO_HANDLER(Http, Layer1_HttpConnectToServer, true, handle_http_connect_to_server, std::move(tun_req));
    MAP_TO_HANDLER(Http, Layer1_HttpDataToServer, true, handle_http_data_to_server, std::move(tun_req));
    MAP_TO_HANDLER(Http, Layer1_HttpDataToClient, true, handle_http_data_to_client, std::move(tun_req));
}


auto snet::comm_stack::layers::http::LayerHttp::start()
    -> void {
    while (true) {
        auto client_socket = m_proxy_socket.accept();
        std::jthread([this, client_socket = std::move(client_socket)] mutable {
            handle_proxy_request(std::move(client_socket));
        }).detach();
    }
}


auto snet::comm_stack::layers::http::LayerHttp::handle_proxy_request(
    net::TCPSocket &&client_socket)
    -> void {
    // Get the CONNECT request from the client using the proxy.
    using namespace std::string_literals;
    const auto request_data = client_socket.recv();

    // Determine the host from the HTTP headers (example: "google.com").
    auto host = HttpParser(request_data).headers()["Host"];
    if (host.empty()) {
        client_socket.close();
        return;
    }

    // Create the CONNECT request object and send it through the route.
    const auto client_socket_fd = client_socket.fileno();
    auto http_conn_req = std::make_unique<Layer1_HttpConnectToServer>(client_socket_fd, std::move(host));
    m_l1->tunnel_application_data_forwards(layer_proto_name(), std::move(http_conn_req));

    // Create the response selectable-object that is interacted with from Layer1.
    m_received_data_at_client[client_socket_fd] = SelectableBytesIO();
    auto &routing_entry_point = m_received_data_at_client[client_socket_fd];
    auto http_ok = utils::encode_string(HTTP_OK);
    client_socket.send(http_ok);

    // Start data exchange between the client and routing entry point.
    handle_data_exchange_as_client(client_socket, routing_entry_point);
}


auto snet::comm_stack::layers::http::LayerHttp::handle_http_connect_to_server(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer1_HttpConnectToServer> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {

    m_logger->info(std::format("Handling HTTP CONNECT to server {}", req->server_host));

    // Create a connection to the web server over secure HTTP port 443.
    auto internet_sock = net::TCPSocket();
    internet_sock.connect(req->server_host, HTTPS_PORT);

    // Save the connection against the client socket identifier.
    m_received_data_at_server[req->client_socket_fd] = SelectableBytesIO();
    auto &routing_exit_point = m_received_data_at_server[req->client_socket_fd];
    handle_data_exchange_as_server(internet_sock, routing_exit_point, req->client_socket_fd, tun_req->conn_tok);
}


auto snet::comm_stack::layers::http::LayerHttp::handle_http_data_to_server(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer1_HttpDataToServer> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {

    // Wait for the routing exit point to be ready.
    m_logger->info(std::format("Handling HTTP data to server"));
    while (not m_received_data_at_server.contains(req->client_socket_fd)) {}

    // Write the data to the correct buffer, that will be sent to the web server.
    m_logger->info(std::format("Client ID exists => writing {} bytes to route exit buffer", req->data.size()));
    m_received_data_at_server[req->client_socket_fd].write(req->data);
}


auto snet::comm_stack::layers::http::LayerHttp::handle_http_data_to_client(
    std::string const &peer_ip,
    std::uint16_t peer_port,
    std::unique_ptr<Layer1_HttpDataToClient> &&req,
    std::unique_ptr<EncryptedRequest> &&tun_req)
    -> void {

    // Wait for the routing entry point to be ready.
    m_logger->info(std::format("Handling HTTP data to client"));
    while (not m_received_data_at_client.contains(req->client_socket_fd)) {}

    // Write the data to the correct buffer, that will be sent to the web client.
    m_logger->info(std::format("Client ID exists => writing {} bytes to route entry buffer", req->data.size()));
    m_received_data_at_client[req->client_socket_fd].write(req->data);
}


auto snet::comm_stack::layers::http::LayerHttp::handle_data_exchange_as_client(
    net::TCPSocket &client_socket,
    SelectableBytesIO &routing_entry_point)
    -> void {
    // Create a socket pair to communicate with the routing entry point.
    const auto sockets = std::vector{client_socket.fileno(), routing_entry_point.fileno()};

    while (true) {
        // Get the readable and errored sockets.
        auto [readable, _, errored] = net::select(sockets, {}, sockets, std::chrono::seconds(1));
        if (not errored.empty()) { break; }

        // Forward data from readable sockets into the opposite socket.
        for (auto sock : readable) {
            // Receive the data from either of the sockets.
            auto data = std::vector<std::uint8_t>(65535);
            if (const auto n = sys::recvfrom(sock, data.data(), data.size(), 0, nullptr, nullptr); n <= 0) {
                errored.emplace_back(sock);
                break;
            }
            else {
                data.resize(static_cast<std::size_t>(n));
            }

            // Determine the opposite socket to send the data to.
            if (sock == client_socket.fileno()) {
                // Send the data to the communication stack.
                auto request = std::make_unique<Layer1_HttpDataToServer>(client_socket.fileno(), data);
                m_l1->tunnel_application_data_forwards(layer_proto_name(), std::move(request));
                m_logger->info(std::format("Sent {} HTTP bytes from client to routing entry point", data.size()));
            }
            else {
                // Write the raw HTTP response back to the client socket.
                client_socket.send(data);
                m_logger->info(std::format("Sent {} HTTP bytes from routing entry point to client", data.size()));
            }
        }
    }

    // Close the client socket and clean up.
    client_socket.close();
    routing_entry_point.close();
}


auto snet::comm_stack::layers::http::LayerHttp::handle_data_exchange_as_server(
    net::TCPSocket &server_socket,
    SelectableBytesIO &routing_exit_point,
    sys::socket_t client_socket_fd,
    crypt::bytes::RawBytes prev_conn_tok)
    -> void {
    // Create a socket pair to communicate with the routing exit point.
    const auto sockets = std::vector{server_socket.fileno(), routing_exit_point.fileno()};

    while (true) {
        // Get the readable and errored sockets.
        auto [readable, _, errored] = net::select(sockets, {}, sockets, std::chrono::seconds(1));
        if (not errored.empty()) { break; }

        // Forward data from readable sockets into the opposite socket.
        for (auto sock : readable) {
            // Receive the data from either of the sockets.
            auto data = std::vector<std::uint8_t>(65535);
            if (const auto n = sys::recvfrom(sock, data.data(), data.size(), 0, nullptr, nullptr); n <= 0) {
                errored.emplace_back(sock);
                break;
            }
            else {
                data.resize(static_cast<std::size_t>(n));
            }

            // Determine the opposite socket to send the data to.
            if (sock == server_socket.fileno()) {
                // Send the data to the communication stack.
                auto request = std::make_unique<Layer1_HttpDataToClient>(client_socket_fd, data);
                const auto prev_conn = ConnectionCache::connections[prev_conn_tok].get();
                m_l1->tunnel_application_data_backwards(layer_proto_name(), prev_conn, std::move(request));
                m_logger->info(std::format("Sent {} HTTP bytes from server to client's routing exit point", data.size()));
            }
            else {
                // Write the raw HTTP response back to the server socket.
                server_socket.send(data);
                m_logger->info(std::format("Sent {} HTTP bytes from client's routing exit point to server", data.size()));
            }
        }
    }

    // Close the server socket and clean up.
    server_socket.close();
    routing_exit_point.close();
    m_received_data_at_server.erase(m_received_data_at_server.find(client_socket_fd));
    m_received_data_at_client.erase(m_received_data_at_client.find(client_socket_fd));
    m_logger->info("Closed HTTP connection and cleaned up routing buffers");
}
