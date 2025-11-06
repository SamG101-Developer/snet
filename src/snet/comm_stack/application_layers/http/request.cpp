export module snet.comm_stack.application_layers.http.request;
import serex.serialize;
import std;
import sys;

import snet.comm_stack.request;
import snet.crypt.bytes;


export namespace snet::comm_stack::layers::http {
    struct LayerHttp_HttpConnectToServer final : RawRequest {
        sys::socket_t client_socket_fd = -1;
        std::string server_host;
        std::uint16_t server_port = 0;

        LayerHttp_HttpConnectToServer() = default;

        LayerHttp_HttpConnectToServer(
            const sys::socket_t client_socket_fd,
            std::string server_host,
            const std::uint16_t server_port) :
            client_socket_fd(client_socket_fd),
            server_host(std::move(server_host)),
            server_port(server_port) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.LayerHttp_HttpConnectToServer";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, client_socket_fd, server_host, server_port);
        }
    };

    struct LayerHttp_HttpDataToServer final : RawRequest {
        sys::socket_t client_socket_fd = 0;
        crypt::bytes::RawBytes data;

        LayerHttp_HttpDataToServer() = default;

        LayerHttp_HttpDataToServer(
            const sys::socket_t client_socket_fd,
            crypt::bytes::RawBytes data) :
            client_socket_fd(client_socket_fd),
            data(std::move(data)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.LayerHttp_HttpDataToServer";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, client_socket_fd, data);
        }
    };

    struct LayerHttp_HttpDataToClient final : RawRequest {
        sys::socket_t client_socket_fd = 0;
        crypt::bytes::RawBytes data;

        LayerHttp_HttpDataToClient() = default;

        LayerHttp_HttpDataToClient(
            const sys::socket_t client_socket_fd,
            crypt::bytes::RawBytes data) :
            client_socket_fd(client_socket_fd),
            data(std::move(data)) {
        }

        auto serex_type() -> std::string override {
            return "snet.comm_stack.layers.LayerHttp_HttpDataToClient";
        }

        auto serialize(serex::Archive &ar) -> void override {
            RawRequest::serialize(ar);
            serex::push_into_archive(ar, client_socket_fd, data);
        }
    };
}
