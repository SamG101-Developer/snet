module;
#include <cerrno>

export module snet.net.tcp_socket;
import std;
import sys;

import snet.net.socket;


export namespace snet::net {
    class TCPSocket : public Socket {
    public:
        explicit TCPSocket(sys::socket_t fd = -1);
        [[nodiscard]] auto connect(std::string const &ip, std::uint16_t port) const -> bool;
        auto listen(std::int32_t backlog = 5) const -> void;
        [[nodiscard]] auto accept() const -> TCPSocket;
        auto send(std::span<std::uint8_t> data) const -> void;
        [[nodiscard]] auto recv() const -> std::vector<std::uint8_t>;
    };
}


snet::net::TCPSocket::TCPSocket(
    const sys::socket_t fd) :
    Socket(sys::AF_INET, sys::SOCK_STREAM, sys::IPPROTO_TCP, fd) {
}


auto snet::net::TCPSocket::connect(
    const std::string &ip,
    const std::uint16_t port) const
    -> bool {
    // Create the address structure for IPv4 and resolve hostname.
    auto hints = sys::addrinfo{};
    auto res = static_cast<sys::addrinfo*>(nullptr);
    std::memset(&hints, 0, sizeof(hints));

    hints.ai_family = sys::AF_INET;
    hints.ai_socktype = sys::SOCK_STREAM;

    const auto port_str = std::to_string(port);
    if (sys::getaddrinfo(ip.c_str(), port_str.c_str(), &hints, &res) != 0) {
        // throw std::system_error(errno, std::system_category(), "Failed to resolve hostname: " + ip);
        return false;
    }

    // Connect to the server.
    if (sys::connect(socket_fd, res->ai_addr, res->ai_addrlen) < 0) {
        sys::freeaddrinfo(res);
        // throw std::system_error(errno, std::system_category(), "Failed to connect to " + ip + ":" + std::to_string(port));
        return false;
    }
    sys::freeaddrinfo(res);
    return true;
}


auto snet::net::TCPSocket::listen(
    const std::int32_t backlog) const
    -> void {
    if (sys::listen(socket_fd, backlog) < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to listen on socket");
    }
}


auto snet::net::TCPSocket::accept() const
    -> TCPSocket {
    // Accept a new connection.
    const auto client_fd = sys::accept(socket_fd, nullptr, nullptr);
    if (client_fd < 0) {
        throw std::system_error(errno, std::system_category(), "Failed to accept connection");
    }
    return TCPSocket(client_fd);
}


auto snet::net::TCPSocket::send(
    const std::span<std::uint8_t> data) const
    -> void {
    // Add a frame header specifying the length of the data (size_t, so 8 byte header).
    const auto data_size = data.size();
    auto buffer = std::vector<std::uint8_t>(data_size);
    std::memcpy(buffer.data(), data.data(), data_size);

    // Send all data, handling partial sends.
    auto total_sent = 0zu;
    while (total_sent < data_size) {
        const auto sent = sys::send(socket_fd, buffer.data() + total_sent, data_size - total_sent, 0);
        if (sent <= 0) {
            throw std::system_error(errno, std::system_category(), "Failed to send data");
        }
        total_sent += static_cast<std::size_t>(sent);
    }
}


auto snet::net::TCPSocket::recv() const
    -> std::vector<std::uint8_t> {
    // Keep receiving 4096 byte chunks until the end of the data is reached.
    auto buffer = std::vector<std::uint8_t>();
    auto temp_buffer = std::vector<std::uint8_t>(4096);
    while (true) {
        const auto recv_len = sys::recv(socket_fd, temp_buffer.data(), temp_buffer.size(), 0);
        if (recv_len < 0) {
            throw std::system_error(errno, std::system_category(), "Failed to receive data");
        }
        if (recv_len == 0) {
            break; // Connection closed
        }
        buffer.insert(buffer.end(), temp_buffer.begin(), temp_buffer.begin() + recv_len);
        if (static_cast<std::size_t>(recv_len) < temp_buffer.size()) {
            break; // No more data available
        }
    }
    return buffer;
}
